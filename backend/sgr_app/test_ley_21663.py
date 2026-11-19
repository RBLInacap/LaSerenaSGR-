"""Ley 21.663 (Ley Marco de Ciberseguridad): detección, incidentes y controles.

Cubre: eventos de seguridad con alerta por correo, registro de incidentes y sus
plazos de reporte al CSIRT Nacional, permisos, bitácora sin borrado, integridad
(SRI) de los recursos de CDN y CSP aplicada.
"""
import re
from datetime import timedelta
from pathlib import Path

from django.core import mail
from django.core.exceptions import ValidationError
from django.test import Client, RequestFactory, TestCase, override_settings
from django.utils import timezone

from sgr_app.models import (
    AccionIncidente,
    EventoSeguridad,
    IncidenteSeguridad,
    RegistroAuditoria,
    Usuario,
)

CLAVE = 'Clave.Segura.2026'
ALERTAS = override_settings(ALERTAS_EMAIL=['seguridad@sim.cl'])


@ALERTAS
class EventosSeguridadTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.funcionario = Usuario.objects.create_user(
            username='victima@sim.cl', password=CLAVE, rol=Usuario.Rol.FUNCIONARIO,
        )

    def _alertas(self):
        return [m for m in mail.outbox if 'Evento de seguridad' in m.subject]

    def test_fuerza_bruta_registra_evento_y_alerta_una_sola_vez(self):
        cliente = Client()
        for _ in range(7):
            cliente.post('/login/', {'username': 'victima@sim.cl', 'password': 'incorrecta'})

        eventos = EventoSeguridad.objects.filter(tipo=EventoSeguridad.Tipo.BLOQUEO_INICIO_SESION)
        self.assertGreaterEqual(eventos.count(), 1)
        self.assertEqual(eventos.first().usuario, self.funcionario)
        self.assertEqual(len(self._alertas()), 1, 'el mismo motivo se alerta una vez cada 30 minutos')
        self.assertIn('3 horas', self._alertas()[0].body)

    def test_bloqueo_de_2fa_registra_evento(self):
        from sgr_app.services.seguridad_acceso import registrar_2fa_fallido

        peticion = RequestFactory().post('/verificar-2fa/')
        for _ in range(5):
            registrar_2fa_fallido(peticion, self.funcionario)
        self.assertTrue(EventoSeguridad.objects.filter(
            tipo=EventoSeguridad.Tipo.BLOQUEO_2FA, usuario=self.funcionario).exists())

    def test_accesos_denegados_repetidos(self):
        self.client.force_login(self.funcionario)
        for _ in range(10):
            self.client.get('/mantenedores/funcionarios/')
        self.assertEqual(EventoSeguridad.objects.filter(
            tipo=EventoSeguridad.Tipo.ACCESOS_DENEGADOS_REPETIDOS).count(), 1)

    def test_intento_de_alterar_la_auditoria_alerta(self):
        RegistroAuditoria.objects.create(accion='PRUEBA', entidad='X', identificador='1')
        with self.assertRaises(ValidationError):
            RegistroAuditoria.objects.all().delete()
        self.assertTrue(EventoSeguridad.objects.filter(
            tipo=EventoSeguridad.Tipo.INTENTO_ALTERAR_AUDITORIA).exists())
        self.assertEqual(len(self._alertas()), 1)

    def test_detecta_triggers_de_auditoria_ausentes(self):
        from django.db import connection

        from sgr_app.db_auditoria import crear_triggers_auditoria, eliminar_triggers_auditoria
        from sgr_app.services.eventos_seguridad import verificar_triggers_auditoria

        eliminar_triggers_auditoria(connection)
        self.assertFalse(verificar_triggers_auditoria(incluso_en_pruebas=True))
        self.assertTrue(EventoSeguridad.objects.filter(
            tipo=EventoSeguridad.Tipo.TRIGGERS_AUDITORIA_AUSENTES).exists())
        crear_triggers_auditoria(connection)
        try:
            self.assertTrue(verificar_triggers_auditoria(incluso_en_pruebas=True))
        finally:
            eliminar_triggers_auditoria(connection)


@ALERTAS
class IncidentesTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        crear = Usuario.objects.create_user
        cls.admin = crear(username='admin.inc@sim.cl', password=CLAVE, rol=Usuario.Rol.ADMINISTRADOR)
        cls.coordinador = crear(username='coord.inc@sim.cl', password=CLAVE, rol=Usuario.Rol.COORDINADOR)
        cls.funcionario = crear(username='func.inc@sim.cl', password=CLAVE, rol=Usuario.Rol.FUNCIONARIO)

    def _datos(self, **extra):
        datos = {
            'titulo': 'Acceso no autorizado a evidencias', 'categoria': 'ACCESO_NO_AUTORIZADO',
            'severidad': 'ALTA', 'estado': 'ABIERTO',
            'detectado_en': timezone.localtime().strftime('%Y-%m-%dT%H:%M'),
            'descripcion': 'Descarga masiva de fotos desde una cuenta comprometida.',
            'afecta_datos_personales': 'on',
        }
        datos.update(extra)
        return datos

    def _crear(self, **extra):
        self.client.force_login(self.admin)
        self.client.post('/incidentes/registrar/', self._datos(**extra))
        return IncidenteSeguridad.objects.latest('pk')

    def test_registrar_incidente_significativo_alerta_con_los_plazos(self):
        incidente = self._crear()
        self.assertRegex(incidente.codigo, r'^INC-\d{4}-0001$')
        self.assertTrue(incidente.requiere_reporte)
        self.assertEqual(incidente.vence('alerta_temprana') - incidente.detectado_en, timedelta(hours=3))
        self.assertEqual(incidente.vence('actualizacion') - incidente.detectado_en, timedelta(hours=72))
        self.assertEqual(incidente.vence('informe_final') - incidente.detectado_en, timedelta(days=15))
        aviso = [m for m in mail.outbox if incidente.codigo in m.subject]
        self.assertEqual(len(aviso), 1)
        self.assertIn('portal.anci.gob.cl', aviso[0].body)
        self.assertTrue(RegistroAuditoria.objects.filter(accion='CREAR_INCIDENTE_SEGURIDAD').exists())

    def test_incidente_sin_efecto_significativo_no_requiere_reporte(self):
        incidente = self._crear(afecta_datos_personales='')
        self.assertFalse(incidente.requiere_reporte)
        self.assertEqual({h['estado'] for h in incidente.hitos()}, {'NO_APLICA'})
        self.assertFalse([m for m in mail.outbox if incidente.codigo in m.subject])

    def test_plazos_por_vencer_y_vencidos_se_alertan_una_vez(self):
        from sgr_app.services.incidentes import revisar_plazos_incidentes

        incidente = self._crear()
        mail.outbox.clear()
        base = incidente.detectado_en
        self.assertEqual(revisar_plazos_incidentes(base + timedelta(hours=1)), 0)
        self.assertEqual(revisar_plazos_incidentes(base + timedelta(hours=2, minutes=30)), 1)
        self.assertEqual(revisar_plazos_incidentes(base + timedelta(hours=2, minutes=40)), 0)
        self.assertEqual(revisar_plazos_incidentes(base + timedelta(hours=4)), 1)
        self.assertIn('VENCIDO', mail.outbox[-1].subject)

    def test_registrar_envio_de_hitos_al_csirt(self):
        incidente = self._crear()
        url = f'/incidentes/{incidente.pk}/'
        antes = (incidente.detectado_en - timedelta(hours=1)).astimezone(timezone.get_current_timezone())
        self.client.post(url, {'operacion': 'hito', 'hito': 'alerta_temprana',
                               'enviado_en': antes.strftime('%Y-%m-%dT%H:%M')})
        incidente.refresh_from_db()
        self.assertIsNone(incidente.alerta_temprana_enviada_en, 'no puede enviarse antes de detectarse')

        self.client.post(url, {'operacion': 'hito', 'hito': 'alerta_temprana', 'folio': 'ANCI-123',
                               'enviado_en': timezone.localtime().strftime('%Y-%m-%dT%H:%M')})
        incidente.refresh_from_db()
        self.assertEqual(incidente.estado_hito('alerta_temprana'), 'ENVIADO')
        self.assertEqual(incidente.folio_csirt, 'ANCI-123')
        self.assertTrue(RegistroAuditoria.objects.filter(accion='REPORTE_CSIRT_INCIDENTE').exists())

    def test_cerrar_exige_causa_raiz(self):
        incidente = self._crear()
        url = f'/incidentes/{incidente.pk}/'
        self.client.post(url, {'operacion': 'actualizar', **self._datos(estado='CERRADO')})
        incidente.refresh_from_db()
        self.assertEqual(incidente.estado, 'ABIERTO')
        self.client.post(url, {'operacion': 'actualizar',
                               **self._datos(estado='CERRADO', causa_raiz='Contraseña reutilizada')})
        incidente.refresh_from_db()
        self.assertEqual(incidente.estado, 'CERRADO')
        self.assertIsNotNone(incidente.cerrado_en)

    def test_bitacora_e_incidente_no_se_editan_ni_borran(self):
        incidente = self._crear()
        self.client.post(f'/incidentes/{incidente.pk}/', {'operacion': 'accion', 'texto': 'Se bloqueó la cuenta'})
        accion = AccionIncidente.objects.get(incidente=incidente)
        accion.texto = 'otro'
        with self.assertRaises(ValidationError):
            accion.save()
        with self.assertRaises(ValidationError):
            incidente.delete()

    def test_crear_incidente_desde_un_evento(self):
        evento = EventoSeguridad.objects.create(tipo=EventoSeguridad.Tipo.BLOQUEO_INICIO_SESION,
                                                detalle='Fuerza bruta', ip_origen='203.0.113.7')
        self.client.force_login(self.admin)
        respuesta = self.client.get(f'/incidentes/registrar/?evento={evento.pk}')
        self.assertContains(respuesta, '203.0.113.7')

    def test_reporte_exportable(self):
        incidente = self._crear()
        respuesta = self.client.get(f'/incidentes/{incidente.pk}/reporte/')
        self.assertEqual(respuesta['Content-Type'], 'text/plain; charset=utf-8')
        texto = respuesta.content.decode()
        for seccion in ('ALERTA TEMPRANA', 'ACTUALIZACIÓN', 'INFORME FINAL', incidente.codigo,
                        'Afecta sistemas informáticos con datos personales'):
            self.assertIn(seccion, texto)

    def test_permisos(self):
        incidente = self._crear()
        self.client.force_login(self.coordinador)
        self.assertEqual(self.client.get('/incidentes/').status_code, 200)
        self.assertEqual(self.client.get(f'/incidentes/{incidente.pk}/').status_code, 200)
        self.assertEqual(self.client.get(f'/incidentes/{incidente.pk}/reporte/').status_code, 200)
        self.assertEqual(self.client.get('/incidentes/registrar/').status_code, 403)
        self.assertEqual(self.client.post(f'/incidentes/{incidente.pk}/',
                                          {'operacion': 'accion', 'texto': 'x'}).status_code, 403)
        self.client.force_login(self.funcionario)
        self.assertEqual(self.client.get('/incidentes/').status_code, 403)


class ControlesNavegadorTests(TestCase):
    PLANTILLAS = Path(__file__).resolve().parent.parent / 'templates'

    def test_recursos_de_cdn_llevan_integridad(self):
        sin_sri = []
        for plantilla in self.PLANTILLAS.rglob('*.html'):
            html = plantilla.read_text(encoding='utf-8')
            for etiqueta in re.findall(r'<(?:script|link)\b[^>]*>', html):
                externo = re.search(r'(?:src|href)="https://(?!fonts\.(?:googleapis|gstatic)\.com)[^"]+"', etiqueta)
                es_recurso = etiqueta.startswith('<script') or 'stylesheet' in etiqueta
                if externo and es_recurso and 'integrity=' not in etiqueta:
                    sin_sri.append(f'{plantilla.name}: {externo.group(0)}')
        self.assertEqual(sin_sri, [], 'Todo script o estilo de CDN debe llevar integrity= (SRI).')

    @override_settings(CSP_REPORT_ONLY=False)
    def test_csp_se_aplica(self):
        respuesta = Client().get('/login/')
        self.assertIn('Content-Security-Policy', respuesta)
        self.assertNotIn('Content-Security-Policy-Report-Only', respuesta)
        self.assertIn("object-src 'none'", respuesta['Content-Security-Policy'])
