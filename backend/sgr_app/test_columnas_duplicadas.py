"""Columnas duplicadas heredadas: fase 1 (ver docs/COLUMNAS_DUPLICADAS.md).

El modelo mantiene la columna heredada igual a la vigente al guardar, la
lógica lee siempre la vigente y, si se sobrescribe un valor distinto, el valor
anterior queda en la auditoría (no se pierde información).
"""

import io
import tempfile
from datetime import timedelta

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.utils import timezone
from PIL import Image

from sgr_app.models import (
    Actividad, Cargo, CompromisoAgenda, Delegacion, Evidencia, ItemMedicion,
    PeriodoMedicion, RegistroAuditoria, Usuario,
)
from sgr_app.serializers import CompromisoAgendaSerializer
from sgr_app.services.coherencia import verificar_coherencia


class BaseDuplicadas(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.hoy = timezone.localdate()
        cls.delegacion = Delegacion.objects.create(nombre='Delegación Dup', codigo='DUP')
        cls.cargo = Cargo.objects.create(nombre='Gestor Dup')
        cls.funcionario = Usuario.objects.create_user(
            username='dup@laserena.cl', password='TestPassword123!', rol=Usuario.Rol.FUNCIONARIO,
            delegacion=cls.delegacion, cargo=cls.cargo,
        )
        cls.periodo = PeriodoMedicion.objects.create(
            nombre='Período Dup', fecha_inicio=cls.hoy - timedelta(days=10),
            fecha_termino=cls.hoy + timedelta(days=30),
        )
        cls.item = ItemMedicion.objects.create(
            cargo=cls.cargo, periodo=cls.periodo, nombre_item='Ítem Dup', ponderador=100,
            meta_cuantitativa=5,
        )

    def compromiso(self, **campos):
        return CompromisoAgenda.objects.create(
            solicitante='Junta Vecinal', delegacion=self.delegacion, responsable=self.funcionario,
            **campos,
        )

    def auditorias_de_sincronizacion(self, instancia):
        return RegistroAuditoria.objects.filter(
            accion='SINCRONIZAR_COLUMNA_DUPLICADA',
            entidad=type(instancia).__name__,
            identificador_registro=str(instancia.pk),
        )


class CompromisoDuplicadasTests(BaseDuplicadas):
    def test_alta_iguala_fecha_y_observaciones(self):
        fecha = self.hoy + timedelta(days=5)
        c = self.compromiso(fecha_comprometida=fecha, observacion='Primera visita')
        c.refresh_from_db()
        self.assertEqual(c.fecha_compromiso, fecha)
        self.assertEqual(c.observaciones, 'Primera visita')

    def test_alta_que_solo_usa_el_nombre_heredado_respeta_la_fecha(self):
        fecha = self.hoy + timedelta(days=7)
        c = self.compromiso(fecha_compromiso=fecha)
        c.refresh_from_db()
        self.assertEqual((c.fecha_comprometida, c.fecha_compromiso), (fecha, fecha))

    def test_guardar_con_update_fields_tambien_guarda_la_duplicada(self):
        c = self.compromiso(fecha_comprometida=self.hoy + timedelta(days=3))
        nueva = self.hoy + timedelta(days=9)
        c.fecha_comprometida = nueva
        c.save(update_fields=['fecha_comprometida'])
        c.refresh_from_db()
        self.assertEqual(c.fecha_compromiso, nueva)

    def test_duplicada_divergente_se_iguala_y_el_valor_anterior_queda_auditado(self):
        c = self.compromiso(fecha_comprometida=self.hoy + timedelta(days=3))
        antigua = self.hoy - timedelta(days=40)
        CompromisoAgenda.todos.filter(pk=c.pk).update(fecha_compromiso=antigua)  # dato heredado
        c = CompromisoAgenda.todos.get(pk=c.pk)
        c.save()
        c.refresh_from_db()
        self.assertEqual(c.fecha_compromiso, c.fecha_comprometida)
        auditoria = self.auditorias_de_sincronizacion(c).get()
        self.assertEqual(auditoria.valor_anterior, {'fecha_compromiso': str(antigua)})
        self.assertEqual(auditoria.valor_nuevo, {'fecha_compromiso': str(c.fecha_comprometida)})

    def test_sin_divergencia_no_genera_auditoria(self):
        c = self.compromiso(fecha_comprometida=self.hoy + timedelta(days=3), observacion='x')
        c.save()
        self.assertFalse(self.auditorias_de_sincronizacion(c).exists())

    def test_el_vencimiento_se_calcula_con_la_fecha_vigente(self):
        c = self.compromiso(fecha_comprometida=self.hoy + timedelta(days=4))
        CompromisoAgenda.todos.filter(pk=c.pk).update(fecha_compromiso=self.hoy - timedelta(days=20))
        c = CompromisoAgenda.todos.get(pk=c.pk)
        self.assertFalse(c.fecha_vencida())
        self.assertEqual(c.calcularDiasAtraso(), 0)
        self.assertEqual(c.fechaCompromiso, c.fecha_comprometida)

    def test_api_no_permite_escribir_la_columna_heredada(self):
        self.assertTrue(CompromisoAgendaSerializer().fields['observaciones'].read_only)


class ActividadDuplicadasTests(BaseDuplicadas):
    def actividad(self, **campos):
        return Actividad.objects.create(
            funcionario=self.funcionario, delegacion=self.delegacion, fecha_actividad=self.hoy,
            **campos,
        )

    def test_alta_por_api_completa_las_columnas_heredadas(self):
        a = self.actividad(actividad_solicitud='Luminaria', accion_ejecutada='Derivada',
                           item_medicion=self.item)
        a.refresh_from_db()
        self.assertEqual((a.solicitud_problema, a.accion, a.item_id), ('Luminaria', 'Derivada', self.item.pk))

    def test_alta_heredada_completa_la_columna_vigente(self):
        a = self.actividad(solicitud_problema='Poda', accion='Retiro de ramas')
        a.refresh_from_db()
        self.assertEqual((a.actividad_solicitud, a.accion_ejecutada), ('Poda', 'Retiro de ramas'))
        self.assertEqual(a.solicitudProblema, 'Poda')

    def test_item_heredado_no_se_copia_al_vigente(self):
        """Copiarlo cambiaría los indicadores: se deja para la fase 2."""
        a = self.actividad(actividad_solicitud='x', accion_ejecutada='y')
        Actividad.objects.filter(pk=a.pk).update(item=self.item, item_medicion=None)
        a = Actividad.objects.get(pk=a.pk)
        a.save()
        a.refresh_from_db()
        self.assertEqual((a.item_id, a.item_medicion_id), (self.item.pk, None))

    def test_texto_divergente_se_iguala_y_queda_auditado(self):
        a = self.actividad(actividad_solicitud='Texto vigente', accion_ejecutada='Acción')
        Actividad.objects.filter(pk=a.pk).update(solicitud_problema='Texto antiguo')
        a = Actividad.objects.get(pk=a.pk)
        a.direccion = 'Calle 1'
        a.save(update_fields=['direccion'])
        a.refresh_from_db()
        self.assertEqual(a.solicitud_problema, 'Texto vigente')
        self.assertEqual(
            self.auditorias_de_sincronizacion(a).get().valor_anterior,
            {'solicitud_problema': 'Texto antiguo'},
        )


class EvidenciaDuplicadasTests(BaseDuplicadas):
    def test_cargar_archivo_usa_la_columna_vigente(self):
        actividad = Actividad.objects.create(
            funcionario=self.funcionario, delegacion=self.delegacion, fecha_actividad=self.hoy,
        )
        imagen = io.BytesIO()
        Image.new('RGB', (4, 4), 'red').save(imagen, format='PNG')
        foto = SimpleUploadedFile('foto.png', imagen.getvalue(), content_type='image/png')
        with tempfile.TemporaryDirectory() as media, override_settings(MEDIA_ROOT=media):
            evidencia = Evidencia.objects.create(actividad=actividad)
            evidencia.cargar_archivo(foto)
            evidencia.refresh_from_db()
            self.assertTrue(evidencia.archivo_foto)
            self.assertFalse(evidencia.archivo)
            self.assertEqual(evidencia.get_foto_url, evidencia.archivo_foto.url)


class CoherenciaDuplicadasTests(BaseDuplicadas):
    def test_detecta_textos_divergentes_de_datos_antiguos(self):
        a = Actividad.objects.create(
            funcionario=self.funcionario, delegacion=self.delegacion, fecha_actividad=self.hoy,
            actividad_solicitud='Vigente', accion_ejecutada='Acción',
        )
        Actividad.objects.filter(pk=a.pk).update(solicitud_problema='Antiguo', accion='Otra')
        c = self.compromiso(fecha_comprometida=self.hoy + timedelta(days=2), observacion='Vigente')
        CompromisoAgenda.todos.filter(pk=c.pk).update(observaciones='Antigua')

        codigos = {h.codigo: h for h in verificar_coherencia()}
        self.assertIn(a.pk, codigos['duplicada.actividad_solicitud_divergente'].ejemplos)
        self.assertIn(a.pk, codigos['duplicada.actividad_accion_divergente'].ejemplos)
        self.assertIn(c.pk, codigos['duplicada.compromiso_observaciones_divergentes'].ejemplos)
