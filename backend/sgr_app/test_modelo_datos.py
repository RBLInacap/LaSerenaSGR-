"""Coherencia del modelo de datos.

Cubre el cálculo de avance de `ItemMedicion`. Sus métodos estuvieron por error
dentro de `VersionConfiguracionPeriodo`, y una meta asociada a un ítem que mide
compromisos fallaba con AttributeError al aprobar una evidencia.
"""
from datetime import date, timedelta

from django.test import TestCase
from django.utils import timezone

from sgr_app.models import (
    Actividad,
    Area,
    Cargo,
    CompromisoAgenda,
    Delegacion,
    Evidencia,
    ItemMedicion,
    MetaModel,
    PeriodoMedicion,
    Usuario,
    VersionConfiguracionPeriodo,
)


class AvanceItemMedicionTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        hoy = timezone.localdate()
        cls.hoy = hoy
        cls.delegacion = Delegacion.objects.create(nombre='Delegación Modelo', codigo='DMOD')
        area = Area.objects.create(nombre='Área Modelo')
        cls.cargo = Cargo.objects.create(nombre='Cargo Modelo', area=area)
        cls.funcionario = Usuario.objects.create_user(
            username='funcionario.modelo',
            password='TestPassword123!',
            rol=Usuario.Rol.FUNCIONARIO,
            cargo=cls.cargo,
            delegacion=cls.delegacion,
        )
        cls.periodo = PeriodoMedicion.objects.create(
            nombre='Período Modelo',
            fecha_inicio=hoy - timedelta(days=10),
            fecha_termino=hoy + timedelta(days=10),
        )

    def _item(self, nombre, medir_compromisos):
        return ItemMedicion.objects.create(
            cargo=self.cargo,
            periodo=self.periodo,
            nombre_item=nombre,
            meta_cuantitativa=2,
            ponderador=50,
            medir_compromisos=medir_compromisos,
        )

    def _actividad_aprobada(self, item, fecha):
        actividad = Actividad.objects.create(
            funcionario=self.funcionario,
            delegacion=self.delegacion,
            item_medicion=item,
            fecha_actividad=fecha,
            actividad_solicitud='Solicitud de prueba',
            accion_ejecutada='Acción de prueba',
        )
        Evidencia.objects.create(actividad=actividad, estado=Evidencia.Estado.APROBADA)
        return actividad

    def test_los_metodos_de_avance_pertenecen_a_item_medicion(self):
        for metodo in ('calcular_avance', 'calcular_cumplimiento', 'calcular_ponderado',
                       'activarItem', 'desactivarItem', 'obtenerCantidadMetas'):
            with self.subTest(metodo=metodo):
                self.assertTrue(hasattr(ItemMedicion, metodo))
                self.assertFalse(hasattr(VersionConfiguracionPeriodo, metodo))

    def test_meta_de_item_que_mide_compromisos_calcula_sin_error(self):
        item = self._item('Ítem por compromisos', medir_compromisos=True)
        actividad = self._actividad_aprobada(item, self.hoy)
        CompromisoAgenda.objects.create(
            actividad=actividad,
            delegacion=self.delegacion,
            responsable=self.funcionario,
            solicitante='Vecino anonimizado',
            fecha_comprometida=self.hoy,
            estado=CompromisoAgenda.Estado.REALIZADO,
        )
        meta = MetaModel.objects.create(
            nombre='Meta por compromisos',
            valor_meta=2,
            ponderador=50,
            periodo=self.periodo,
            item=item,
            funcionario=self.funcionario,
            delegacion=self.delegacion,
        )

        self.assertEqual(item.calcular_avance(self.funcionario, self.delegacion), 1.0)
        self.assertEqual(meta.calcular_meta(), 50.0)

    def test_avance_por_actividades_solo_cuenta_las_del_periodo(self):
        item = self._item('Ítem por actividades', medir_compromisos=False)
        self._actividad_aprobada(item, self.hoy)
        self._actividad_aprobada(item, self.periodo.fecha_inicio - timedelta(days=1))

        self.assertEqual(item.calcular_avance(self.funcionario), 1.0)
        self.assertEqual(item.calcular_cumplimiento(self.funcionario), 50.0)
        self.assertEqual(item.calcular_ponderado(self.funcionario), 25.0)


class UnificarColumnasDuplicadasTests(TestCase):
    """Fase 2 de docs/COLUMNAS_DUPLICADAS.md."""

    @classmethod
    def setUpTestData(cls):
        cls.hoy = timezone.localdate()
        cls.delegacion = Delegacion.objects.create(nombre='Delegación Fase 2', codigo='DF2')
        cls.funcionario = Usuario.objects.create_user(
            username='funcionario.fase2', password='TestPassword123!', delegacion=cls.delegacion,
        )
        cls.periodo = PeriodoMedicion.objects.create(
            nombre='Período Fase 2',
            fecha_inicio=cls.hoy - timedelta(days=5),
            fecha_termino=cls.hoy + timedelta(days=5),
        )

    def setUp(self):
        # Datos anteriores a la fase 1: se fuerzan divergencias saltándose save().
        self.actividad = Actividad.objects.create(
            funcionario=self.funcionario, delegacion=self.delegacion,
            actividad_solicitud='Solicitud vigente', accion_ejecutada='',
        )
        Actividad.objects.filter(pk=self.actividad.pk).update(
            solicitud_problema='Solicitud antigua', accion='Acción solo heredada',
        )
        self.compromiso = CompromisoAgenda.objects.create(
            delegacion=self.delegacion, responsable=self.funcionario,
            solicitante='Vecino', fecha_comprometida=self.hoy,
        )
        CompromisoAgenda.todos.filter(pk=self.compromiso.pk).update(
            fecha_compromiso=self.hoy - timedelta(days=3),
        )
        PeriodoMedicion.objects.filter(pk=self.periodo.pk).update(umbral_verde=1.0)
        self.evidencia = Evidencia.objects.create(actividad=self.actividad)
        Evidencia.todas.filter(pk=self.evidencia.pk).update(
            fecha_evidencia=self.hoy + timedelta(days=1),
            archivo='evidencias/2026/01/antigua.jpg',
            archivo_foto='',
        )

    def _ejecutar(self, *args):
        from io import StringIO

        from django.core.management import call_command

        salida = StringIO()
        call_command('unificar_columnas_duplicadas', *args, stdout=salida)
        return salida.getvalue()

    def test_simulacion_no_modifica_nada(self):
        from sgr_app.models import RegistroAuditoria

        salida = self._ejecutar()

        self.assertIn('SIMULACIÓN', salida)
        self.actividad.refresh_from_db()
        self.assertEqual(self.actividad.solicitud_problema, 'Solicitud antigua')
        self.assertFalse(
            RegistroAuditoria.objects.filter(accion='UNIFICAR_COLUMNA_DUPLICADA').exists()
        )

    def test_aplicar_unifica_a_favor_de_la_vigente_y_audita(self):
        from sgr_app.models import RegistroAuditoria

        self._ejecutar('--aplicar')

        self.actividad.refresh_from_db()
        self.assertEqual(self.actividad.solicitud_problema, 'Solicitud vigente')
        self.assertEqual(self.actividad.accion_ejecutada, 'Acción solo heredada')
        self.compromiso.refresh_from_db()
        self.assertEqual(self.compromiso.fecha_compromiso, self.hoy)
        self.periodo.refresh_from_db()
        self.assertEqual(self.periodo.umbral_verde, self.periodo.umbral_semaforo_verde)
        evidencia = Evidencia.todas.get(pk=self.evidencia.pk)
        self.assertEqual(evidencia.archivo_foto.name, 'evidencias/2026/01/antigua.jpg')
        self.assertEqual(evidencia.archivo.name, 'evidencias/2026/01/antigua.jpg')
        self.assertEqual(evidencia.fecha_evidencia, timezone.localdate(evidencia.fecha_subida))

        auditoria = RegistroAuditoria.objects.get(
            accion='UNIFICAR_COLUMNA_DUPLICADA', entidad='Actividad',
            identificador=str(self.actividad.pk),
        )
        self.assertEqual(auditoria.valor_anterior['solicitud_problema'], 'Solicitud antigua')
        self.assertEqual(auditoria.valor_nuevo['accion_ejecutada'], 'Acción solo heredada')
        self.assertEqual(
            RegistroAuditoria.objects.filter(accion='UNIFICAR_COLUMNA_DUPLICADA').count(), 4,
        )

    def test_es_idempotente(self):
        from sgr_app.models import RegistroAuditoria

        self._ejecutar('--aplicar')
        salida = self._ejecutar('--aplicar')

        self.assertIn('Total: 0 registro(s)', salida)
        self.assertEqual(
            RegistroAuditoria.objects.filter(accion='UNIFICAR_COLUMNA_DUPLICADA').count(), 4,
        )


class RelacionesSinBorradoEnCascadaTests(TestCase):
    """Normativa: ninguna relación del SGR puede borrar registros en cadena."""

    def test_ninguna_clave_foranea_usa_cascade(self):
        from django.apps import apps
        from django.db import models

        en_cascada = [
            f'{modelo.__name__}.{campo.name}'
            for modelo in apps.get_app_config('sgr_app').get_models()
            for campo in modelo._meta.get_fields()
            if isinstance(campo, models.ForeignKey)
            and campo.remote_field.on_delete is models.CASCADE
        ]
        self.assertEqual(
            en_cascada, [],
            'Usa PROTECT (o SET_NULL) en vez de CASCADE: por normativa nada se elimina.',
        )

    def test_borrar_una_delegacion_con_actividades_se_rechaza(self):
        from django.db.models import ProtectedError

        delegacion = Delegacion.objects.create(nombre='Delegación Protegida', codigo='DPRO')
        funcionario = Usuario.objects.create_user(
            username='funcionario.protegido',
            password='TestPassword123!',
            delegacion=delegacion,
        )
        Actividad.objects.create(funcionario=funcionario, delegacion=delegacion)

        with self.assertRaises(ProtectedError):
            delegacion.delete()
        self.assertTrue(Actividad.objects.filter(delegacion=delegacion).exists())
