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
