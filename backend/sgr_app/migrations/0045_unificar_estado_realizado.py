"""Compromisos: COMPLETADO y CUMPLIDO pasan a REALIZADO (sinónimos).

Los tres estados significaban lo mismo: todas las evidencias aprobadas y el
compromiso cerrado. Todo el sistema los contaba igual, y la especificación de
casos de uso habla solo de "realizado".

Sin pérdida de datos:
- Solo cambia el valor de `estado`. `fecha_realizacion`, las observaciones y
  todo lo demás quedan intactos.
- Cada compromiso convertido deja un evento de auditoría
  (`UNIFICAR_ESTADO_COMPROMISO`) con su estado anterior.
- La migración es reversible: al revertirla, cada compromiso recupera su estado
  original leído desde esa auditoría (que no se borra).
"""

from django.db import migrations, models

SINONIMOS = ('COMPLETADO', 'CUMPLIDO')
ACCION = 'UNIFICAR_ESTADO_COMPROMISO'


def unificar(apps, schema_editor):
    Compromiso = apps.get_model('sgr_app', 'CompromisoAgenda')
    Auditoria = apps.get_model('sgr_app', 'RegistroAuditoria')
    for compromiso_id, estado in (
        Compromiso.objects.filter(estado__in=SINONIMOS).values_list('pk', 'estado').iterator()
    ):
        Auditoria.objects.create(
            evento='MODIFICACION',
            accion=ACCION,
            entidad='CompromisoAgenda',
            identificador=str(compromiso_id),
            identificador_registro=str(compromiso_id),
            valor_anterior={'estado': estado},
            valor_nuevo={'estado': 'REALIZADO'},
        )
        Compromiso.objects.filter(pk=compromiso_id).update(estado='REALIZADO')


def restaurar(apps, schema_editor):
    Compromiso = apps.get_model('sgr_app', 'CompromisoAgenda')
    Auditoria = apps.get_model('sgr_app', 'RegistroAuditoria')
    for identificador, anterior in (
        Auditoria.objects.filter(accion=ACCION).order_by('pk').values_list('identificador', 'valor_anterior')
    ):
        Compromiso.objects.filter(pk=int(identificador), estado='REALIZADO').update(
            estado=anterior['estado'],
        )


class Migration(migrations.Migration):

    dependencies = [
        ('sgr_app', '0044_evidencia_fecha_local_y_observacion_protegida'),
    ]

    operations = [
        migrations.RunPython(unificar, restaurar),
        migrations.AlterField(
            model_name='compromisoagenda',
            name='estado',
            field=models.CharField(choices=[('INGRESADO', 'Ingresado'), ('PENDIENTE', 'Pendiente'), ('EN_PROCESO', 'En Proceso'), ('VENCIDO', 'Vencido'), ('REPROGRAMADO', 'Reprogramado'), ('REALIZADO', 'Realizado')], default='PENDIENTE', max_length=30, verbose_name='Estado'),
        ),
    ]
