"""Ajustes de incentivo: la observación de la decisión va en su propio campo.

Antes, al rechazar se agregaba "\\n[RECHAZADO]: <observación>" al final del
motivo, y al aprobar la observación escrita se perdía. Ahora se guarda en
`observacion_decision` y el motivo original queda intacto.

Sin pérdida de datos: los motivos que ya traían la observación pegada se
separan (motivo original + observación) y cada cambio queda en la auditoría
(`SEPARAR_OBSERVACION_AJUSTE`). Es reversible: al revertir se vuelven a unir.
"""

from django.db import migrations, models

MARCA = '\n[RECHAZADO]: '
ACCION = 'SEPARAR_OBSERVACION_AJUSTE'


def separar(apps, schema_editor):
    Ajuste = apps.get_model('sgr_app', 'AjusteIncentivo')
    Auditoria = apps.get_model('sgr_app', 'RegistroAuditoria')
    for pk, motivo in Ajuste.objects.filter(motivo__contains=MARCA).values_list('pk', 'motivo'):
        original, observacion = motivo.split(MARCA, 1)
        Ajuste.objects.filter(pk=pk).update(motivo=original, observacion_decision=observacion)
        Auditoria.objects.create(
            evento='MODIFICACION', accion=ACCION, entidad='AjusteIncentivo',
            identificador=str(pk), identificador_registro=str(pk),
            valor_anterior={'motivo': motivo},
            valor_nuevo={'motivo': original, 'observacion_decision': observacion},
        )


def unir(apps, schema_editor):
    Ajuste = apps.get_model('sgr_app', 'AjusteIncentivo')
    Auditoria = apps.get_model('sgr_app', 'RegistroAuditoria')
    for identificador, anterior in Auditoria.objects.filter(accion=ACCION).values_list(
        'identificador', 'valor_anterior',
    ):
        Ajuste.objects.filter(pk=int(identificador)).update(motivo=anterior['motivo'])


class Migration(migrations.Migration):

    dependencies = [
        ('sgr_app', '0048_codigo_recuperacion_vigente_unico_portable'),
    ]

    operations = [
        migrations.AddField(
            model_name='ajusteincentivo',
            name='observacion_decision',
            field=models.TextField(blank=True, default='', verbose_name='Observación de la decisión'),
        ),
        migrations.RunPython(separar, unir),
    ]
