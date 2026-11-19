"""Un solo código de recuperación vigente por usuario, también en MariaDB.

La regla era una UniqueConstraint condicional (WHERE invalidado_en IS NULL).
MariaDB/MySQL no admiten restricciones condicionales: Django la omitía en
silencio (advertencia models.W036) y solo la aplicación evitaba duplicados.

Ahora la garantiza la base en cualquier motor: una columna calculada
`vigente_de_usuario` (id del usuario si el código está vigente, NULL si se
invalidó) con índice único. Varios NULL no chocan, así el historial se conserva.

Sin pérdida de datos: si en MariaDB ya hubiera dos códigos vigentes para un
mismo usuario, los antiguos se invalidan (motivo DUPLICADO), no se borran.
"""

from django.db import migrations, models
from django.utils import timezone


def invalidar_duplicados(apps, schema_editor):
    Codigo = apps.get_model('sgr_app', 'PasswordResetCode')
    vistos = set()
    vigentes = Codigo.objects.filter(invalidado_en__isnull=True).order_by('user_id', '-created_at', '-pk')
    for codigo_id, user_id in vigentes.values_list('pk', 'user_id'):
        if user_id in vistos:
            Codigo.objects.filter(pk=codigo_id).update(
                invalidado_en=timezone.now(), motivo_invalidacion='DUPLICADO',
            )
        vistos.add(user_id)


class Migration(migrations.Migration):

    dependencies = [
        ('sgr_app', '0047_una_foto_por_evidencia'),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name='passwordresetcode',
            name='codigo_recuperacion_vigente_unico',
        ),
        migrations.RunPython(invalidar_duplicados, migrations.RunPython.noop),
        migrations.AddField(
            model_name='passwordresetcode',
            name='vigente_de_usuario',
            field=models.GeneratedField(db_persist=True, expression=models.Case(models.When(invalidado_en__isnull=True, then=models.F('user_id')), default=None, output_field=models.BigIntegerField()), output_field=models.BigIntegerField(null=True), unique=True),
        ),
    ]
