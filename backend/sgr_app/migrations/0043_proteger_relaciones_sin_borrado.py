"""Normativa: nada se elimina. Las relaciones pasan de CASCADE a PROTECT.

Con CASCADE, borrar un funcionario, una delegación o una actividad desde el ORM
habría borrado en cadena sus actividades, evidencias y compromisos. Con PROTECT
el borrado se rechaza (ProtectedError), de modo que el propio esquema expresa la
regla de baja lógica.

No ejecuta SQL (`sqlmigrate` muestra "no-op" en cada operación): Django aplica
on_delete en Python, no en la restricción de la base de datos. No toca datos.
"""

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sgr_app', '0042_orden_compromisos_por_fecha_vigente'),
    ]

    operations = [
        migrations.AlterField(
            model_name='actividad',
            name='delegacion',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='actividades', to='sgr_app.delegacion'),
        ),
        migrations.AlterField(
            model_name='actividad',
            name='funcionario',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='actividades', to=settings.AUTH_USER_MODEL, verbose_name='Funcionario Ejecutor'),
        ),
        migrations.AlterField(
            model_name='ajusteincentivo',
            name='funcionario',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='ajustes', to=settings.AUTH_USER_MODEL, verbose_name='Funcionario Evaluado'),
        ),
        migrations.AlterField(
            model_name='ajusteincentivo',
            name='periodo',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='ajustes', to='sgr_app.periodomedicion', verbose_name='Período Evaluativo'),
        ),
        migrations.AlterField(
            model_name='atencionsocial',
            name='caso',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='atenciones', to='sgr_app.casosocial'),
        ),
        migrations.AlterField(
            model_name='atencionsocial',
            name='funcionario',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='casosocial',
            name='delegacion',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='casos_sociales', to='sgr_app.delegacion'),
        ),
        migrations.AlterField(
            model_name='comentarioactividad',
            name='actividad',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='comentarios', to='sgr_app.actividad'),
        ),
        migrations.AlterField(
            model_name='compromisoagenda',
            name='actividad',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='compromisos', to='sgr_app.actividad', verbose_name='Actividad Origen'),
        ),
        migrations.AlterField(
            model_name='compromisoagenda',
            name='delegacion',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='compromisos', to='sgr_app.delegacion'),
        ),
        migrations.AlterField(
            model_name='compromisoagenda',
            name='responsable',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='compromisos_asignados', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='evidencia',
            name='actividad',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='evidencias', to='sgr_app.actividad', verbose_name='Actividad Asociada'),
        ),
        migrations.AlterField(
            model_name='indicador',
            name='meta',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='indicadores', to='sgr_app.metamodel', verbose_name='Meta'),
        ),
        migrations.AlterField(
            model_name='indicador',
            name='periodo',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='sgr_app.periodomedicion'),
        ),
        migrations.AlterField(
            model_name='itemmedicion',
            name='cargo',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='items_medicion', to='sgr_app.cargo'),
        ),
        migrations.AlterField(
            model_name='itemmedicion',
            name='periodo',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='items_medicion', to='sgr_app.periodomedicion'),
        ),
        migrations.AlterField(
            model_name='metamodel',
            name='delegacion',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='metas', to='sgr_app.delegacion'),
        ),
        migrations.AlterField(
            model_name='metamodel',
            name='funcionario',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='metas', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='metamodel',
            name='item',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='metas_rel', to='sgr_app.itemmedicion'),
        ),
        migrations.AlterField(
            model_name='metamodel',
            name='periodo',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='metas', to='sgr_app.periodomedicion', verbose_name='Período'),
        ),
    ]
