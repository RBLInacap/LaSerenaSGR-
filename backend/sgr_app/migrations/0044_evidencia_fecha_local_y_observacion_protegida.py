"""Evidencia.fecha_evidencia toma la fecha local y las observaciones quedan protegidas.

- `fecha_evidencia` usaba `timezone.now` como valor por defecto: en un DateField
  eso guarda la fecha UTC, y las evidencias subidas en Chile después de las
  ~21:00 quedaban con el día siguiente (divergían de `fecha_subida`). Ahora usa
  `timezone.localdate`. Los registros anteriores se corrigen con
  `python manage.py unificar_columnas_duplicadas --aplicar`.
- `ObservacionCompromiso.compromiso` pasa de SET_NULL a PROTECT: una
  observación nunca debe quedar huérfana.

Solo cambia valores de Python: no modifica datos.
"""

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sgr_app', '0043_proteger_relaciones_sin_borrado'),
    ]

    operations = [
        migrations.AlterField(
            model_name='evidencia',
            name='fecha_evidencia',
            field=models.DateField(blank=True, default=django.utils.timezone.localdate, verbose_name='Fecha de Carga'),
        ),
        migrations.AlterField(
            model_name='observacioncompromiso',
            name='compromiso',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='historial_observaciones', to='sgr_app.compromisoagenda'),
        ),
    ]
