"""Nombres uniformes: todas las tablas con la convención de Django y columnas en snake_case.

Antes, 11 tablas tenían nombres propios con mayúsculas (`Actividades`,
`Auditorias`, `Roles`…) y las otras 24 usaban la convención `sgr_app_<modelo>`.
MySQL en Windows guarda los nombres en minúsculas y en Linux los distingue, lo
que rompía una exportación de WAMP importada en la EC2. Ahora todas quedan en
minúsculas con el mismo formato.

Sin pérdida de datos: solo hay renombres.
- `AlterModelTable` renombra la tabla (RENAME TABLE) con sus filas, índices y
  claves foráneas.
- `RenameField` renombra la columna (RENAME COLUMN) con sus valores.
  `aprobadoPor`/`fechaAprobacion` siguen disponibles como alias en el modelo,
  con los nombres del diagrama de clases.
- Los triggers de inmutabilidad de la auditoría se quitan antes de renombrar
  su tabla y se vuelven a crear sobre el nombre nuevo.
Es reversible.
"""

from django.conf import settings
from django.db import migrations

from sgr_app.db_auditoria import crear_triggers_auditoria, eliminar_triggers_auditoria

TABLAS = {
    # modelo: nombre anterior (el nuevo es el de Django: sgr_app_<modelo>)
    'rol': 'Roles',
    'solicitante': 'Solicitantes',
    'periodomedicion': 'Periodos',
    'itemmedicion': 'Items',
    'actividad': 'Actividades',
    'compromisoagenda': 'Compromisos',
    'evidencia': 'Evidencias',
    'metamodel': 'Metas',
    'indicador': 'Indicadores',
    'ajusteincentivo': 'AjustesIncentivo',
    'registroauditoria': 'Auditorias',
}


def _crear_si_corresponde(connection, tabla):
    # Igual que la 0031: en la base temporal de pruebas no se crean.
    if not getattr(settings, 'TESTING', False):
        crear_triggers_auditoria(connection, tabla=tabla)


def quitar_triggers(apps, schema_editor):
    eliminar_triggers_auditoria(schema_editor.connection)


def triggers_tabla_anterior(apps, schema_editor):
    _crear_si_corresponde(schema_editor.connection, 'Auditorias')


def triggers_tabla_nueva(apps, schema_editor):
    _crear_si_corresponde(schema_editor.connection, 'sgr_app_registroauditoria')


class Migration(migrations.Migration):

    dependencies = [
        ('sgr_app', '0045_unificar_estado_realizado'),
    ]

    operations = [
        migrations.RunPython(quitar_triggers, triggers_tabla_anterior),
        *[
            migrations.AlterModelTable(name=modelo, table=None)
            for modelo in TABLAS
        ],
        migrations.RenameField(
            model_name='ajusteincentivo',
            old_name='aprobadoPor',
            new_name='aprobado_por',
        ),
        migrations.RenameField(
            model_name='ajusteincentivo',
            old_name='fechaAprobacion',
            new_name='fecha_aprobacion',
        ),
        migrations.RunPython(triggers_tabla_nueva, quitar_triggers),
    ]
