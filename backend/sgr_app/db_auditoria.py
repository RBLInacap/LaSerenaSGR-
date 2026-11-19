"""Protección de la tabla de auditoría a nivel de base de datos (RNF-008).

Los triggers impiden UPDATE y DELETE sobre la tabla de auditoría incluso fuera
de Django (phpMyAdmin, consola SQL, scripts). Solo quien tenga privilegios para
eliminar los triggers podría alterar el historial, y esa acción queda fuera del
uso normal de la aplicación.

La tabla se llamó `Auditorias` hasta la migración 0046 y desde entonces
`sgr_app_registroauditoria`. Las migraciones pasan el nombre vigente en su
momento; el resto del código usa el nombre actual del modelo.
"""

MENSAJE = 'Los registros de auditoria son inmutables'

TRIGGERS = ('auditorias_no_update', 'auditorias_no_delete')

TABLA_ACTUAL = 'sgr_app_registroauditoria'


def crear_triggers_auditoria(connection, tabla=TABLA_ACTUAL):
    vendor = connection.vendor
    tabla_sql = connection.ops.quote_name(tabla)
    with connection.cursor() as cursor:
        if vendor == 'sqlite':
            for nombre, operacion in zip(TRIGGERS, ('UPDATE', 'DELETE')):
                cursor.execute(f'DROP TRIGGER IF EXISTS {nombre}')
                cursor.execute(
                    f'CREATE TRIGGER {nombre} BEFORE {operacion} ON {tabla_sql} '
                    f"BEGIN SELECT RAISE(ABORT, '{MENSAJE}'); END"
                )
        elif vendor == 'mysql':
            for nombre, operacion in zip(TRIGGERS, ('UPDATE', 'DELETE')):
                cursor.execute(f'DROP TRIGGER IF EXISTS {nombre}')
                cursor.execute(
                    f'CREATE TRIGGER {nombre} BEFORE {operacion} ON {tabla_sql} '
                    f"FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = '{MENSAJE}'"
                )


def eliminar_triggers_auditoria(connection):
    if connection.vendor not in ('sqlite', 'mysql'):
        return
    with connection.cursor() as cursor:
        for nombre in TRIGGERS:
            cursor.execute(f'DROP TRIGGER IF EXISTS {nombre}')
