"""Fase 2 de las columnas duplicadas: alinea la heredada con la vigente.

Uso:
    python manage.py unificar_columnas_duplicadas            # simulación: solo informa
    python manage.py unificar_columnas_duplicadas --aplicar  # corrige y audita cada cambio

Haz un respaldo antes de aplicar (`python manage.py respaldar_base_datos`).
Cada registro corregido queda en la auditoría con acción UNIFICAR_COLUMNA_DUPLICADA
y sus valores anteriores. Es idempotente: una segunda ejecución no cambia nada.
Ver docs/COLUMNAS_DUPLICADAS.md.
"""

from django.core.management.base import BaseCommand

from sgr_app.services.columnas_duplicadas import unificar_columnas_duplicadas
from sgr_app.services.operacion import registrar_tarea


class Command(BaseCommand):
    help = 'Unifica las columnas duplicadas heredadas a favor de la vigente (simulación por defecto).'

    def add_arguments(self, parser):
        parser.add_argument(
            '--aplicar', action='store_true',
            help='Escribe los cambios. Sin esta opción solo informa qué cambiaría.',
        )

    def handle(self, *args, **options):
        aplicar = options['aplicar']
        with registrar_tarea('unificar_columnas_duplicadas') as resultado:
            resultados = unificar_columnas_duplicadas(aplicar=aplicar)
            total = sum(r.corregidos for r in resultados)
            resultado['detalle'] = (
                f'{total} registro(s) {"corregidos" if aplicar else "por corregir (simulación)"}'
            )

        modo = 'APLICADO' if aplicar else 'SIMULACIÓN (usa --aplicar para escribir)'
        self.stdout.write(f'Unificación de columnas duplicadas - {modo}\n')
        for r in resultados:
            linea = f'  {r.tabla:<12} revisados: {r.revisados:>6}   con diferencias: {r.corregidos:>6}'
            if r.ejemplos:
                linea += f'   ej. id {", ".join(map(str, r.ejemplos))}'
            self.stdout.write(linea)
        verbo = 'corregidos y auditados' if aplicar else 'se corregirían'
        self.stdout.write(self.style.SUCCESS(f'\nTotal: {total} registro(s) {verbo}.'))
