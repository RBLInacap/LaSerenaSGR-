"""Fase 2 de la unificación de columnas duplicadas (docs/COLUMNAS_DUPLICADAS.md).

Desde la fase 1 cada `save()` mantiene alineadas la columna vigente y la heredada.
Este módulo corrige de una vez los registros anteriores, sin esperar a que cada
uno se vuelva a guardar:

1. Si la vigente está vacía y la heredada no, se completa la vigente (salvo
   `Actividad.item`, que cambiaría los indicadores, y nunca para fechas).
2. Si la vigente tiene valor y la heredada difiere, la heredada pasa a tener el
   valor de la vigente.
3. Cada registro modificado deja un evento de auditoría
   (`UNIFICAR_COLUMNA_DUPLICADA`) con los valores anteriores y nuevos: por
   normativa ningún dato se pierde.

Escribe con `filter(pk=...).update()` fila por fila para no disparar los efectos
secundarios de `save()` (por ejemplo, guardar una evidencia recalcula el estado
de su compromiso). La auditoría (`Auditorias`) no se toca: es inmutable.
"""

from dataclasses import dataclass, field

from django.db import transaction
from django.db.models import F, Q
from django.db.models.functions import TruncDate
from django.utils import timezone

ACCION_AUDITORIA = 'UNIFICAR_COLUMNA_DUPLICADA'


@dataclass
class ResultadoTabla:
    tabla: str
    revisados: int = 0
    corregidos: int = 0
    ejemplos: list = field(default_factory=list)


def _vacio(valor):
    if valor is None:
        return True
    if isinstance(valor, str):
        return not valor.strip()
    nombre = getattr(valor, 'name', None)  # FieldFile
    if nombre is not None or hasattr(valor, 'storage'):
        return not nombre
    return False


def _valor_db(instancia, campo):
    """Valor tal como se guarda: el id en claves foráneas y el nombre en archivos."""
    attname = instancia._meta.get_field(campo).attname
    valor = getattr(instancia, attname)
    if hasattr(valor, 'storage'):
        return valor.name or ''
    return valor


def _cambios_por_pares(instancia, pares):
    """Calcula {campo: (anterior, nuevo)} aplicando las reglas 1 y 2."""
    cambios = {}
    for vigente, heredada, rellenar_vigente in pares:
        valor_vigente = _valor_db(instancia, vigente)
        valor_heredada = _valor_db(instancia, heredada)
        if _vacio(valor_vigente):
            if rellenar_vigente and not _vacio(valor_heredada):
                cambios[vigente] = (valor_vigente, valor_heredada)
            continue
        if valor_heredada != valor_vigente:
            cambios[heredada] = (valor_heredada, valor_vigente)
    return cambios


def _texto(valor):
    return '' if valor is None else str(valor)


def _aplicar(modelo, instancia, cambios):
    from sgr_app.models import RegistroAuditoria

    actualizacion = {
        modelo._meta.get_field(campo).attname: nuevo
        for campo, (_, nuevo) in cambios.items()
    }
    with transaction.atomic():
        modelo._base_manager.filter(pk=instancia.pk).update(**actualizacion)
        RegistroAuditoria.objects.create(
            evento='MODIFICACION',
            accion=ACCION_AUDITORIA,
            entidad=modelo.__name__,
            identificador=str(instancia.pk),
            identificador_registro=str(instancia.pk),
            valor_anterior={campo: _texto(anterior) for campo, (anterior, _) in cambios.items()},
            valor_nuevo={campo: _texto(nuevo) for campo, (_, nuevo) in cambios.items()},
        )


def _procesar(resultado, modelo, queryset, calcular_cambios, aplicar):
    for instancia in queryset.iterator(chunk_size=500):
        resultado.revisados += 1
        cambios = calcular_cambios(instancia)
        if not cambios:
            continue
        resultado.corregidos += 1
        if len(resultado.ejemplos) < 5:
            resultado.ejemplos.append(instancia.pk)
        if aplicar:
            _aplicar(modelo, instancia, cambios)
    return resultado


def _actividades(aplicar):
    from sgr_app.models import Actividad

    divergentes = Actividad.objects.filter(
        (~Q(actividad_solicitud=F('solicitud_problema')))
        | (~Q(accion_ejecutada=F('accion')))
        | Q(item__isnull=False, item_medicion__isnull=False) & ~Q(item_id=F('item_medicion_id'))
        | Q(item__isnull=True, item_medicion__isnull=False)
    )
    return _procesar(
        ResultadoTabla('Actividades'), Actividad, divergentes,
        lambda a: _cambios_por_pares(a, Actividad.COLUMNAS_DUPLICADAS), aplicar,
    )


def _compromisos(aplicar):
    from sgr_app.models import CompromisoAgenda

    divergentes = CompromisoAgenda.todos.filter(
        ~Q(fecha_compromiso=F('fecha_comprometida'))
        | Q(observacion__isnull=True, observaciones__isnull=False)
        | Q(observacion__isnull=False, observaciones__isnull=True)
        | ~Q(observacion=F('observaciones'))
    )
    return _procesar(
        ResultadoTabla('Compromisos'), CompromisoAgenda, divergentes,
        lambda c: _cambios_por_pares(c, CompromisoAgenda.COLUMNAS_DUPLICADAS), aplicar,
    )


def _periodos(aplicar):
    from sgr_app.models import PeriodoMedicion

    pares = (
        ('umbral_semaforo_verde', 'umbral_verde', False),
        ('umbral_semaforo_ambar', 'umbral_ambar', False),
    )
    divergentes = PeriodoMedicion.objects.filter(
        ~Q(umbral_verde=F('umbral_semaforo_verde')) | ~Q(umbral_ambar=F('umbral_semaforo_ambar'))
    )
    return _procesar(
        ResultadoTabla('Periodos'), PeriodoMedicion, divergentes,
        lambda p: _cambios_por_pares(p, pares), aplicar,
    )


def _evidencias(aplicar):
    from sgr_app.models import Evidencia

    def cambios_evidencia(evidencia):
        cambios = {}
        # La foto heredada solo completa la vigente vacía; `archivo` no se
        # sobrescribe porque ya no se escribe y apunta a cargas antiguas.
        if _vacio(evidencia.archivo_foto) and not _vacio(evidencia.archivo):
            cambios['archivo_foto'] = ('', evidencia.archivo.name)
        dia_subida = timezone.localdate(evidencia.fecha_subida) if evidencia.fecha_subida else None
        if dia_subida and evidencia.fecha_evidencia != dia_subida:
            cambios['fecha_evidencia'] = (evidencia.fecha_evidencia, dia_subida)
        return cambios

    candidatas = Evidencia.todas.annotate(dia_subida=TruncDate('fecha_subida')).filter(
        ~Q(fecha_evidencia=F('dia_subida'))
        | (Q(archivo_foto='') | Q(archivo_foto__isnull=True)) & ~Q(archivo='') & Q(archivo__isnull=False)
    )
    return _procesar(ResultadoTabla('Evidencias'), Evidencia, candidatas, cambios_evidencia, aplicar)


def unificar_columnas_duplicadas(aplicar=False):
    """Revisa (y con `aplicar=True` corrige) todas las tablas con columnas duplicadas."""
    return [
        _actividades(aplicar),
        _compromisos(aplicar),
        _periodos(aplicar),
        _evidencias(aplicar),
    ]
