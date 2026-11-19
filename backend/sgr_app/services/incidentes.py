"""Seguimiento de plazos de reporte de incidentes al CSIRT Nacional (Ley 21.663).

- Al registrar un incidente con efecto significativo se avisa de inmediato con
  los tres vencimientos (alerta temprana 3 h, actualización 72 h, informe 15 días).
- El monitor (cada minuto) avisa una vez cuando un hito entra en su último
  cuarto de plazo y una vez cuando vence sin haberse marcado como enviado.
- El reporte exportable reúne lo que pide cada hito del esquema de notificación.
"""

from django.utils import timezone

from sgr_app.services.operacion import enviar_alerta


def _fecha(valor):
    return timezone.localtime(valor).strftime('%d/%m/%Y %H:%M') if valor else '-'


def notificar_incidente_creado(incidente):
    if not incidente.requiere_reporte:
        return False
    vencimientos = '\n'.join(f'- {h["nombre"]}: vence {_fecha(h["vence"])}' for h in incidente.hitos())
    return enviar_alerta(
        f'Incidente {incidente.codigo} con efecto significativo: reportar al CSIRT Nacional',
        f'{incidente.titulo}\nSeveridad: {incidente.get_severidad_display()}\n'
        f'Detectado: {_fecha(incidente.detectado_en)}\n\nPlazos (Ley 21.663):\n{vencimientos}\n\n'
        'Reporte en https://portal.anci.gob.cl y marque cada hito como enviado en el SGR.',
    )


def revisar_plazos_incidentes(ahora=None):
    """Envía las alertas pendientes de plazos. Devuelve cuántas se enviaron."""
    from sgr_app.models import IncidenteSeguridad

    ahora = ahora or timezone.now()
    enviadas = 0
    abiertos = IncidenteSeguridad.objects.exclude(estado=IncidenteSeguridad.Estado.CERRADO)
    for incidente in abiertos:
        if not incidente.requiere_reporte:
            continue
        ya = set(incidente.alertas_enviadas or [])
        nuevas = []
        for hito in incidente.hitos(ahora):
            if hito['estado'] not in ('POR_VENCER', 'VENCIDO'):
                continue
            clave = f'{hito["clave"]}:{hito["estado"]}'
            if clave in ya:
                continue
            asunto = (
                f'VENCIDO: {hito["nombre"]} del incidente {incidente.codigo}'
                if hito['estado'] == 'VENCIDO'
                else f'Por vencer: {hito["nombre"]} del incidente {incidente.codigo}'
            )
            enviar_alerta(asunto, f'{incidente.titulo}\nVence: {_fecha(hito["vence"])}\n'
                                  'Reporte en https://portal.anci.gob.cl y márquelo como enviado en el SGR.')
            nuevas.append(clave)
        if nuevas:
            IncidenteSeguridad.objects.filter(pk=incidente.pk).update(alertas_enviadas=sorted(ya | set(nuevas)))
            enviadas += len(nuevas)
    return enviadas


def reporte_texto(incidente):
    """Texto con los datos que pide cada hito, para copiar en el portal de la ANCI."""
    criterios = [
        etiqueta for activo, etiqueta in (
            (incidente.afecta_continuidad, 'Interrumpe la continuidad de un servicio esencial'),
            (incidente.afecta_personas, 'Afecta la integridad física o la salud de las personas'),
            (incidente.afecta_datos_personales, 'Afecta sistemas informáticos con datos personales'),
        ) if activo
    ] or ['Ninguno (no requiere reporte al CSIRT Nacional)']
    lineas = [
        f'REPORTE DE INCIDENTE DE CIBERSEGURIDAD {incidente.codigo}',
        'Sistema de Gestión de Resultados (SGR) - Ilustre Municipalidad de La Serena',
        f'Generado: {_fecha(timezone.now())}',
        '',
        '1. ALERTA TEMPRANA',
        f'Título: {incidente.titulo}',
        f'Categoría: {incidente.get_categoria_display()}',
        f'Severidad: {incidente.get_severidad_display()}',
        f'Detectado: {_fecha(incidente.detectado_en)}',
        f'Ocurrido (estimado): {_fecha(incidente.ocurrido_en)}',
        'Efecto significativo: ' + '; '.join(criterios),
        f'Descripción: {incidente.descripcion}',
        f'Sistemas afectados: {incidente.sistemas_afectados or "-"}',
        '',
        '2. ACTUALIZACIÓN (evaluación inicial)',
        f'Gravedad e impacto: {incidente.impacto or "-"}',
        f'Indicadores de compromiso (IoC): {incidente.indicadores_compromiso or "-"}',
        f'Medidas de contención: {incidente.medidas_contencion or "-"}',
        '',
        '3. INFORME FINAL',
        f'Estado: {incidente.get_estado_display()} (cerrado: {_fecha(incidente.cerrado_en)})',
        f'Causa raíz y lecciones aprendidas: {incidente.causa_raiz or "-"}',
        '',
        'PLAZOS Y ENVÍOS',
    ]
    for hito in incidente.hitos():
        lineas.append(f'- {hito["nombre"]}: vence {_fecha(hito["vence"])}; '
                      f'enviado {_fecha(hito["enviado_en"])} [{hito["estado"]}]')
    lineas.append(f'Folio ANCI: {incidente.folio_csirt or "-"}')
    eventos = list(incidente.eventos.all())
    if eventos:
        lineas += ['', 'EVENTOS DE SEGURIDAD ASOCIADOS (evidencia)']
        lineas += [f'- {_fecha(e.creado_en)} {e.get_tipo_display()} IP {e.ip_origen or "-"}: {e.detalle}'
                   for e in eventos]
    acciones = list(incidente.acciones.select_related('autor'))
    if acciones:
        lineas += ['', 'BITÁCORA DE ACCIONES']
        lineas += [f'- {_fecha(a.creado_en)} {a.autor.get_full_name() or a.autor.username}: {a.texto}'
                   for a in acciones]
    return '\n'.join(lineas) + '\n'
