"""Detección y alerta de eventos de seguridad (Ley 21.663, art. de reporte).

Los plazos de reporte al CSIRT Nacional corren desde que se *detecta* un
incidente (alerta temprana en 3 horas). Por eso los eventos sospechosos no
pueden quedar solo en el log: cada uno se guarda como `EventoSeguridad`
(evidencia para un eventual incidente) y se avisa por correo a ALERTAS_EMAIL.

Para no saturar el correo, un mismo motivo (tipo + clave de agrupación) se
alerta como máximo una vez cada `VENTANA_ALERTA`; los eventos se registran todos.
Nada de esto debe impedir que la aplicación responda: nunca lanza excepciones.
"""

import logging
from datetime import timedelta

from django.utils import timezone

logger = logging.getLogger('sgr.security')

VENTANA_ALERTA = timedelta(minutes=30)
# Accesos denegados del mismo usuario que se consideran sospechosos.
UMBRAL_ACCESOS_DENEGADOS = 10
VENTANA_ACCESOS_DENEGADOS = timedelta(minutes=10)


def registrar_evento(tipo, detalle, usuario=None, ip=None, agrupar_por='', alertar=True):
    """Guarda el evento y, si corresponde, envía la alerta. Devuelve el evento o None."""
    from sgr_app.models import EventoSeguridad
    from sgr_app.services.operacion import enviar_alerta

    try:
        ahora = timezone.now()
        clave = f'{tipo}:{agrupar_por}'[:200]
        ya_alertado = EventoSeguridad.objects.filter(
            clave_agrupacion=clave, alertado=True, creado_en__gte=ahora - VENTANA_ALERTA,
        ).exists()
        evento = EventoSeguridad.objects.create(
            tipo=tipo, detalle=str(detalle)[:4000],
            usuario=usuario if getattr(usuario, 'pk', None) else None,
            ip_origen=ip or None, clave_agrupacion=clave, creado_en=ahora,
        )
        if alertar and not ya_alertado:
            enviado = enviar_alerta(
                f'Evento de seguridad: {evento.get_tipo_display()}',
                f'{detalle}\n\nFecha: {timezone.localtime(ahora):%d/%m/%Y %H:%M:%S}\n'
                f'IP de origen: {ip or "-"}\n\n'
                'Si corresponde a un incidente con efecto significativo, regístrelo en '
                'SGR > Incidentes de seguridad: la alerta temprana al CSIRT Nacional '
                'vence 3 horas después de la detección (Ley 21.663).',
            )
            if enviado:
                EventoSeguridad.objects.filter(pk=evento.pk).update(alertado=True)
                evento.alertado = True
        return evento
    except Exception:  # noqa: BLE001 - la detección nunca debe romper la petición.
        logger.exception('No se pudo registrar el evento de seguridad %s', tipo)
        return None


def revisar_accesos_denegados(usuario, ip=None):
    """Alerta si un usuario acumula demasiados accesos denegados en poco tiempo."""
    from sgr_app.models import EventoSeguridad, RegistroAuditoria

    try:
        desde = timezone.now() - VENTANA_ACCESOS_DENEGADOS
        cantidad = RegistroAuditoria.objects.filter(
            funcionario=usuario, accion='ACCESO_DENEGADO', fecha_auditoria__gte=desde,
        ).count()
        if cantidad < UMBRAL_ACCESOS_DENEGADOS:
            return None
        clave = f'{EventoSeguridad.Tipo.ACCESOS_DENEGADOS_REPETIDOS}:{usuario.pk}'
        if EventoSeguridad.objects.filter(clave_agrupacion=clave, creado_en__gte=desde).exists():
            return None
        return registrar_evento(
            EventoSeguridad.Tipo.ACCESOS_DENEGADOS_REPETIDOS,
            f'El usuario {usuario.get_username()} acumuló {cantidad} accesos denegados en '
            f'{int(VENTANA_ACCESOS_DENEGADOS.total_seconds() // 60)} minutos (posible exploración de permisos).',
            usuario=usuario, ip=ip, agrupar_por=str(usuario.pk),
        )
    except Exception:  # noqa: BLE001
        logger.exception('No se pudo revisar los accesos denegados')
        return None


def verificar_triggers_auditoria(incluso_en_pruebas=False):
    """Comprueba que la base siga protegiendo la auditoría (triggers activos)."""
    from django.conf import settings
    from django.db import connection

    if getattr(settings, 'TESTING', False) and not incluso_en_pruebas:
        return True  # La base temporal de pruebas se crea sin triggers (ver migración 0031).

    from sgr_app.db_auditoria import TRIGGERS
    from sgr_app.models import EventoSeguridad, RegistroAuditoria

    tabla = RegistroAuditoria._meta.db_table
    with connection.cursor() as cursor:
        if connection.vendor == 'mysql':
            cursor.execute(
                'SELECT TRIGGER_NAME FROM information_schema.TRIGGERS '
                'WHERE TRIGGER_SCHEMA = DATABASE() AND EVENT_OBJECT_TABLE = %s', [tabla],
            )
        elif connection.vendor == 'sqlite':
            cursor.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name=%s", [tabla])
        else:
            return True
        presentes = {fila[0] for fila in cursor.fetchall()}
    faltantes = sorted(set(TRIGGERS) - presentes)
    if faltantes:
        registrar_evento(
            EventoSeguridad.Tipo.TRIGGERS_AUDITORIA_AUSENTES,
            f'Faltan los triggers {", ".join(faltantes)} sobre {tabla}: la auditoría podría '
            'modificarse por SQL directo. Recréalos y revisa quién tuvo acceso a la base.',
            agrupar_por=tabla,
        )
    return not faltantes
