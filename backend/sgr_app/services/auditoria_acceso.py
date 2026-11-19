"""Registro de accesos denegados (HU-26, CU-01/CU-02; OWASP A01/A09).

Cada respuesta 403 a un usuario autenticado, en la web o en la API, queda en la
auditoría inmutable con el usuario, la ruta, el método y la IP de origen.
"""
import logging

from rest_framework.views import exception_handler as drf_exception_handler

logger = logging.getLogger('sgr.security')


def registrar_acceso_denegado(request, detalle=''):
    usuario = getattr(request, 'user', None)
    if not usuario or not usuario.is_authenticated:
        return
    from sgr_app.models import RegistroAuditoria
    from sgr_app.services.seguridad_acceso import obtener_ip_cliente

    ruta = request.get_full_path()[:500]
    logger.warning(
        'Acceso denegado: usuario=%r metodo=%s ruta=%s', usuario.get_username(), request.method, ruta,
    )
    try:
        RegistroAuditoria.objects.create(
            usuario=usuario,
            funcionario=usuario,
            evento='ACCESO_DENEGADO',
            accion='ACCESO_DENEGADO',
            entidad='Acceso',
            identificador=request.method[:50],
            identificador_registro=request.method[:50],
            valor_anterior=None,
            valor_nuevo={'ruta': ruta, 'metodo': request.method, 'detalle': str(detalle)[:300]},
            ip_origen=obtener_ip_cliente(request) or None,
        )
    except Exception:  # El registro nunca debe impedir responder el 403.
        logger.exception('No se pudo auditar el acceso denegado a %s', ruta)


MENSAJE_ERROR_INTERNO = (
    'Error interno del servidor. El incidente quedó registrado; '
    'intenta nuevamente o contacta al administrador.'
)


def exception_handler_api(exc, context):
    """Manejador de errores de la API.

    - 4xx: respuesta JSON estándar de DRF; los 403 quedan en la auditoría.
    - Error no controlado: 500 en JSON con un mensaje genérico. El detalle y la
      traza van solo al log (y al correo de alertas), nunca al cliente
      (OWASP A05: no exponer información interna). Con DEBUG=True se deja
      propagar para ver la traza completa durante el desarrollo.
    """
    from django.conf import settings

    response = drf_exception_handler(exc, context)
    request = context.get('request')
    if response is not None:
        if response.status_code == 403 and request is not None:
            registrar_acceso_denegado(request, getattr(exc, 'detail', ''))
        # Código legible por máquinas junto al mensaje, p. ej. "not_authenticated".
        datos = response.data
        if isinstance(datos, dict) and 'detail' in datos and 'code' not in datos:
            codigo = exc.get_codes() if hasattr(exc, 'get_codes') else None
            if isinstance(codigo, str):
                datos['code'] = codigo
        return response

    if settings.DEBUG:
        return None

    from rest_framework import status
    from rest_framework.response import Response
    from rest_framework.views import set_rollback

    set_rollback()
    ruta = request.get_full_path()[:500] if request is not None else ''
    logging.getLogger('django.request').error(
        'Error no controlado en la API: %s %s', getattr(request, 'method', ''), ruta,
        exc_info=(type(exc), exc, exc.__traceback__),
    )
    response = Response(
        {'detail': MENSAJE_ERROR_INTERNO, 'code': 'error_interno'},
        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )
    response._has_been_logged = True  # Evita que Django lo registre dos veces.
    return response
