"""Páginas de error: JSON para la API y HTML para la web.

DRF ya responde JSON dentro de sus vistas. Estos manejadores cubren lo que
ocurre fuera de ellas, por ejemplo una ruta /api/... que no existe.
Django solo los usa con DEBUG=False.
"""

from django.http import JsonResponse
from django.views import defaults

from sgr_app.services.auditoria_acceso import MENSAJE_ERROR_INTERNO


def _es_api(request):
    return request.path.startswith('/api/')


def manejar_404(request, exception):
    if _es_api(request):
        return JsonResponse(
            {'detail': 'Recurso no encontrado. Revisa la ruta en /api/v1/docs/.', 'code': 'no_encontrado'},
            status=404,
        )
    return defaults.page_not_found(request, exception)


def manejar_500(request):
    if _es_api(request):
        return JsonResponse({'detail': MENSAJE_ERROR_INTERNO, 'code': 'error_interno'}, status=500)
    return defaults.server_error(request)
