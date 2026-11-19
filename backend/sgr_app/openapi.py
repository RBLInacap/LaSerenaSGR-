"""Ajustes del esquema OpenAPI (RNF-016)."""

from drf_spectacular.contrib.rest_framework_simplejwt import SimpleJWTScheme


class JWTAutenticacionSGRScheme(SimpleJWTScheme):
    """Esquema Bearer JWT para Swagger (habilita el botón Authorize).

    drf-spectacular reconoce la clase de SimpleJWT, pero no sus subclases;
    esta extensión le indica que JWTAutenticacionSGR usa el mismo esquema.
    """

    target_class = 'sgr_app.autenticacion_jwt.JWTAutenticacionSGR'
    name = 'jwtAuth'


def solo_api_v1(endpoints, **kwargs):
    """
    Documenta solo la versión estable /api/v1/. La ruta /api/ sin versión se
    mantiene por compatibilidad con la interfaz web, pero no forma parte del
    contrato publicado para integraciones.
    """
    return [endpoint for endpoint in endpoints if endpoint[0].startswith('/api/v1/')]
