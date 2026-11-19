"""Clase de autenticación JWT referenciada desde REST_FRAMEWORK en settings.

Vive en un módulo aparte (sin vistas) porque DRF la importa al arrancar;
si estuviera junto a las vistas de tokens se produciría una importación circular.
"""

from rest_framework_simplejwt.authentication import JWTAuthentication

from sgr_app.services.contexto import fijar_usuario_actual


class JWTAutenticacionSGR(JWTAuthentication):
    """JWTAuthentication que además informa el usuario a la auditoría de modelos.

    El middleware de auditoría solo conoce el usuario de la sesión; con JWT el
    usuario se resuelve dentro de DRF, por eso se fija aquí. SimpleJWT ya
    rechaza los tokens de usuarios desactivados (is_active=False).
    """

    def authenticate(self, request):
        resultado = super().authenticate(request)
        if resultado is not None:
            fijar_usuario_actual(resultado[0])
        return resultado
