"""Autenticación JWT de la API REST (SimpleJWT).

La emisión de tokens aplica las mismas reglas que el inicio de sesión web:

- Bloqueo temporal tras varios intentos fallidos (OWASP A07) -> 429.
- Cuentas con contraseña inicial pendiente no reciben token -> 403.
- Verificación en dos pasos (TOTP): si la cuenta la tiene activa, el código
  se envía en el mismo pedido (`codigo_2fa`) -> 401 si falta o es incorrecto.
- Roles con 2FA obligatoria que aún no la configuran no reciben token -> 403.
- Cada emisión queda en la auditoría inmutable.

El payload del token solo lleva el id y el rol: un JWT está firmado, no
cifrado, y cualquiera que lo tenga puede leer su contenido.
"""

from django.conf import settings
from drf_spectacular.utils import OpenApiExample, OpenApiResponse, extend_schema, inline_serializer
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied, Throttled
from rest_framework.throttling import ScopedRateThrottle
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import (
    TokenBlacklistView,
    TokenObtainPairView,
    TokenRefreshView,
)

from sgr_app.models import RegistroAuditoria
from sgr_app.services import seguridad_acceso
from sgr_app.services.seguridad_acceso import obtener_ip_cliente

ETIQUETA = 'autenticación JWT'


def _auditar_token(request, usuario, accion):
    RegistroAuditoria.objects.create(
        usuario=usuario,
        funcionario=usuario,
        evento='LOGIN',
        accion=accion,
        entidad='Usuario',
        identificador=str(usuario.pk),
        identificador_registro=str(usuario.pk),
        valor_nuevo={'username': usuario.get_username(), 'canal': 'API_JWT'},
        ip_origen=obtener_ip_cliente(request) or None,
    )


class ObtenerTokenSerializer(TokenObtainPairSerializer):
    codigo_2fa = serializers.CharField(
        required=False,
        allow_blank=True,
        write_only=True,
        help_text='Código de 6 dígitos de la app autenticadora. Solo si la cuenta tiene 2FA activa.',
    )

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['rol'] = user.rol
        return token

    def validate(self, attrs):
        from sgr_app.dos_factores import requiere_2fa_obligatorio
        from sgr_app.web_views import es_codigo_2fa_valido

        request = self.context['request']
        username = attrs.get(self.username_field, '')

        if seguridad_acceso.login_bloqueado(request, username):
            raise Throttled(detail=seguridad_acceso.mensaje_bloqueo())

        try:
            data = super().validate(attrs)
        except AuthenticationFailed as exc:
            seguridad_acceso.registrar_login_fallido(request, username)
            raise AuthenticationFailed(
                'Credenciales inválidas o usuario inactivo.',
                code='credenciales_invalidas',
            ) from exc
        usuario = self.user
        seguridad_acceso.registrar_login_exitoso(request, username)

        if usuario.must_change_password:
            raise PermissionDenied(
                'Debes definir tu contraseña desde la página de inicio de sesión '
                'antes de usar la API.'
            )

        if usuario.requires_2fa:
            if seguridad_acceso.two_factor_bloqueado(usuario):
                raise Throttled(detail=seguridad_acceso.mensaje_bloqueo())
            codigo = (attrs.get('codigo_2fa') or '').strip()
            if not codigo:
                raise AuthenticationFailed(
                    'Esta cuenta tiene verificación en dos pasos: envía también "codigo_2fa".',
                    code='requiere_2fa',
                )
            if not es_codigo_2fa_valido(usuario, codigo):
                seguridad_acceso.registrar_2fa_fallido(request, usuario)
                raise AuthenticationFailed('Código 2FA incorrecto.', code='codigo_2fa_invalido')
            seguridad_acceso.registrar_2fa_exitoso(usuario)
        elif requiere_2fa_obligatorio(usuario):
            raise PermissionDenied(
                'Tu rol exige verificación en dos pasos. Actívala en la web '
                '(Mi cuenta > Verificación en dos pasos) antes de usar la API.'
            )

        _auditar_token(request, usuario, 'EMITIR_TOKEN_JWT')
        data.update({
            'token_type': 'Bearer',
            'access_expira_en_segundos': int(
                settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds()
            ),
            'usuario': {
                'id': usuario.pk,
                'username': usuario.get_username(),
                'rol': usuario.rol,
            },
        })
        return data


ERRORES_TOKEN = {
    400: OpenApiResponse(description='Faltan campos obligatorios.'),
    401: OpenApiResponse(description='Credenciales inválidas, usuario inactivo o código 2FA ausente/incorrecto.'),
    403: OpenApiResponse(description='Contraseña inicial pendiente o 2FA obligatoria sin configurar.'),
    429: OpenApiResponse(description='Bloqueo temporal por intentos fallidos o exceso de peticiones.'),
}

RESPUESTA_TOKEN = inline_serializer('TokenParResponse', {
    'access': serializers.CharField(),
    'refresh': serializers.CharField(),
    'token_type': serializers.CharField(),
    'access_expira_en_segundos': serializers.IntegerField(),
    'usuario': inline_serializer('TokenUsuario', {
        'id': serializers.IntegerField(),
        'username': serializers.CharField(),
        'rol': serializers.CharField(),
    }),
})


class LimiteTokensMixin:
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'auth_jwt'


class ObtenerTokenView(LimiteTokensMixin, TokenObtainPairView):
    @extend_schema(
        summary='Obtener access y refresh token',
        description=(
            'Entrega un par de tokens JWT. Usa el `access` en la cabecera '
            '`Authorization: Bearer <access>` (o en el botón **Authorize** de Swagger).'
        ),
        responses={200: RESPUESTA_TOKEN, **ERRORES_TOKEN},
        examples=[
            OpenApiExample(
                'Credenciales',
                value={'username': 'admin@laserena.cl', 'password': 'MiClaveSegura!2026'},
                request_only=True,
            ),
            OpenApiExample(
                'Credenciales con 2FA',
                value={'username': 'admin@laserena.cl', 'password': 'MiClaveSegura!2026', 'codigo_2fa': '123456'},
                request_only=True,
            ),
            OpenApiExample(
                'Tokens emitidos',
                value={
                    'access': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                    'refresh': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                    'token_type': 'Bearer',
                    'access_expira_en_segundos': 900,
                    'usuario': {'id': 1, 'username': 'admin@laserena.cl', 'rol': 'ADMINISTRADOR'},
                },
                response_only=True,
                status_codes=['200'],
            ),
            OpenApiExample(
                'Credenciales inválidas',
                value={'detail': 'Credenciales inválidas o usuario inactivo.', 'code': 'credenciales_invalidas'},
                response_only=True,
                status_codes=['401'],
            ),
        ],
        tags=[ETIQUETA],
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


class RenovarTokenView(LimiteTokensMixin, TokenRefreshView):
    @extend_schema(
        summary='Renovar el access token',
        description=(
            'Recibe el `refresh` y entrega un `access` nuevo y un `refresh` nuevo. '
            'El refresh usado queda en la lista negra y no puede reutilizarse.'
        ),
        responses={
            200: inline_serializer('TokenRenovadoResponse', {
                'access': serializers.CharField(),
                'refresh': serializers.CharField(),
            }),
            401: OpenApiResponse(description='Refresh token inválido, vencido o ya utilizado.'),
        },
        tags=[ETIQUETA],
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


class CerrarSesionTokenView(TokenBlacklistView):
    @extend_schema(
        summary='Cerrar sesión (revocar refresh token)',
        description='Agrega el refresh token a la lista negra. El access vigente expira solo a los pocos minutos.',
        responses={
            200: OpenApiResponse(description='Refresh token revocado.'),
            401: OpenApiResponse(description='Refresh token inválido o ya revocado.'),
        },
        tags=[ETIQUETA],
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)
