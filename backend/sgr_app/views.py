from django.utils import timezone
from django.utils.dateparse import parse_date
from django.contrib.auth import authenticate, login
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.db.models import Prefetch, Q
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import (
    OpenApiExample,
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
    inline_serializer,
)
from rest_framework import serializers as drf_serializers
from rest_framework.exceptions import (
    NotFound,
    PermissionDenied as DRFPermissionDenied,
    ValidationError as DRFValidationError,
)

from sgr_app.services.seguridad_acceso import obtener_ip_cliente
from sgr_app.concurrencia import ConcurrenciaAPIMixin
from sgr_app.permissions import AuditAccessPermission
from sgr_app.models import (
    Usuario, Delegacion, Cargo, PeriodoMedicion, CatalogoServicio,
    ItemMedicion, CompromisoAgenda, Actividad, Evidencia,
    CasoSocial, AtencionSocial, RegistroAuditoria,
    Area, Solicitante, TipoAtencionSocial, SubatencionSocial,
    OrganizacionComunitaria, RegistroTuboTrabajo, CartaSeguimiento,
    Rol, TipoActividad, ConceptoAjuste, AjusteIncentivo,
)
from sgr_app.web_views import (
    _puede_gestionar_compromiso,
    es_codigo_2fa_valido,
    puede_anular_actividades,
)
from sgr_app.services import seguridad_acceso
from sgr_app.serializers import (
    UsuarioSerializer, DelegacionSerializer, CargoSerializer,
    PeriodoMedicionSerializer, CatalogoServicioSerializer,
    ItemMedicionSerializer, CompromisoAgendaSerializer,
    ActividadSerializer, EvidenciaSerializer,
    CasoSocialSerializer, AtencionSocialSerializer,
    RegistroAuditoriaSerializer,
    AreaSerializer, SolicitanteSerializer, TipoAtencionSocialSerializer,
    SubatencionSocialSerializer, OrganizacionComunitariaSerializer,
    RegistroTuboTrabajoSerializer, CartaSeguimientoSerializer,
    RolSerializer, TipoActividadSerializer, ConceptoAjusteSerializer, AjusteIncentivoSerializer,
)
from sgr_app.services.calculos import (
    calcular_metricas_funcionario,
    calcular_resumen_delegacion,
    calcular_resumen_comunal,
    recalcular_indicadores_actividad,
)
from sgr_app.services.evidencias import metadatos_archivo_evidencia, validar_archivo_evidencia


def registrar_evento_auditoria(request, usuario, accion, entidad, identificador, val_ant=None, val_nuevo=None):
    ip = obtener_ip_cliente(request) or None
    accion_normalizada = accion.upper()
    if accion_normalizada in {'INICIO_SESION', 'LOGIN'}:
        evento = 'LOGIN'
    elif any(token in accion_normalizada for token in ('APROBAR', 'VALIDAR')):
        evento = 'APROBACION'
    elif accion_normalizada.startswith(('ELIMINAR', 'BORRAR')):
        evento = 'ELIMINACION'
    else:
        evento = 'MODIFICACION' if val_ant is not None else 'CREACION'
    RegistroAuditoria.objects.create(
        usuario=usuario,
        funcionario=usuario,
        evento=evento,
        accion=accion,
        entidad=entidad,
        identificador=str(identificador),
        identificador_registro=str(identificador),
        valor_anterior=val_ant,
        valor_nuevo=val_nuevo,
        ip_origen=ip,
    )


class AuthLoginView(APIView):
    """
    Login seguro con autenticación de credenciales y preparación para 2FA.
    """
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary='Iniciar sesión',
        description='Crea la sesión. Si la cuenta tiene 2FA, responde requires_2fa=true y se debe '
                    'llamar a /auth/verificar-2fa/. Tras 5 intentos fallidos responde 429.',
        request=inline_serializer('LoginRequest', {
            'username': drf_serializers.CharField(), 'password': drf_serializers.CharField(),
        }),
        responses={200: OpenApiTypes.OBJECT, 400: OpenApiTypes.OBJECT, 401: OpenApiTypes.OBJECT,
                   403: OpenApiTypes.OBJECT, 429: OpenApiTypes.OBJECT},
        tags=['autenticación'],
    )
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response(
                {'error': 'Debe proporcionar usuario y contraseña.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # OWASP A07: bloqueo temporal tras varios intentos fallidos.
        if seguridad_acceso.login_bloqueado(request, username):
            return Response(
                {'error': seguridad_acceso.mensaje_bloqueo()},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        user = authenticate(request._request, username=username, password=password)
        if not user:
            seguridad_acceso.registrar_login_fallido(request, username)
            return Response(
                {'error': 'Credenciales inválidas o usuario inactivo.'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        seguridad_acceso.registrar_login_exitoso(request, username)

        # La activación con clave inicial solo se completa en la web, dentro de su plazo.
        if user.must_change_password:
            return Response(
                {
                    'error': 'Debes definir tu contraseña desde la página de inicio de sesión '
                             'antes de usar la API.',
                    'requires_password_change': True,
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        # Si el usuario tiene 2FA activado (módulo de Rodrigo)
        if user.requires_2fa:
            request.session['pending_2fa_user_id'] = user.pk
            request.session.set_expiry(300)
            return Response({
                'requires_2fa': True,
                'user_id': user.id,
                'username': user.username,
                'message': 'Autenticación en dos pasos requerida.'
            }, status=status.HTTP_200_OK)

        login(request._request, user)
        registrar_evento_auditoria(request, user, 'INICIO_SESION', 'Usuario', user.id, None, {'username': user.username})

        serializer = UsuarioSerializer(user)
        return Response({
            'requires_2fa': False,
            'user': serializer.data,
            'authenticated': True
        }, status=status.HTTP_200_OK)


class Verificar2FAView(APIView):
    """
    Endpoint preparado para que Rodrigo valide el código TOTP / 2FA.
    """
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary='Verificar código 2FA',
        request=inline_serializer('Verificar2FARequest', {'code': drf_serializers.CharField()}),
        responses={200: OpenApiTypes.OBJECT, 400: OpenApiTypes.OBJECT, 401: OpenApiTypes.OBJECT,
                   429: OpenApiTypes.OBJECT},
        tags=['autenticación'],
    )
    def post(self, request):
        user_id = request.session.get('pending_2fa_user_id')
        code = request.data.get('code')
        if not user_id:
            return Response({'error': 'Debe iniciar sesión con usuario y contraseña antes de verificar 2FA.'}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            user = Usuario.objects.get(id=user_id, is_active=True, requires_2fa=True)
        except Usuario.DoesNotExist:
            return Response({'error': 'Usuario no encontrado'}, status=status.HTTP_404_NOT_FOUND)

        if seguridad_acceso.two_factor_bloqueado(user):
            request.session.pop('pending_2fa_user_id', None)
            return Response(
                {'error': seguridad_acceso.mensaje_bloqueo()},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        if es_codigo_2fa_valido(user, code):
            seguridad_acceso.registrar_2fa_exitoso(user)
            request.session.pop('pending_2fa_user_id', None)
            login(request._request, user)
            registrar_evento_auditoria(request, user, 'VERIFICACION_2FA', 'Usuario', user.id)
            serializer = UsuarioSerializer(user)
            return Response({
                'success': True,
                'user': serializer.data,
                'authenticated': True
            })
        else:
            seguridad_acceso.registrar_2fa_fallido(request, user)
            return Response({'error': 'Código 2FA incorrecto o inválido'}, status=status.HTTP_400_BAD_REQUEST)


class SinBorradoFisicoMixin:
    """Por normativa ningún registro se elimina: la API no expone DELETE.

    Los registros se desactivan o se anulan con motivo (baja lógica).
    """

    http_method_names = ['get', 'post', 'put', 'patch', 'head', 'options']


class BajaLogicaMixin:
    """DELETE disponible, pero como baja lógica: nunca se borra la fila.

    Cumple la normativa municipal (no hay borrado físico) y el contrato REST
    (DELETE desactiva o anula el recurso y conserva su historial).

    Cada ViewSet que use este mixin debe redefinir el método DELETE con su
    propia baja lógica. Si lo olvida, este método responde 405 en lugar de
    caer en el borrado físico que DRF trae por defecto.
    """

    http_method_names = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options']

    def destroy(self, request, *args, **kwargs):
        return Response(
            {'detail': 'Este recurso no admite bajas por la API.'},
            status=status.HTTP_405_METHOD_NOT_ALLOWED,
        )


def _auditar_api(request, evento, accion, instancia, antes=None, despues=None):
    RegistroAuditoria.objects.create(
        usuario=request.user,
        funcionario=request.user,
        evento=evento,
        accion=accion,
        entidad=type(instancia).__name__,
        identificador=str(instancia.pk),
        identificador_registro=str(instancia.pk),
        valor_anterior=antes,
        valor_nuevo=despues,
        ip_origen=obtener_ip_cliente(request) or None,
    )


ERRORES_COMUNES = {
    401: OpenApiResponse(description='Falta el token JWT o está vencido.'),
    403: OpenApiResponse(description='Tu perfil no tiene permiso para esta operación.'),
    404: OpenApiResponse(description='El registro no existe o está fuera de tu ámbito.'),
}
ERRORES_ESCRITURA = {
    400: OpenApiResponse(description='Datos inválidos; el cuerpo indica el error de cada campo.'),
    **ERRORES_COMUNES,
}
RESPUESTA_BAJA_LOGICA = inline_serializer('BajaLogicaResponse', {
    'detail': drf_serializers.CharField(),
    'id': drf_serializers.IntegerField(),
    'advertencias': drf_serializers.ListField(child=drf_serializers.CharField(), required=False),
})


def _campos_delegacion(delegacion):
    return {
        'nombre': delegacion.nombre,
        'codigo': delegacion.codigo,
        'activo': delegacion.activo,
    }


@extend_schema_view(
    list=extend_schema(
        summary='Listar delegaciones',
        description='Todas las delegaciones, activas e inactivas (campo `activo`).',
        responses={200: DelegacionSerializer(many=True), **ERRORES_COMUNES},
        tags=['mantenedor: delegaciones'],
    ),
    retrieve=extend_schema(
        summary='Ver una delegación',
        responses={200: DelegacionSerializer, **ERRORES_COMUNES},
        tags=['mantenedor: delegaciones'],
    ),
    create=extend_schema(
        summary='Crear delegación (Administrador)',
        responses={201: DelegacionSerializer, **ERRORES_ESCRITURA},
        examples=[OpenApiExample(
            'Nueva delegación',
            value={'nombre': 'Delegación Centro', 'codigo': 'CEN', 'direccion': 'Prat 451',
                   'telefono': '512206000', 'email': 'centro@laserena.cl', 'ambito': 'Urbano'},
            request_only=True,
        )],
        tags=['mantenedor: delegaciones'],
    ),
    update=extend_schema(
        summary='Reemplazar delegación (Administrador)',
        responses={200: DelegacionSerializer, **ERRORES_ESCRITURA},
        tags=['mantenedor: delegaciones'],
    ),
    partial_update=extend_schema(
        summary='Modificar delegación (Administrador)',
        description='Para reactivar una delegación dada de baja envía `{"activo": true}`.',
        responses={200: DelegacionSerializer, **ERRORES_ESCRITURA},
        tags=['mantenedor: delegaciones'],
    ),
    destroy=extend_schema(
        summary='Dar de baja una delegación (Administrador)',
        description=(
            'Baja lógica: marca `activo=false` y conserva la delegación con todo su historial. '
            'Responde advertencias si aún tiene funcionarios activos o compromisos abiertos.'
        ),
        responses={200: RESPUESTA_BAJA_LOGICA, **ERRORES_COMUNES},
        examples=[OpenApiExample(
            'Baja realizada',
            value={'detail': 'Delegación dada de baja. Su historial se conserva.', 'id': 3,
                   'advertencias': ['La delegación tiene 2 funcionarios activos asignados.']},
            response_only=True,
            status_codes=['200'],
        )],
        tags=['mantenedor: delegaciones'],
    ),
)
class DelegacionViewSet(BajaLogicaMixin, viewsets.ModelViewSet):
    queryset = Delegacion.objects.all()
    serializer_class = DelegacionSerializer

    def perform_create(self, serializer):
        with transaction.atomic():
            delegacion = serializer.save()
            _auditar_api(self.request, 'CREACION', 'CREAR_DELEGACION_API', delegacion,
                         None, _campos_delegacion(delegacion))

    def perform_update(self, serializer):
        antes = _campos_delegacion(serializer.instance)
        with transaction.atomic():
            delegacion = serializer.save()
            _auditar_api(self.request, 'MODIFICACION', 'ACTUALIZAR_DELEGACION_API', delegacion,
                         antes, _campos_delegacion(delegacion))

    def destroy(self, request, *args, **kwargs):
        delegacion = self.get_object()
        if not delegacion.activo:
            return Response({
                'detail': 'La delegación ya estaba dada de baja.',
                'id': delegacion.pk,
            })
        advertencias = []
        funcionarios = delegacion.usuarios.filter(is_active=True).count()
        if funcionarios:
            advertencias.append(
                f'La delegación tiene {funcionarios} funcionario(s) activo(s) asignado(s).'
            )
        abiertos = delegacion.compromisos.filter(anulado=False).exclude(
            estado__in=(
                CompromisoAgenda.Estado.REALIZADO,
            ),
        ).count()
        if abiertos:
            advertencias.append(f'Tiene {abiertos} compromiso(s) sin cerrar.')

        antes = _campos_delegacion(delegacion)
        with transaction.atomic():
            delegacion.activo = False
            delegacion.save(update_fields=['activo'])
            _auditar_api(request, 'ELIMINACION', 'BAJA_LOGICA', delegacion,
                         antes, _campos_delegacion(delegacion))
        return Response({
            'detail': 'Delegación dada de baja. Su historial se conserva.',
            'id': delegacion.pk,
            'advertencias': advertencias,
        })


class CargoViewSet(SinBorradoFisicoMixin, viewsets.ModelViewSet):
    queryset = Cargo.objects.all()
    serializer_class = CargoSerializer


def _campos_funcionario(usuario):
    return {
        'username': usuario.username,
        'rol': usuario.rol,
        'cargo_id': usuario.cargo_id,
        'delegacion_id': usuario.delegacion_id,
        'area_entidad_id': usuario.area_entidad_id,
        'is_active': usuario.is_active,
    }


@extend_schema_view(
    list=extend_schema(
        summary='Listar funcionarios',
        description=(
            'El Administrador y el Coordinador ven a todos; el Delegado, a los de su '
            'delegación; el Funcionario, solo a sí mismo. Correo, teléfono, RUN y '
            '`requires_2fa` solo se incluyen para el Administrador.'
        ),
        parameters=[
            OpenApiParameter('delegacion', int, description='Filtra por id de delegación.'),
            OpenApiParameter('rol', str, description='Filtra por rol (ADMINISTRADOR, COORDINADOR, ...).'),
        ],
        responses={200: UsuarioSerializer(many=True), **ERRORES_COMUNES},
        examples=[
            OpenApiExample(
                'Vista del Administrador',
                value=[{'id': 7, 'username': 'jperez@laserena.cl', 'first_name': 'Juana',
                        'last_name': 'Pérez Soto', 'email': 'jperez@laserena.cl', 'rol': 'FUNCIONARIO',
                        'roles': [], 'es_delegado': False, 'area_entidad': 2, 'cargo': 4,
                        'cargo_nombre': 'Gestor territorial', 'delegacion': 1,
                        'delegacion_nombre': 'Delegación Centro', 'delegacion_codigo': 'CEN',
                        'telefono': '+56912345678', 'rut_anonimizado': '12.345.678-5',
                        'requires_2fa': False, 'is_active': True}],
                response_only=True,
                status_codes=['200'],
            ),
            OpenApiExample(
                'Vista de otros perfiles (sin datos sensibles)',
                value=[{'id': 7, 'username': 'jperez@laserena.cl', 'first_name': 'Juana',
                        'last_name': 'Pérez Soto', 'rol': 'FUNCIONARIO', 'roles': [],
                        'es_delegado': False, 'area_entidad': 2, 'cargo': 4,
                        'cargo_nombre': 'Gestor territorial', 'delegacion': 1,
                        'delegacion_nombre': 'Delegación Centro', 'delegacion_codigo': 'CEN',
                        'is_active': True}],
                response_only=True,
                status_codes=['200'],
            ),
        ],
        tags=['mantenedor: funcionarios'],
    ),
    retrieve=extend_schema(
        summary='Ver un funcionario',
        responses={200: UsuarioSerializer, **ERRORES_COMUNES},
        tags=['mantenedor: funcionarios'],
    ),
    create=extend_schema(
        summary='Crear funcionario (Administrador)',
        description=(
            'Obligatorios: `email`, `rut_anonimizado`, `first_name`, `last_name`. '
            'El correo será su usuario y su clave inicial es el RUN sin puntos ni guion; '
            'debe cambiarla en la web dentro de 10 minutos.'
        ),
        responses={201: UsuarioSerializer, **ERRORES_ESCRITURA},
        examples=[OpenApiExample(
            'Nuevo funcionario',
            value={'email': 'jperez@laserena.cl', 'rut_anonimizado': '12.345.678-5',
                   'first_name': 'Juana', 'last_name': 'Pérez Soto', 'rol': 'FUNCIONARIO',
                   'delegacion': 1, 'cargo': 4, 'area_entidad': 2, 'telefono': '912345678'},
            request_only=True,
        )],
        tags=['mantenedor: funcionarios'],
    ),
    update=extend_schema(
        summary='Reemplazar funcionario (Administrador)',
        responses={200: UsuarioSerializer, **ERRORES_ESCRITURA},
        tags=['mantenedor: funcionarios'],
    ),
    partial_update=extend_schema(
        summary='Modificar funcionario (Administrador)',
        description='Para reactivar a un funcionario dado de baja envía `{"is_active": true}`.',
        responses={200: UsuarioSerializer, **ERRORES_ESCRITURA},
        tags=['mantenedor: funcionarios'],
    ),
    destroy=extend_schema(
        summary='Dar de baja un funcionario (Administrador)',
        description=(
            'Baja lógica: `is_active=false`. El funcionario ya no puede iniciar sesión '
            'ni usar sus tokens, y se conservan sus actividades y su auditoría. '
            'No puedes darte de baja a ti mismo.'
        ),
        responses={200: RESPUESTA_BAJA_LOGICA, **ERRORES_COMUNES,
                   400: OpenApiResponse(description='Intento de darse de baja a sí mismo.')},
        tags=['mantenedor: funcionarios'],
    ),
)
class UsuarioViewSet(BajaLogicaMixin, viewsets.ModelViewSet):
    queryset = Usuario.objects.all()
    serializer_class = UsuarioSerializer

    def perform_create(self, serializer):
        with transaction.atomic():
            funcionario = serializer.save()
            _auditar_api(self.request, 'CREACION', 'CREAR_FUNCIONARIO_API', funcionario,
                         None, _campos_funcionario(funcionario))

    def perform_update(self, serializer):
        antes = _campos_funcionario(serializer.instance)
        with transaction.atomic():
            funcionario = serializer.save()
            _auditar_api(self.request, 'MODIFICACION', 'ACTUALIZAR_FUNCIONARIO_API', funcionario,
                         antes, _campos_funcionario(funcionario))

    def destroy(self, request, *args, **kwargs):
        funcionario = self.get_object()
        if funcionario.pk == request.user.pk:
            return Response(
                {'detail': 'No puedes dar de baja tu propia cuenta.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not funcionario.is_active:
            return Response({
                'detail': 'El funcionario ya estaba dado de baja.',
                'id': funcionario.pk,
            })
        antes = _campos_funcionario(funcionario)
        with transaction.atomic():
            funcionario.desactivar_usuario()
            _auditar_api(request, 'ELIMINACION', 'BAJA_LOGICA', funcionario,
                         antes, _campos_funcionario(funcionario))
        return Response({
            'detail': 'Funcionario dado de baja. Ya no puede iniciar sesión; su historial se conserva.',
            'id': funcionario.pk,
            'advertencias': [],
        })

    def get_queryset(self):
        qs = Usuario.objects.all()
        if self.request.user.es_funcionario:
            qs = qs.filter(pk=self.request.user.pk)
        elif self.request.user.esta_limitado_a_delegacion:
            qs = qs.filter(delegacion_id=self.request.user.delegacion_id)
        delegacion_id = self.request.query_params.get('delegacion')
        rol = self.request.query_params.get('rol')
        if delegacion_id:
            qs = qs.filter(delegacion_id=delegacion_id)
        if rol:
            qs = qs.filter(rol=rol)
        return qs


class PeriodoMedicionViewSet(SinBorradoFisicoMixin, viewsets.ModelViewSet):
    queryset = PeriodoMedicion.objects.all()
    serializer_class = PeriodoMedicionSerializer


class CatalogoServicioViewSet(SinBorradoFisicoMixin, viewsets.ModelViewSet):
    queryset = CatalogoServicio.objects.filter(activo=True)
    serializer_class = CatalogoServicioSerializer


class ItemMedicionViewSet(SinBorradoFisicoMixin, viewsets.ModelViewSet):
    queryset = ItemMedicion.objects.all()
    serializer_class = ItemMedicionSerializer

    def get_queryset(self):
        qs = ItemMedicion.objects.all()
        cargo_id = self.request.query_params.get('cargo')
        periodo_id = self.request.query_params.get('periodo')
        if cargo_id:
            qs = qs.filter(cargo_id=cargo_id)
        if periodo_id:
            qs = qs.filter(periodo_id=periodo_id)
        return qs


class CompromisoAgendaViewSet(SinBorradoFisicoMixin, ConcurrenciaAPIMixin, viewsets.ModelViewSet):
    """
    Tubo de Trabajo / Agenda Colectiva.
    Permite transiciones controladas de estado y auditoría.
    """
    queryset = CompromisoAgenda.objects.all()
    serializer_class = CompromisoAgendaSerializer

    def get_queryset(self):
        qs = CompromisoAgenda.objects.all()
        if self.request.user.esta_limitado_a_delegacion:
            qs = qs.filter(delegacion_id=self.request.user.delegacion_id)
        elif self.request.user.es_funcionario:
            from django.db.models import Q
            qs = qs.filter(Q(responsable=self.request.user) | Q(creado_por=self.request.user))
        delegacion_id = self.request.query_params.get('delegacion')
        responsable_id = self.request.query_params.get('responsable')
        estado = self.request.query_params.get('estado')
        if delegacion_id:
            qs = qs.filter(delegacion_id=delegacion_id)
        if responsable_id:
            qs = qs.filter(responsable_id=responsable_id)
        if estado:
            qs = qs.filter(estado=estado)
        return qs

    def perform_create(self, serializer):
        if self.request.user.esta_limitado_a_delegacion:
            delegacion = serializer.validated_data.get('delegacion')
            responsable = serializer.validated_data.get('responsable')
            if (
                not self.request.user.delegacion_id
                or not delegacion
                or delegacion.pk != self.request.user.delegacion_id
                or (responsable and responsable.delegacion_id != self.request.user.delegacion_id)
            ):
                raise DRFPermissionDenied('Solo puedes crear compromisos dentro de tu delegación.')
        with transaction.atomic():
            compromiso = serializer.save(creado_por=self.request.user)
            registrar_evento_auditoria(
                self.request,
                self.request.user,
                'CREAR',
                'CompromisoAgenda',
                compromiso.pk,
                None,
                {
                    'solicitante': compromiso.solicitante,
                    'estado': compromiso.estado,
                    'responsable_id': compromiso.responsable_id,
                },
            )

    def perform_update(self, serializer):
        if self.request.user.esta_limitado_a_delegacion:
            delegacion = serializer.validated_data.get('delegacion', serializer.instance.delegacion)
            responsable = serializer.validated_data.get('responsable', serializer.instance.responsable)
            if (
                delegacion.pk != self.request.user.delegacion_id
                or (responsable and responsable.delegacion_id != self.request.user.delegacion_id)
            ):
                raise DRFPermissionDenied('Solo puedes mantener compromisos dentro de tu delegación.')
        compromiso = serializer.instance
        anterior = {
            'estado': compromiso.estado,
            'fecha_comprometida': str(compromiso.fecha_comprometida),
            'responsable_id': compromiso.responsable_id,
            'delegacion_id': compromiso.delegacion_id,
            'descripcion': compromiso.descripcion,
        }
        with transaction.atomic():
            compromiso = serializer.save()
            registrar_evento_auditoria(
                self.request,
                self.request.user,
                'ACTUALIZAR',
                'CompromisoAgenda',
                compromiso.pk,
                anterior,
                {
                    'estado': compromiso.estado,
                    'fecha_comprometida': str(compromiso.fecha_comprometida),
                    'responsable_id': compromiso.responsable_id,
                    'delegacion_id': compromiso.delegacion_id,
                    'descripcion': compromiso.descripcion,
                },
            )

    @action(detail=True, methods=['post'], url_path='cambiar-estado')
    def cambiar_estado(self, request, pk=None):
        compromiso = self.get_object()
        nuevo_estado = request.data.get('estado')
        observacion = (request.data.get('observacion') or '').strip()
        if nuevo_estado not in {
            CompromisoAgenda.Estado.INGRESADO,
            CompromisoAgenda.Estado.PENDIENTE,
            CompromisoAgenda.Estado.EN_PROCESO,
            CompromisoAgenda.Estado.REPROGRAMADO,
            CompromisoAgenda.Estado.REALIZADO,
        }:
            raise DRFValidationError({'estado': f'Estado inválido: {nuevo_estado}'})
        if not observacion:
            raise DRFValidationError({
                'observacion': 'Explica el cambio de estado en la observación.'
            })

        with transaction.atomic():
            compromiso = self.get_queryset().select_for_update().get(pk=compromiso.pk)
            self.check_object_permissions(request, compromiso)
            estado_anterior = compromiso.estado
            try:
                compromiso.registrar_transicion(
                    nuevo_estado,
                    request.user,
                    observacion,
                )
            except DjangoValidationError as exc:
                raise DRFValidationError(exc.message_dict) from exc
            RegistroAuditoria.objects.create(
                usuario=request.user,
                funcionario=request.user,
                accion='CAMBIO_ESTADO',
                evento='MODIFICACION',
                entidad='CompromisoAgenda',
                identificador=str(compromiso.pk),
                identificador_registro=str(compromiso.pk),
                valor_anterior={'estado': estado_anterior},
                valor_nuevo={
                    'estado': compromiso.estado,
                    'fecha_realizacion': (
                        compromiso.fecha_realizacion.isoformat()
                        if compromiso.fecha_realizacion
                        else None
                    ),
                    'observacion': observacion,
                },
                ip_origen=obtener_ip_cliente(request) or None,
            )

        return Response(CompromisoAgendaSerializer(compromiso).data)

    @action(detail=True, methods=['post'], url_path='anular')
    def anular(self, request, pk=None):
        """Baja lógica del compromiso: por normativa no se elimina, se anula con motivo."""
        motivo = (request.data.get('motivo') or '').strip()
        if not motivo:
            raise DRFValidationError({'motivo': 'Indica el motivo de la anulación.'})

        with transaction.atomic():
            try:
                compromiso = self.get_queryset().select_for_update().get(pk=pk)
            except CompromisoAgenda.DoesNotExist as exc:
                raise NotFound() from exc
            self.check_object_permissions(request, compromiso)
            if not _puede_gestionar_compromiso(request.user, compromiso):
                raise DRFPermissionDenied('No puedes anular este compromiso.')
            try:
                compromiso.anular(request.user, motivo)
            except DjangoValidationError as exc:
                raise DRFValidationError(exc.message_dict) from exc
            RegistroAuditoria.objects.create(
                usuario=request.user,
                funcionario=request.user,
                accion='ANULAR_COMPROMISO',
                evento='MODIFICACION',
                entidad='CompromisoAgenda',
                identificador=str(compromiso.pk),
                identificador_registro=str(compromiso.pk),
                valor_anterior={'anulado': False, 'estado': compromiso.estado},
                valor_nuevo={
                    'anulado': True,
                    'motivo_anulacion': compromiso.motivo_anulacion,
                    'solicitante': compromiso.solicitante,
                },
                ip_origen=obtener_ip_cliente(request) or None,
            )
        return Response(CompromisoAgendaSerializer(compromiso).data)

PARAMETRO_MOTIVO = OpenApiParameter(
    'motivo', str, location=OpenApiParameter.QUERY, required=True,
    description='Motivo de la anulación (obligatorio). También se acepta en el cuerpo JSON.',
)


@extend_schema_view(
    list=extend_schema(
        summary='Listar actividades',
        description=(
            'Ámbito según el perfil: el Funcionario ve solo las propias; el Delegado, las de '
            'su delegación; Coordinador y Administrador, todas. Incluye las anuladas '
            '(`anulada=true`). `contacto_telefono` solo se entrega al Administrador.'
        ),
        parameters=[
            OpenApiParameter('delegacion', int, description='Filtra por id de delegación.'),
            OpenApiParameter('funcionario', int, description='Filtra por id de funcionario.'),
            OpenApiParameter('fecha_desde', OpenApiTypes.DATE, description='Desde (AAAA-MM-DD).'),
            OpenApiParameter('fecha_hasta', OpenApiTypes.DATE, description='Hasta (AAAA-MM-DD).'),
        ],
        responses={200: ActividadSerializer(many=True), **ERRORES_COMUNES},
        tags=['transacción: actividades'],
    ),
    retrieve=extend_schema(
        summary='Ver una actividad',
        description='Incluye la cabecera `ETag` para control de concurrencia.',
        responses={200: ActividadSerializer, **ERRORES_COMUNES},
        tags=['transacción: actividades'],
    ),
    create=extend_schema(
        summary='Registrar actividad',
        description=(
            'Registra la actividad del funcionario autenticado (o, para Coordinador y '
            'Administrador, del funcionario indicado). Involucra los mantenedores: '
            '`funcionario` y `delegacion`. Si se omiten, se usan los del usuario del token.'
        ),
        responses={201: ActividadSerializer, **ERRORES_ESCRITURA},
        examples=[
            OpenApiExample(
                'Actividad en terreno',
                value={'fecha_actividad': '2026-11-18', 'actividad_solicitud': 'Luminaria apagada',
                       'accion_ejecutada': 'Se derivó a Alumbrado Público', 'direccion': 'Av. del Mar 1200',
                       'contacto_nombre': 'Vecina J.P.', 'contacto_telefono': '912345678'},
                request_only=True,
            ),
            OpenApiExample(
                'Error de validación',
                value={'fecha_actividad': ['La fecha de actividad no puede ser futura.'],
                       'contacto_telefono': ['Este campo es requerido.']},
                response_only=True,
                status_codes=['400'],
            ),
        ],
        tags=['transacción: actividades'],
    ),
    update=extend_schema(
        summary='Reemplazar actividad (Coordinador / Administrador)',
        description='Admite `If-Match` con el ETag; responde 412 si otra persona la modificó.',
        responses={200: ActividadSerializer, **ERRORES_ESCRITURA,
                   412: OpenApiResponse(description='El registro cambió desde que lo leíste.')},
        tags=['transacción: actividades'],
    ),
    partial_update=extend_schema(
        summary='Modificar actividad (Coordinador / Administrador)',
        description='Admite `If-Match` con el ETag; responde 412 si otra persona la modificó.',
        responses={200: ActividadSerializer, **ERRORES_ESCRITURA,
                   412: OpenApiResponse(description='El registro cambió desde que lo leíste.')},
        tags=['transacción: actividades'],
    ),
    destroy=extend_schema(
        summary='Anular actividad (Delegado / Coordinador / Administrador)',
        description=(
            'Baja lógica: la actividad queda `anulada=true` con motivo, fecha y responsable, '
            'deja de contar en los indicadores y se conserva para la auditoría. El Delegado '
            'solo anula actividades de su delegación.'
        ),
        parameters=[PARAMETRO_MOTIVO],
        responses={200: RESPUESTA_BAJA_LOGICA, **ERRORES_ESCRITURA},
        examples=[OpenApiExample(
            'Actividad anulada',
            value={'detail': 'Actividad anulada. Se conserva en el historial y deja de contar en los indicadores.',
                   'id': 15, 'advertencias': []},
            response_only=True,
            status_codes=['200'],
        )],
        tags=['transacción: actividades'],
    ),
    anular=extend_schema(tags=['transacción: actividades']),
)
class ActividadViewSet(BajaLogicaMixin, ConcurrenciaAPIMixin, viewsets.ModelViewSet):
    """
    CRUD del registro de actividades diarias de los funcionarios.
    """
    queryset = Actividad.objects.all()
    serializer_class = ActividadSerializer

    def get_queryset(self):
        qs = Actividad.objects.all().select_related('funcionario', 'delegacion', 'item_medicion', 'compromiso_agenda').prefetch_related(
            Prefetch('evidencias', queryset=Evidencia.objects.select_related('verificador', 'subido_por'))
        )
        if self.request.user.es_funcionario:
            qs = qs.filter(funcionario=self.request.user)
        elif self.request.user.esta_limitado_a_delegacion:
            qs = qs.filter(delegacion_id=self.request.user.delegacion_id)
        delegacion_id = self.request.query_params.get('delegacion')
        funcionario_id = self.request.query_params.get('funcionario')
        fecha_desde = self.request.query_params.get('fecha_desde')
        fecha_hasta = self.request.query_params.get('fecha_hasta')

        fecha_desde_parseada = parse_date(fecha_desde) if fecha_desde else None
        fecha_hasta_parseada = parse_date(fecha_hasta) if fecha_hasta else None
        if (
            (fecha_desde and not fecha_desde_parseada)
            or (fecha_hasta and not fecha_hasta_parseada)
            or (
                fecha_desde_parseada
                and fecha_hasta_parseada
                and fecha_desde_parseada > fecha_hasta_parseada
            )
        ):
            return qs.none()
        if delegacion_id:
            qs = qs.filter(delegacion_id=delegacion_id)
        if funcionario_id:
            qs = qs.filter(funcionario_id=funcionario_id)
        if fecha_desde_parseada:
            qs = qs.filter(fecha_actividad__gte=fecha_desde_parseada)
        if fecha_hasta_parseada:
            qs = qs.filter(fecha_actividad__lte=fecha_hasta_parseada)
        return qs

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        # Permite registrar actividad y evidencia en una sola operación optimizada para móvil (<= 3 clics)
        data = request.data.copy()
        if request.user.es_funcionario:
            if data.get('funcionario') not in (None, '', str(request.user.pk), request.user.pk):
                return Response({'error': 'Solo puedes registrar actividades propias.'}, status=status.HTTP_403_FORBIDDEN)
            if data.get('delegacion') not in (None, '', str(request.user.delegacion_id), request.user.delegacion_id):
                return Response({'error': 'Solo puedes registrar actividades en tu delegación.'}, status=status.HTTP_403_FORBIDDEN)
        elif request.user.esta_limitado_a_delegacion and data.get('delegacion') not in (
            None, '', str(request.user.delegacion_id), request.user.delegacion_id
        ):
            return Response({'error': 'Solo puedes registrar actividades en tu delegación.'}, status=status.HTTP_403_FORBIDDEN)
        if request.user.esta_limitado_a_delegacion and data.get('funcionario'):
            try:
                funcionario = Usuario.objects.get(pk=data['funcionario'])
            except (Usuario.DoesNotExist, TypeError, ValueError):
                return Response({'error': 'Funcionario no encontrado.'}, status=status.HTTP_400_BAD_REQUEST)
            if funcionario.delegacion_id != request.user.delegacion_id:
                return Response({'error': 'Solo puedes registrar actividades de tu delegación.'}, status=status.HTTP_403_FORBIDDEN)
        
        # Si el funcionario no viene en data, usar el logueado o fallback
        funcionario_id = data.get('funcionario')
        if not funcionario_id and request.user.is_authenticated:
            data['funcionario'] = request.user.id
            if not data.get('delegacion') and request.user.delegacion:
                data['delegacion'] = request.user.delegacion.id

        fotos_multiples = request.FILES.getlist('fotos')
        archivos_individuales = [
            request.FILES[campo]
            for campo in ('archivo_foto', 'archivo_foto_2', 'archivo_foto_3')
            if campo in request.FILES
        ]
        archivos_subidos = fotos_multiples or archivos_individuales
        try:
            for archivo in archivos_subidos:
                validar_archivo_evidencia(archivo)
        except DjangoValidationError as exc:
            raise DRFValidationError({'fotos': exc.messages}) from exc

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            actividad, evidencia = self._crear_actividad_con_evidencia(
                request, serializer, data, fotos_multiples, archivos_individuales,
            )

        headers = self.get_success_headers(serializer.data)
        # Recargar para incluir evidencia
        return Response(
            ActividadSerializer(actividad, context=self.get_serializer_context()).data,
            status=status.HTTP_201_CREATED,
            headers=headers,
        )

    def _crear_actividad_con_evidencia(self, request, serializer, data, fotos_multiples, archivos_individuales):
        actividad = serializer.save()

        # Cada fotografía es una evidencia con su propio código verificador
        # (hasta tres por actividad). Se aceptan `fotos` (lista) o los campos
        # individuales archivo_foto[_2|_3] / url_foto_simulada[_2|_3].
        if fotos_multiples:
            casillas = [(foto, '') for foto in fotos_multiples]
        else:
            casillas = [
                (request.FILES.get(campo_archivo), data.get(campo_url) or '')
                for campo_archivo, campo_url in (
                    ('archivo_foto', 'url_foto_simulada'),
                    ('archivo_foto_2', 'url_foto_simulada_2'),
                    ('archivo_foto_3', 'url_foto_simulada_3'),
                )
            ]
        evidencias = [
            Evidencia.objects.create(
                actividad=actividad,
                archivo_foto=foto,
                url_foto_simulada=url,
                subido_por=request.user,
                metadatos=metadatos_archivo_evidencia(foto, request.user) if foto else None,
                estado=Evidencia.Estado.PENDIENTE,
            )
            for foto, url in casillas
            if foto or url
        ]
        # Sin fotografía no se crea evidencia: la actividad queda a la espera de su carga.
        evidencia = evidencias[0] if evidencias else None

        registrar_evento_auditoria(
            request,
            request.user,
            'CREAR', 'Actividad', actividad.id,
            None,
            {
                'actividad': actividad.actividad_solicitud,
                'funcionario_id': actividad.funcionario_id,
                'codigo_evidencia': evidencia.codigo_verificador if evidencia else None,
                'codigos_evidencias': [e.codigo_verificador for e in evidencias],
            },
        )
        return actividad, evidencia

    def perform_update(self, serializer):
        actividad = serializer.instance
        anterior = {
            'fecha_actividad': actividad.fecha_actividad.isoformat(),
            'item_medicion_id': actividad.item_medicion_id,
            'tipo_actividad_id': actividad.tipo_actividad_id,
            'catalogo_servicio_id': actividad.catalogo_servicio_id,
            'direccion': actividad.direccion,
            'actividad_solicitud': actividad.actividad_solicitud,
            'accion_ejecutada': actividad.accion_ejecutada,
        }
        with transaction.atomic():
            actividad = serializer.save()
            registrar_evento_auditoria(
                self.request,
                self.request.user,
                'ACTUALIZAR',
                'Actividad',
                actividad.pk,
                anterior,
                {
                    'fecha_actividad': actividad.fecha_actividad.isoformat(),
                    'item_medicion_id': actividad.item_medicion_id,
                    'tipo_actividad_id': actividad.tipo_actividad_id,
                    'catalogo_servicio_id': actividad.catalogo_servicio_id,
                    'direccion': actividad.direccion,
                    'actividad_solicitud': actividad.actividad_solicitud,
                    'accion_ejecutada': actividad.accion_ejecutada,
                },
            )

    @action(detail=True, methods=['post'], url_path='anular')
    def anular(self, request, pk=None):
        actividad = self._anular(request, pk, request.data.get('motivo'))
        return Response(ActividadSerializer(actividad, context=self.get_serializer_context()).data)

    def destroy(self, request, *args, **kwargs):
        """DELETE = anulación (baja lógica). El motivo llega por query string o en el cuerpo."""
        motivo = request.query_params.get('motivo')
        if not motivo and hasattr(request.data, 'get'):
            motivo = request.data.get('motivo')
        with transaction.atomic():
            self._verificar_if_match(request)
            actividad = self._anular(request, kwargs.get('pk'), motivo)
        return Response({
            'detail': 'Actividad anulada. Se conserva en el historial y deja de contar en los indicadores.',
            'id': actividad.pk,
            'advertencias': [],
        })

    def _anular(self, request, pk, motivo):
        if not puede_anular_actividades(request.user):
            raise DRFPermissionDenied(
                'Solo el Delegado, el Coordinador o el Administrador pueden anular actividades.'
            )
        motivo = (motivo or '').strip()
        if not motivo:
            raise DRFValidationError({'motivo': 'Indica el motivo de la anulación.'})

        with transaction.atomic():
            try:
                actividad = self.get_queryset().select_for_update().get(pk=pk)
            except Actividad.DoesNotExist as exc:
                raise NotFound() from exc
            self.check_object_permissions(request, actividad)
            estado_anterior = {
                'anulada': actividad.anulada,
                'motivo_anulacion': actividad.motivo_anulacion,
            }
            try:
                actividad.anular(request.user, motivo)
            except DjangoValidationError as exc:
                raise DRFValidationError(exc.message_dict) from exc
            recalcular_indicadores_actividad(actividad)
            RegistroAuditoria.objects.create(
                usuario=request.user,
                funcionario=request.user,
                accion='ANULAR_ACTIVIDAD',
                evento='MODIFICACION',
                entidad='Actividad',
                identificador=str(actividad.pk),
                identificador_registro=str(actividad.pk),
                valor_anterior=estado_anterior,
                valor_nuevo={
                    'anulada': actividad.anulada,
                    'motivo_anulacion': actividad.motivo_anulacion,
                    'codigo_registro': actividad.codigo_registro,
                },
                ip_origen=obtener_ip_cliente(request) or None,
            )
        return actividad


class EvidenciaViewSet(SinBorradoFisicoMixin, ConcurrenciaAPIMixin, viewsets.ModelViewSet):
    """
    Gestión de Evidencias y módulo de validación ("Check" del Delegado/Verificador).
    """
    queryset = Evidencia.objects.all().select_related('actividad', 'verificador')
    serializer_class = EvidenciaSerializer

    def perform_create(self, serializer):
        actividad = serializer.validated_data['actividad']
        with transaction.atomic():
            actividad = Actividad.objects.select_for_update().get(pk=actividad.pk)
            if actividad.anulada:
                raise DRFValidationError({
                    'actividad': 'No se puede asociar evidencia a una actividad anulada.'
                })
            if Evidencia.objects.filter(
                actividad=actividad,
                estado=Evidencia.Estado.APROBADA,
            ).exists():
                raise DRFValidationError({
                    'actividad': 'La actividad está cerrada porque ya tiene una evidencia aprobada.'
                })
            evidencia = serializer.save()
            registrar_evento_auditoria(
                self.request,
                self.request.user,
                'CREAR_EVIDENCIA',
                'Evidencia',
                evidencia.pk,
                None,
                {
                    'actividad_id': actividad.pk,
                    'codigo_verificador': evidencia.codigo_verificador,
                    'estado': evidencia.estado,
                },
            )

    def perform_update(self, serializer):
        evidencia = serializer.instance
        anterior = {
            'actividad_id': evidencia.actividad_id,
            'codigo_verificador': evidencia.codigo_verificador,
            'estado': evidencia.estado,
            'observacion': evidencia.observacion,
        }
        with transaction.atomic():
            evidencia = serializer.save()
            registrar_evento_auditoria(
                self.request,
                self.request.user,
                'ACTUALIZAR_EVIDENCIA',
                'Evidencia',
                evidencia.pk,
                anterior,
                {
                    'actividad_id': evidencia.actividad_id,
                    'codigo_verificador': evidencia.codigo_verificador,
                    'estado': evidencia.estado,
                    'observacion': evidencia.observacion,
                },
            )

    def get_queryset(self):
        qs = Evidencia.objects.all()
        if self.request.user.es_funcionario:
            qs = qs.filter(actividad__funcionario=self.request.user)
        elif self.request.user.esta_limitado_a_delegacion:
            qs = qs.filter(actividad__delegacion_id=self.request.user.delegacion_id)
        delegacion_id = self.request.query_params.get('delegacion')
        estado = self.request.query_params.get('estado')
        if delegacion_id:
            qs = qs.filter(actividad__delegacion_id=delegacion_id)
        if estado:
            qs = qs.filter(estado=estado)
        return qs

    @action(detail=True, methods=['post'], url_path='validar')
    def validar(self, request, pk=None):
        """
        Botón de validación del Delegado: Aprobar, Rechazar o Corrección.
        """
        if not (
            request.user.is_superuser
            or request.user.es_admin()
            or request.user.es_coordinador
            or request.user.esta_limitado_a_delegacion
        ):
            raise DRFPermissionDenied(
                'Solo coordinadores, delegados y administradores pueden validar evidencias.'
            )

        decision = request.data.get('decision')
        observacion = (request.data.get('observacion') or '').strip()
        if decision not in (
            Evidencia.Estado.APROBADA,
            Evidencia.Estado.RECHAZADA,
            Evidencia.Estado.CORRECCION,
        ):
            return Response(
                {'error': f'Decisión no válida: {decision}'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if decision in (
            Evidencia.Estado.RECHAZADA,
            Evidencia.Estado.CORRECCION,
        ) and not observacion:
            return Response(
                {'error': 'Indica el motivo del rechazo o la corrección solicitada.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        with transaction.atomic():
            try:
                evidencia = self.get_queryset().select_for_update().get(pk=pk)
            except Evidencia.DoesNotExist as exc:
                raise NotFound() from exc
            self.check_object_permissions(request, evidencia)
            if evidencia.es_autovalidacion(request.user):
                raise DRFPermissionDenied(Evidencia.MENSAJE_AUTOVALIDACION)
            if evidencia.estado not in (
                Evidencia.Estado.PENDIENTE,
                Evidencia.Estado.CORRECCION,
            ):
                raise DRFValidationError({
                    'estado': 'Esta evidencia ya fue aprobada o rechazada y no admite otra decisión.'
                })
            if evidencia.actividad.anulada:
                raise DRFValidationError({
                    'actividad': 'No se puede validar evidencia de una actividad anulada.'
                })
            estado_anterior = evidencia.estado
            evidencia.estado = decision
            evidencia.observacion = observacion
            evidencia.observacion_rechazo = (
                observacion
                if decision in (
                    Evidencia.Estado.RECHAZADA,
                    Evidencia.Estado.CORRECCION,
                )
                else None
            )
            evidencia.verificador = request.user
            evidencia.fecha_validacion = timezone.now()
            evidencia.save()
            recalcular_indicadores_actividad(evidencia.actividad)

            RegistroAuditoria.objects.create(
                usuario=request.user,
                funcionario=request.user,
                accion='VALIDAR_EVIDENCIA',
                evento=(
                    'APROBACION'
                    if decision == Evidencia.Estado.APROBADA
                    else 'MODIFICACION'
                ),
                entidad='Evidencia',
                identificador=str(evidencia.pk),
                identificador_registro=str(evidencia.pk),
                valor_anterior={'estado': estado_anterior},
                valor_nuevo={
                    'estado': decision,
                    'observacion': observacion,
                    'codigo': evidencia.codigo_verificador,
                    'verificador_id': request.user.pk,
                    'fecha_validacion': evidencia.fecha_validacion.isoformat(),
                },
                ip_origen=obtener_ip_cliente(request) or None,
            )

        return Response(EvidenciaSerializer(evidencia).data)

class MetricasAPIView(APIView):
    """
    Endpoints analíticos de métricas del semáforo.
    """
    @extend_schema(
        summary='Métricas del semáforo de cumplimiento',
        parameters=[
            OpenApiParameter('tipo', str, enum=['comunal', 'delegacion', 'funcionario'], default='comunal'),
            OpenApiParameter('periodo', int, required=False, description='ID del período (por defecto, el activo)'),
            OpenApiParameter('delegacion_id', int, required=False, description='Con tipo=delegacion'),
        ],
        responses={200: OpenApiTypes.OBJECT},
        tags=['métricas'],
    )
    def get(self, request):
        tipo = request.query_params.get('tipo', 'comunal') # comunal, delegacion, funcionario
        periodo_id = request.query_params.get('periodo')
        
        if periodo_id:
            periodo = PeriodoMedicion.objects.filter(id=periodo_id).first()
        else:
            periodo = PeriodoMedicion.objects.filter(cerrado=False).order_by('-fecha_inicio', '-id').first() or PeriodoMedicion.objects.order_by('-fecha_inicio', '-id').first()

        if not periodo:
            return Response({'error': 'No hay períodos de medición registrados.'}, status=status.HTTP_404_NOT_FOUND)

        if tipo == 'comunal':
            if not (request.user.is_superuser or request.user.es_admin() or request.user.es_coordinador):
                return Response(
                    {'error': 'El resumen comunal está reservado a administración y coordinación. '
                              'Consulta tipo=delegacion o tipo=funcionario.'},
                    status=status.HTTP_403_FORBIDDEN,
                )
            data = calcular_resumen_comunal(periodo)
            return Response(data)

        elif tipo == 'delegacion':
            delegacion_id = request.query_params.get('delegacion_id')
            if not delegacion_id:
                return Response({'error': 'delegacion_id requerido'}, status=status.HTTP_400_BAD_REQUEST)
            try:
                delegacion = Delegacion.objects.get(id=delegacion_id)
            except Delegacion.DoesNotExist:
                return Response({'error': 'Delegación no encontrada'}, status=status.HTTP_404_NOT_FOUND)
            if request.user.esta_limitado_a_delegacion and delegacion.pk != request.user.delegacion_id:
                return Response({'error': 'Acceso restringido a tu delegación.'}, status=status.HTTP_403_FORBIDDEN)
            if request.user.es_funcionario:
                return Response({'error': 'No tienes permiso para consultar métricas de delegación.'}, status=status.HTTP_403_FORBIDDEN)
            data = calcular_resumen_delegacion(delegacion, periodo)
            return Response(data)

        elif tipo == 'funcionario':
            funcionario_id = request.query_params.get('funcionario_id')
            if not funcionario_id:
                return Response({'error': 'funcionario_id requerido'}, status=status.HTTP_400_BAD_REQUEST)
            try:
                funcionario = Usuario.objects.get(id=funcionario_id)
            except Usuario.DoesNotExist:
                return Response({'error': 'Funcionario no encontrado'}, status=status.HTTP_404_NOT_FOUND)
            if request.user.es_funcionario and funcionario.pk != request.user.pk:
                return Response({'error': 'Solo puedes consultar tus propias métricas.'}, status=status.HTTP_403_FORBIDDEN)
            if request.user.esta_limitado_a_delegacion and funcionario.delegacion_id != request.user.delegacion_id:
                return Response({'error': 'Acceso restringido a funcionarios de tu delegación.'}, status=status.HTTP_403_FORBIDDEN)
            data = calcular_metricas_funcionario(funcionario, periodo)
            return Response(data)

        return Response({'error': 'Tipo no reconocido'}, status=status.HTTP_400_BAD_REQUEST)


class CasoSocialViewSet(SinBorradoFisicoMixin, ConcurrenciaAPIMixin, viewsets.ModelViewSet):
    queryset = CasoSocial.objects.all().prefetch_related('atenciones')
    serializer_class = CasoSocialSerializer

    def get_queryset(self):
        qs = CasoSocial.objects.all().prefetch_related('atenciones')
        if self.request.user.es_funcionario:
            return qs.none()
        if self.request.user.esta_limitado_a_delegacion:
            return qs.filter(delegacion_id=self.request.user.delegacion_id)
        return qs


class AtencionSocialViewSet(SinBorradoFisicoMixin, ConcurrenciaAPIMixin, viewsets.ModelViewSet):
    queryset = AtencionSocial.objects.all()
    serializer_class = AtencionSocialSerializer

    def get_queryset(self):
        qs = AtencionSocial.objects.all()
        if self.request.user.es_funcionario:
            return qs.none()
        if self.request.user.esta_limitado_a_delegacion:
            return qs.filter(caso__delegacion_id=self.request.user.delegacion_id)
        return qs

    def perform_create(self, serializer):
        caso = serializer.validated_data['caso']
        with transaction.atomic():
            try:
                caso = CasoSocial.objects.select_for_update().get(pk=caso.pk)
            except CasoSocial.DoesNotExist as exc:
                raise NotFound() from exc
            if caso.cerrado:
                raise DRFValidationError({
                    'caso': 'No se pueden registrar gestiones en un caso cerrado.'
                })
            siguiente_etapa = (
                caso.atenciones.order_by('-etapa')
                .values_list('etapa', flat=True)
                .first()
                or 0
            ) + 1
            if siguiente_etapa > 3:
                raise DRFValidationError({
                    'caso': 'El caso ya tiene el máximo de tres gestiones.'
                })
            if serializer.validated_data['etapa'] != siguiente_etapa:
                raise DRFValidationError({
                    'etapa': f'La siguiente gestión disponible es la etapa {siguiente_etapa}.'
                })
            try:
                atencion = serializer.save(
                    caso=caso,
                    funcionario=self.request.user,
                )
            except ValueError as exc:
                raise DRFValidationError({'caso': str(exc)}) from exc
            RegistroAuditoria.objects.create(
                usuario=self.request.user,
                funcionario=self.request.user,
                accion='REGISTRAR_ATENCION_SOCIAL',
                evento='CREACION',
                entidad='AtencionSocial',
                identificador=str(atencion.pk),
                identificador_registro=str(atencion.pk),
                valor_nuevo={
                    'caso_id': caso.pk,
                    'etapa': atencion.etapa,
                    'tipo_atencion': atencion.tipo_atencion,
                },
                ip_origen=obtener_ip_cliente(self.request) or None,
            )


class RegistroAuditoriaViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = RegistroAuditoria.objects.all()
    serializer_class = RegistroAuditoriaSerializer
    permission_classes = [AuditAccessPermission]


# =============================================================================
# API de consulta (solo lectura): catálogos y datos importados de los Excel
# =============================================================================
class PaginacionConsulta(PageNumberPagination):
    """50 por página; `?page_size=` hasta 500."""
    page_size = 50
    page_size_query_param = 'page_size'
    max_page_size = 500


def _limitado_a_delegacion(user):
    """Delegado, Funcionario y Consulta con delegación solo ven la suya (igual que en la web)."""
    return user.es_funcionario or user.esta_limitado_a_delegacion


def _por_delegacion(queryset, user):
    if not _limitado_a_delegacion(user):
        return queryset
    if not user.delegacion_id:
        return queryset.none()
    return queryset.filter(delegacion_id=user.delegacion_id)


def _buscar(queryset, texto, campos):
    texto = (texto or '').strip()
    if not texto:
        return queryset
    condicion = Q()
    for campo in campos:
        condicion |= Q(**{f'{campo}__icontains': texto})
    return queryset.filter(condicion)


class AreaViewSet(viewsets.ReadOnlyModelViewSet):
    """Áreas funcionales. Datos de referencia: cualquier usuario autenticado."""
    queryset = Area.objects.order_by('nombre')
    serializer_class = AreaSerializer


class TipoAtencionSocialViewSet(viewsets.ReadOnlyModelViewSet):
    """Tipos de atención social. Filtro: `?area=<id>`."""
    queryset = TipoAtencionSocial.objects.select_related('area').order_by('nombre')
    serializer_class = TipoAtencionSocialSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        area = self.request.query_params.get('area', '')
        return qs.filter(area_id=area) if area.isdecimal() else qs


class SubatencionSocialViewSet(viewsets.ReadOnlyModelViewSet):
    """Subatenciones sociales. Filtro: `?tipo_atencion=<id>`."""
    queryset = SubatencionSocial.objects.select_related('tipo_atencion').order_by('tipo_atencion__nombre', 'nombre')
    serializer_class = SubatencionSocialSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        tipo = self.request.query_params.get('tipo_atencion', '')
        return qs.filter(tipo_atencion_id=tipo) if tipo.isdecimal() else qs


class SolicitanteViewSet(viewsets.ReadOnlyModelViewSet):
    """Solicitantes activos. Filtros: `?q=` y `?tipo=`. No disponible para el Usuario de consulta."""
    queryset = Solicitante.objects.filter(estado=True).order_by('nombre', 'apellido', 'pk')
    serializer_class = SolicitanteSerializer
    pagination_class = PaginacionConsulta

    def get_queryset(self):
        if self.request.user.es_consulta:
            raise DRFPermissionDenied('El usuario de consulta no tiene acceso a los solicitantes.')
        qs = _buscar(super().get_queryset(), self.request.query_params.get('q'), ['nombre', 'apellido', 'direccion'])
        tipo = self.request.query_params.get('tipo')
        return qs.filter(tipo_solicitante=tipo) if tipo else qs


class OrganizacionComunitariaViewSet(viewsets.ReadOnlyModelViewSet):
    """Organizaciones del Excel JJVV. Filtros: `?q=`, `?territorio=`, `?delegacion=<id>`."""
    queryset = OrganizacionComunitaria.objects.select_related('delegacion').order_by('nombre', 'pk')
    serializer_class = OrganizacionComunitariaSerializer
    pagination_class = PaginacionConsulta

    def get_queryset(self):
        qs = _por_delegacion(super().get_queryset(), self.request.user)
        params = self.request.query_params
        qs = _buscar(qs, params.get('q'), ['nombre', 'domicilio_legal'])
        if params.get('territorio'):
            qs = qs.filter(territorio=params['territorio'])
        if params.get('delegacion', '').isdecimal():
            qs = qs.filter(delegacion_id=params['delegacion'])
        return qs


class RegistroTuboTrabajoViewSet(viewsets.ReadOnlyModelViewSet):
    """Tubo de trabajo del Excel. Filtros: `?q=`, `?hoja=`, `?estatus=`, `?responsable=`, `?territorio=`."""
    queryset = RegistroTuboTrabajo.objects.select_related('delegacion').order_by('hoja', 'fila_origen')
    serializer_class = RegistroTuboTrabajoSerializer
    pagination_class = PaginacionConsulta

    def get_queryset(self):
        qs = _por_delegacion(super().get_queryset(), self.request.user)
        params = self.request.query_params
        qs = _buscar(qs, params.get('q'), ['actividad', 'solicitante', 'avance_observaciones', 'area_apoyo'])
        for campo in ('hoja', 'estatus', 'responsable', 'territorio'):
            if params.get(campo):
                qs = qs.filter(**{campo: params[campo]})
        return qs


class CartaSeguimientoViewSet(viewsets.ReadOnlyModelViewSet):
    """Cartas del Excel. Sin delegación asociada: solo perfiles sin límite territorial.
    Filtros: `?q=`, `?hoja=`, `?estado=`."""
    queryset = CartaSeguimiento.objects.order_by('hoja', 'fila_origen')
    serializer_class = CartaSeguimientoSerializer
    pagination_class = PaginacionConsulta

    def get_queryset(self):
        qs = super().get_queryset()
        if _limitado_a_delegacion(self.request.user):
            return qs.none()
        params = self.request.query_params
        qs = _buscar(qs, params.get('q'), ['remite', 'para', 'actividad_tema', 'observacion'])
        for campo in ('hoja', 'estado'):
            if params.get(campo):
                qs = qs.filter(**{campo: params[campo]})
        return qs


class RolViewSet(viewsets.ReadOnlyModelViewSet):
    """Roles adicionales y sus permisos. Solo Administrador y Coordinador."""
    queryset = Rol.objects.order_by('nombre_rol')
    serializer_class = RolSerializer

    def get_queryset(self):
        user = self.request.user
        if not (user.es_admin() or user.es_coordinador):
            raise DRFPermissionDenied('Solo Administrador y Coordinador consultan los roles.')
        return super().get_queryset()


class TipoActividadViewSet(viewsets.ReadOnlyModelViewSet):
    """Tipos de actividad por área. Datos de referencia. Filtro: `?area=<id>`."""
    queryset = TipoActividad.objects.select_related('area').order_by('nombre')
    serializer_class = TipoActividadSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        area = self.request.query_params.get('area', '')
        return qs.filter(area_id=area) if area.isdecimal() else qs


class ConceptoAjusteViewSet(viewsets.ReadOnlyModelViewSet):
    """Conceptos de ajuste de incentivo (positivo / negativo). Datos de referencia."""
    queryset = ConceptoAjuste.objects.order_by('nombre')
    serializer_class = ConceptoAjusteSerializer


class AjusteIncentivoViewSet(viewsets.ReadOnlyModelViewSet):
    """Ajustes de incentivo. Administrador y Coordinador ven todos; el Funcionario solo los
    suyos; Delegado y Consulta no tienen acceso (igual que la pantalla Incentivos).
    Filtros: `?periodo=<id>`, `?funcionario=<id>`, `?estado=`."""
    queryset = AjusteIncentivo.objects.select_related('concepto', 'funcionario', 'periodo').order_by('-fecha_registro', '-pk')
    serializer_class = AjusteIncentivoSerializer
    pagination_class = PaginacionConsulta

    def get_queryset(self):
        user = self.request.user
        qs = super().get_queryset()
        if user.es_admin() or user.es_coordinador:
            pass
        elif user.es_funcionario:
            qs = qs.filter(funcionario=user)
        else:
            raise DRFPermissionDenied('No tiene acceso a los ajustes de incentivo.')
        params = self.request.query_params
        if params.get('periodo', '').isdecimal():
            qs = qs.filter(periodo_id=params['periodo'])
        if params.get('funcionario', '').isdecimal():
            qs = qs.filter(funcionario_id=params['funcionario'])
        if params.get('estado'):
            qs = qs.filter(estado=params['estado'])
        return qs
