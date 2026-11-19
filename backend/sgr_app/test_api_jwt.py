"""API REST con JWT (Evaluación Sumativa 4).

Cubre: emisión, renovación y revocación de tokens; endpoints protegidos;
reglas de seguridad al emitir tokens (bloqueo, 2FA, clave inicial); CRUD de
los mantenedores Funcionarios y Delegaciones; la transacción Actividades;
protección de datos sensibles por perfil y respuestas JSON con códigos HTTP.
"""

import base64
import hashlib
import hmac
import time
from datetime import timedelta
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from sgr_app.models import Actividad, Delegacion, RegistroAuditoria, Usuario

PASSWORD = 'TestPassword123!'
TOKEN_URL = '/api/v1/auth/token/'
REFRESH_URL = '/api/v1/auth/token/refresh/'
LOGOUT_URL = '/api/v1/auth/token/logout/'


def codigo_totp(secreto):
    clave = base64.b32decode(secreto + '=' * (-len(secreto) % 8))
    digest = hmac.new(clave, (int(time.time()) // 30).to_bytes(8, 'big'), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return f'{(int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF) % 1_000_000:06d}'


class BaseJWT(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.del_a = Delegacion.objects.create(nombre='Delegación A', codigo='DLA')
        cls.del_b = Delegacion.objects.create(nombre='Delegación B', codigo='DLB')
        cls.admin = Usuario.objects.create_user(
            username='admin@laserena.cl', email='admin@laserena.cl', password=PASSWORD,
            rol=Usuario.Rol.ADMINISTRADOR,
        )
        cls.coordinador = Usuario.objects.create_user(
            username='coord@laserena.cl', password=PASSWORD, rol=Usuario.Rol.COORDINADOR,
        )
        cls.delegado = Usuario.objects.create_user(
            username='delegado@laserena.cl', password=PASSWORD, rol=Usuario.Rol.DELEGADO,
            delegacion=cls.del_a,
        )
        cls.funcionario = Usuario.objects.create_user(
            username='func@laserena.cl', email='func@laserena.cl', password=PASSWORD,
            rol=Usuario.Rol.FUNCIONARIO, delegacion=cls.del_a,
            telefono='912345678', rut_anonimizado='11.111.111-1',
        )
        cls.consulta = Usuario.objects.create_user(
            username='consulta@laserena.cl', password=PASSWORD, rol=Usuario.Rol.CONSULTA,
        )
        hoy = timezone.localdate()
        cls.act_a = Actividad.objects.create(
            funcionario=cls.funcionario, delegacion=cls.del_a, fecha_actividad=hoy,
            contacto_nombre='Vecina', contacto_telefono='+56987654321',
        )
        otro = Usuario.objects.create_user(
            username='otro@laserena.cl', password=PASSWORD, rol=Usuario.Rol.FUNCIONARIO,
            delegacion=cls.del_b,
        )
        cls.act_b = Actividad.objects.create(funcionario=otro, delegacion=cls.del_b, fecha_actividad=hoy)

    def setUp(self):
        cache.clear()  # reinicia el límite de peticiones (throttling) entre pruebas

    def tokens(self, usuario, **extra):
        respuesta = APIClient().post(
            TOKEN_URL, {'username': usuario.username, 'password': PASSWORD, **extra}, format='json',
        )
        self.assertEqual(respuesta.status_code, 200, respuesta.content)
        return respuesta.json()

    def cliente(self, usuario):
        cliente = APIClient()
        cliente.credentials(HTTP_AUTHORIZATION=f'Bearer {self.tokens(usuario)["access"]}')
        return cliente


class TokensJWTTests(BaseJWT):
    def test_obtener_par_de_tokens(self):
        datos = self.tokens(self.admin)
        self.assertEqual(datos['token_type'], 'Bearer')
        self.assertEqual(datos['access_expira_en_segundos'], 15 * 60)
        self.assertEqual(datos['usuario'], {'id': self.admin.pk, 'username': self.admin.username, 'rol': 'ADMINISTRADOR'})
        self.assertTrue(datos['access'] and datos['refresh'])
        self.assertTrue(RegistroAuditoria.objects.filter(
            accion='EMITIR_TOKEN_JWT', usuario=self.admin,
        ).exists())

    def test_el_token_no_lleva_datos_personales(self):
        import json

        access = self.tokens(self.funcionario)['access']
        payload = json.loads(base64.urlsafe_b64decode(access.split('.')[1] + '=='))
        self.assertEqual(payload['rol'], 'FUNCIONARIO')
        self.assertFalse({'email', 'telefono', 'rut_anonimizado', 'password'} & set(payload))

    def test_endpoint_protegido_sin_token_responde_401(self):
        respuesta = APIClient().get('/api/v1/usuarios/')
        self.assertEqual(respuesta.status_code, 401)
        self.assertIn('Bearer', respuesta['WWW-Authenticate'])
        self.assertIn('detail', respuesta.json())

    def test_token_invalido_responde_401(self):
        cliente = APIClient()
        cliente.credentials(HTTP_AUTHORIZATION='Bearer token.falso.123')
        self.assertEqual(cliente.get('/api/v1/usuarios/').status_code, 401)

    def test_access_token_da_acceso(self):
        self.assertEqual(self.cliente(self.admin).get('/api/v1/usuarios/').status_code, 200)

    def test_refresh_rota_y_el_anterior_queda_revocado(self):
        refresh = self.tokens(self.admin)['refresh']
        renovado = APIClient().post(REFRESH_URL, {'refresh': refresh}, format='json')
        self.assertEqual(renovado.status_code, 200)
        self.assertIn('access', renovado.json())
        self.assertNotEqual(renovado.json()['refresh'], refresh)
        # El refresh usado ya no sirve (lista negra).
        self.assertEqual(APIClient().post(REFRESH_URL, {'refresh': refresh}, format='json').status_code, 401)

    def test_cerrar_sesion_revoca_el_refresh(self):
        refresh = self.tokens(self.admin)['refresh']
        self.assertEqual(APIClient().post(LOGOUT_URL, {'refresh': refresh}, format='json').status_code, 200)
        self.assertEqual(APIClient().post(REFRESH_URL, {'refresh': refresh}, format='json').status_code, 401)

    def test_access_vencido_responde_401(self):
        access = self.tokens(self.admin)['access']
        cliente = APIClient()
        cliente.credentials(HTTP_AUTHORIZATION=f'Bearer {access}')
        with patch('rest_framework_simplejwt.tokens.aware_utcnow',
                   return_value=timezone.now() + timedelta(minutes=16)):
            self.assertEqual(cliente.get('/api/v1/usuarios/').status_code, 401)

    def test_credenciales_invalidas(self):
        respuesta = APIClient().post(TOKEN_URL, {'username': self.admin.username, 'password': 'mala'}, format='json')
        self.assertEqual(respuesta.status_code, 401)
        self.assertEqual(respuesta.json()['detail'], 'Credenciales inválidas o usuario inactivo.')

    def test_faltan_campos_responde_400(self):
        self.assertEqual(APIClient().post(TOKEN_URL, {}, format='json').status_code, 400)

    @override_settings(LOGIN_MAX_FAILED_ATTEMPTS=3)
    def test_bloqueo_tras_intentos_fallidos(self):
        cliente = APIClient()
        for _ in range(3):
            cliente.post(TOKEN_URL, {'username': self.admin.username, 'password': 'mala'}, format='json')
        respuesta = cliente.post(TOKEN_URL, {'username': self.admin.username, 'password': PASSWORD}, format='json')
        self.assertEqual(respuesta.status_code, 429)

    def test_usuario_desactivado_pierde_acceso_con_su_token(self):
        usuario = Usuario.objects.create_user(
            username='temporal@laserena.cl', password=PASSWORD, rol=Usuario.Rol.FUNCIONARIO,
        )
        tokens = self.tokens(usuario)
        cliente = APIClient()
        cliente.credentials(HTTP_AUTHORIZATION=f'Bearer {tokens["access"]}')
        self.assertEqual(cliente.get('/api/v1/usuarios/').status_code, 200)
        usuario.desactivar_usuario()
        self.assertEqual(cliente.get('/api/v1/usuarios/').status_code, 401)
        self.assertEqual(APIClient().post(REFRESH_URL, {'refresh': tokens['refresh']}, format='json').status_code, 401)

    def test_clave_inicial_pendiente_no_recibe_token(self):
        usuario = Usuario.objects.create_user(
            username='nuevo@laserena.cl', password=PASSWORD, rol=Usuario.Rol.FUNCIONARIO,
            must_change_password=True,
        )
        respuesta = APIClient().post(TOKEN_URL, {'username': usuario.username, 'password': PASSWORD}, format='json')
        self.assertEqual(respuesta.status_code, 403)

    def test_2fa_activa_exige_codigo(self):
        secreto = 'JBSWY3DPEHPK3PXP'
        Usuario.objects.filter(pk=self.coordinador.pk).update(requires_2fa=True, totp_secret=secreto)
        sin_codigo = APIClient().post(
            TOKEN_URL, {'username': self.coordinador.username, 'password': PASSWORD}, format='json',
        )
        self.assertEqual(sin_codigo.status_code, 401)
        self.assertEqual(sin_codigo.json()['code'], 'requiere_2fa')
        incorrecto = APIClient().post(
            TOKEN_URL, {'username': self.coordinador.username, 'password': PASSWORD, 'codigo_2fa': '000000'},
            format='json',
        )
        self.assertEqual(incorrecto.status_code, 401)
        self.tokens(self.coordinador, codigo_2fa=codigo_totp(secreto))

    @override_settings(TWO_FACTOR_REQUIRED_ROLES=['ADMINISTRADOR'])
    def test_rol_con_2fa_obligatoria_sin_configurar_no_recibe_token(self):
        respuesta = APIClient().post(
            TOKEN_URL, {'username': self.admin.username, 'password': PASSWORD}, format='json',
        )
        self.assertEqual(respuesta.status_code, 403)

    def test_limite_de_peticiones_al_emitir_tokens(self):
        from rest_framework.throttling import ScopedRateThrottle

        with patch.object(ScopedRateThrottle, 'THROTTLE_RATES', {'auth_jwt': '2/min'}):
            cliente = APIClient()
            codigos = [
                cliente.post(TOKEN_URL, {'username': 'x', 'password': 'y'}, format='json').status_code
                for _ in range(3)
            ]
        self.assertEqual(codigos, [401, 401, 429])


class MantenedorFuncionariosTests(BaseJWT):
    URL = '/api/v1/usuarios/'

    def test_crud_completo_del_administrador(self):
        admin = self.cliente(self.admin)
        creado = admin.post(self.URL, {
            'email': 'Nueva.Persona@LaSerena.cl', 'rut_anonimizado': '22.222.222-2',
            'first_name': 'Nueva', 'last_name': 'Persona Prueba', 'rol': 'FUNCIONARIO',
            'delegacion': self.del_a.pk, 'telefono': '987654321',
        }, format='json')
        self.assertEqual(creado.status_code, 201, creado.content)
        datos = creado.json()
        self.assertEqual(datos['username'], 'nueva.persona@laserena.cl')
        self.assertNotIn('password', datos)
        nuevo = Usuario.objects.get(pk=datos['id'])
        self.assertTrue(nuevo.must_change_password)
        self.assertTrue(nuevo.check_password('222222222'))  # RUN sin puntos ni guion

        detalle = f'{self.URL}{nuevo.pk}/'
        self.assertEqual(admin.get(detalle).json()['first_name'], 'Nueva')
        completo = {**datos, 'first_name': 'Renombrada', 'cargo': None, 'area_entidad': None}
        self.assertEqual(admin.put(detalle, completo, format='json').status_code, 200)
        self.assertEqual(admin.patch(detalle, {'last_name': 'Otra'}, format='json').json()['last_name'], 'Otra')

        baja = admin.delete(detalle)
        self.assertEqual(baja.status_code, 200)
        self.assertIn('detail', baja.json())
        nuevo.refresh_from_db()
        self.assertFalse(nuevo.is_active)  # baja lógica: la fila se conserva
        self.assertTrue(RegistroAuditoria.objects.filter(
            accion='BAJA_LOGICA', entidad='Usuario', identificador_registro=str(nuevo.pk),
        ).exists())
        # Reactivar
        self.assertTrue(admin.patch(detalle, {'is_active': True}, format='json').json()['is_active'])

    def test_validaciones_responden_400_con_detalle(self):
        admin = self.cliente(self.admin)
        respuesta = admin.post(self.URL, {
            'email': 'func@laserena.cl', 'rut_anonimizado': '11.111.111-2',
            'first_name': 'X', 'last_name': 'Y', 'telefono': '123',
        }, format='json')
        self.assertEqual(respuesta.status_code, 400)
        self.assertEqual(set(respuesta.json()), {'email', 'rut_anonimizado', 'telefono'})
        faltan = admin.post(self.URL, {'rol': 'FUNCIONARIO'}, format='json')
        self.assertEqual(faltan.status_code, 400)
        self.assertTrue({'email', 'rut_anonimizado', 'first_name', 'last_name'} <= set(faltan.json()))

    def test_no_puede_darse_de_baja_a_si_mismo(self):
        respuesta = self.cliente(self.admin).delete(f'{self.URL}{self.admin.pk}/')
        self.assertEqual(respuesta.status_code, 400)
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.is_active)

    def test_otros_perfiles_no_escriben(self):
        for usuario in (self.coordinador, self.delegado, self.funcionario, self.consulta):
            cliente = self.cliente(usuario)
            with self.subTest(perfil=usuario.rol):
                self.assertEqual(cliente.post(self.URL, {}, format='json').status_code, 403)
                self.assertEqual(cliente.patch(f'{self.URL}{self.funcionario.pk}/', {}, format='json').status_code, 403)
                self.assertEqual(cliente.delete(f'{self.URL}{self.funcionario.pk}/').status_code, 403)

    def test_inexistente_responde_404(self):
        respuesta = self.cliente(self.admin).get(f'{self.URL}999999/')
        self.assertEqual(respuesta.status_code, 404)
        self.assertIn('detail', respuesta.json())


class MantenedorDelegacionesTests(BaseJWT):
    URL = '/api/v1/delegaciones/'

    def test_crud_completo_del_administrador(self):
        admin = self.cliente(self.admin)
        creada = admin.post(self.URL, {'nombre': 'Delegación Nueva', 'codigo': 'nue', 'telefono': '512206000'},
                            format='json')
        self.assertEqual(creada.status_code, 201, creada.content)
        self.assertEqual(creada.json()['codigo'], 'NUE')
        detalle = f'{self.URL}{creada.json()["id"]}/'
        self.assertEqual(admin.put(detalle, {'nombre': 'Delegación Renombrada', 'codigo': 'NUE'},
                                   format='json').status_code, 200)
        self.assertEqual(admin.patch(detalle, {'ambito': 'Rural'}, format='json').json()['ambito'], 'Rural')
        baja = admin.delete(detalle)
        self.assertEqual(baja.status_code, 200)
        self.assertFalse(Delegacion.objects.get(pk=creada.json()['id']).activo)
        self.assertEqual(admin.delete(detalle).json()['detail'], 'La delegación ya estaba dada de baja.')

    def test_baja_advierte_funcionarios_activos(self):
        respuesta = self.cliente(self.admin).delete(f'{self.URL}{self.del_a.pk}/')
        self.assertEqual(respuesta.status_code, 200)
        self.assertTrue(any('funcionario' in aviso for aviso in respuesta.json()['advertencias']))

    def test_codigo_duplicado_responde_400(self):
        respuesta = self.cliente(self.admin).post(self.URL, {'nombre': 'Otra', 'codigo': 'DLA'}, format='json')
        self.assertEqual(respuesta.status_code, 400)
        self.assertIn('codigo', respuesta.json())

    def test_lectura_para_todos_escritura_solo_administrador(self):
        for usuario in (self.coordinador, self.delegado, self.funcionario, self.consulta):
            cliente = self.cliente(usuario)
            with self.subTest(perfil=usuario.rol):
                self.assertEqual(cliente.get(self.URL).status_code, 200)
                self.assertEqual(cliente.post(self.URL, {'nombre': 'X', 'codigo': 'X'}, format='json').status_code, 403)
                self.assertEqual(cliente.delete(f'{self.URL}{self.del_b.pk}/').status_code, 403)


class TransaccionActividadesTests(BaseJWT):
    URL = '/api/v1/actividades/'

    def payload(self, **extra):
        return {
            'fecha_actividad': timezone.localdate().isoformat(),
            'actividad_solicitud': 'Luminaria apagada', 'accion_ejecutada': 'Derivación a Alumbrado',
            'direccion': 'Av. del Mar 1200', 'contacto_nombre': 'Vecina', 'contacto_telefono': '912345678',
            **extra,
        }

    def test_funcionario_registra_y_consulta_sus_actividades(self):
        cliente = self.cliente(self.funcionario)
        creada = cliente.post(self.URL, self.payload(), format='json')
        self.assertEqual(creada.status_code, 201, creada.content)
        self.assertEqual(creada.json()['funcionario'], self.funcionario.pk)
        self.assertEqual(creada.json()['delegacion'], self.del_a.pk)
        ids = {fila['id'] for fila in cliente.get(self.URL).json()}
        self.assertIn(creada.json()['id'], ids)
        self.assertNotIn(self.act_b.pk, ids)

    def test_coordinador_modifica(self):
        cliente = self.cliente(self.coordinador)
        detalle = f'{self.URL}{self.act_a.pk}/'
        respuesta = cliente.patch(detalle, {'direccion': 'Nueva dirección 123'}, format='json')
        self.assertEqual(respuesta.status_code, 200, respuesta.content)
        self.assertEqual(respuesta.json()['direccion'], 'Nueva dirección 123')
        self.assertEqual(self.cliente(self.funcionario).patch(detalle, {}, format='json').status_code, 403)

    def test_delete_anula_con_motivo_y_conserva_el_registro(self):
        cliente = self.cliente(self.delegado)
        detalle = f'{self.URL}{self.act_a.pk}/'
        sin_motivo = cliente.delete(detalle)
        self.assertEqual(sin_motivo.status_code, 400)
        self.assertIn('motivo', sin_motivo.json())

        anulada = cliente.delete(f'{detalle}?motivo=Registro duplicado')
        self.assertEqual(anulada.status_code, 200, anulada.content)
        actividad = Actividad.objects.get(pk=self.act_a.pk)
        self.assertTrue(actividad.anulada)
        self.assertEqual(actividad.motivo_anulacion, 'Registro duplicado')
        self.assertEqual(actividad.anulada_por, self.delegado)
        self.assertTrue(cliente.get(detalle).json()['anulada'])

    def test_delete_fuera_de_ambito_y_sin_permiso(self):
        self.assertEqual(self.cliente(self.delegado).delete(f'{self.URL}{self.act_b.pk}/?motivo=x').status_code, 404)
        self.assertEqual(self.cliente(self.funcionario).delete(f'{self.URL}{self.act_a.pk}/?motivo=x').status_code, 403)
        self.assertEqual(self.cliente(self.consulta).delete(f'{self.URL}{self.act_a.pk}/?motivo=x').status_code, 403)

    def test_usuario_de_consulta_no_escribe_con_jwt(self):
        self.assertEqual(self.cliente(self.consulta).post(self.URL, self.payload(), format='json').status_code, 403)

    def test_error_interno_responde_json_sin_detalles(self):
        with patch('sgr_app.views.registrar_evento_auditoria', side_effect=RuntimeError('secreto interno')):
            respuesta = self.cliente(self.funcionario).post(self.URL, self.payload(), format='json')
        self.assertEqual(respuesta.status_code, 500)
        self.assertEqual(respuesta['Content-Type'].split(';')[0], 'application/json')
        self.assertNotIn('secreto interno', respuesta.content.decode())
        self.assertFalse(Actividad.objects.filter(actividad_solicitud='Luminaria apagada').exists())


class DatosSensiblesTests(BaseJWT):
    def test_administrador_ve_datos_personales(self):
        datos = self.cliente(self.admin).get(f'/api/v1/usuarios/{self.funcionario.pk}/').json()
        self.assertEqual(datos['email'], 'func@laserena.cl')
        self.assertEqual(datos['telefono'], '+56912345678')
        self.assertEqual(datos['rut_anonimizado'], '11.111.111-1')
        actividad = self.cliente(self.admin).get(f'/api/v1/actividades/{self.act_a.pk}/').json()
        self.assertEqual(actividad['contacto_telefono'], '+56987654321')

    def test_otros_perfiles_no_ven_datos_personales(self):
        sensibles = {'email', 'telefono', 'rut_anonimizado', 'requires_2fa', 'password', 'totp_secret'}
        for usuario in (self.coordinador, self.delegado, self.funcionario, self.consulta):
            cliente = self.cliente(usuario)
            with self.subTest(perfil=usuario.rol):
                for fila in cliente.get('/api/v1/usuarios/').json():
                    self.assertFalse(sensibles & set(fila), fila)
                    self.assertIn('first_name', fila)  # los campos operativos siguen
                for fila in cliente.get('/api/v1/actividades/').json():
                    self.assertNotIn('contacto_telefono', fila)
                    self.assertIn('direccion', fila)

    def test_respuesta_de_registro_tampoco_expone_el_telefono(self):
        respuesta = self.cliente(self.funcionario).post('/api/v1/actividades/', {
            'fecha_actividad': timezone.localdate().isoformat(), 'actividad_solicitud': 'Poda',
            'accion_ejecutada': 'Derivado', 'direccion': 'Calle 1', 'contacto_nombre': 'Vecino',
            'contacto_telefono': '912345678',
        }, format='json')
        self.assertEqual(respuesta.status_code, 201)
        self.assertNotIn('contacto_telefono', respuesta.json())
        self.assertEqual(Actividad.objects.get(pk=respuesta.json()['id']).contacto_telefono, '+56912345678')


class RespuestasJSONTests(BaseJWT):
    def test_ruta_api_inexistente_responde_404_json(self):
        respuesta = self.client.get('/api/v1/no-existe/')
        self.assertEqual(respuesta.status_code, 404)
        self.assertEqual(respuesta.json()['code'], 'no_encontrado')

    def test_metodo_no_permitido_responde_405_json(self):
        respuesta = self.cliente(self.admin).delete('/api/v1/cargos/1/')
        self.assertEqual(respuesta.status_code, 405)
        self.assertIn('detail', respuesta.json())
