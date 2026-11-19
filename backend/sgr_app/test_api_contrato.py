"""Contrato de la API (RNF-016): versión v1, esquema OpenAPI y campos estables."""

from django.test import Client, TestCase

from sgr_app import serializers
from sgr_app.models import Delegacion, Usuario

PASSWORD = 'TestPassword123!'


class ContratoApiTests(TestCase):
    def setUp(self):
        self.admin = Usuario.objects.create_superuser(
            username='admin.api', email='admin.api@example.com', password=PASSWORD,
            rol=Usuario.Rol.ADMINISTRADOR,
        )
        self.client = Client()
        self.client.force_login(self.admin)

    def test_api_v1_responde_igual_que_la_ruta_sin_version(self):
        Delegacion.objects.create(nombre='Centro', codigo='CEN')
        self.assertEqual(self.client.get('/api/v1/delegaciones/').json(), self.client.get('/api/delegaciones/').json())

    def test_esquema_openapi_documenta_solo_v1(self):
        response = self.client.get('/api/v1/schema/', HTTP_ACCEPT='application/vnd.oai.openapi+json')
        self.assertEqual(response.status_code, 200)
        esquema = response.json()
        self.assertTrue(esquema['openapi'].startswith('3.'))
        self.assertIn('/api/v1/actividades/', esquema['paths'])
        self.assertIn('/api/v1/auth/login/', esquema['paths'])
        self.assertFalse([ruta for ruta in esquema['paths'] if not ruta.startswith('/api/v1/')])

    def test_documentacion_publica_pero_endpoints_protegidos(self):
        """Swagger se abre sin sesión para usar Authorize con JWT; los datos siguen protegidos."""
        anonimo = Client()
        self.assertEqual(anonimo.get('/api/v1/docs/').status_code, 200)
        self.assertEqual(anonimo.get('/api/v1/schema/').status_code, 200)
        self.assertEqual(anonimo.get('/api/v1/delegaciones/').status_code, 401)
        self.assertEqual(self.client.get('/api/v1/docs/').status_code, 200)

    def test_esquema_documenta_autenticacion_jwt(self):
        esquema = Client().get('/api/v1/schema/', HTTP_ACCEPT='application/vnd.oai.openapi+json').json()
        jwt = esquema['components']['securitySchemes']['jwtAuth']
        self.assertEqual((jwt['type'], jwt['scheme'], jwt['bearerFormat']), ('http', 'bearer', 'JWT'))
        for ruta in ('/api/v1/auth/token/', '/api/v1/auth/token/refresh/', '/api/v1/auth/token/logout/'):
            self.assertIn(ruta, esquema['paths'])
        operaciones = esquema['paths']['/api/v1/usuarios/{id}/']
        self.assertEqual(set(operaciones) & {'get', 'put', 'patch', 'delete'}, {'get', 'put', 'patch', 'delete'})
        self.assertIn({'jwtAuth': []}, operaciones['delete']['security'])

    def test_ningun_serializador_expone_todos_los_campos_del_modelo(self):
        for nombre in dir(serializers):
            clase = getattr(serializers, nombre)
            meta = getattr(clase, 'Meta', None)
            if meta is not None and hasattr(meta, 'model'):
                with self.subTest(serializador=nombre):
                    self.assertNotEqual(getattr(meta, 'fields', None), '__all__')

    def test_usuario_no_expone_secretos(self):
        campos = set(serializers.UsuarioSerializer().fields)
        self.assertFalse(campos & {'password', 'totp_secret'})
