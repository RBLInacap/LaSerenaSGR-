# API REST del SGR (Django REST Framework + JWT)

La API expone las funciones del SGR para que otras aplicaciones (móviles, servicios municipales, integraciones) puedan consumirlas de forma segura. Está versionada en `/api/v1/`, responde siempre en JSON y está documentada con Swagger/OpenAPI.

- **Swagger UI:** `/api/v1/docs/`
- **Esquema OpenAPI 3:** `/api/v1/schema/`

## Recursos principales

| Recurso | Tipo | Ruta | Operaciones |
|---|---|---|---|
| Funcionarios | Mantenedor 1 | `/api/v1/usuarios/` | `GET` `POST` `PUT` `PATCH` `DELETE` |
| Delegaciones | Mantenedor 2 | `/api/v1/delegaciones/` | `GET` `POST` `PUT` `PATCH` `DELETE` |
| Actividades | Transacción del negocio | `/api/v1/actividades/` | `GET` `POST` `PUT` `PATCH` `DELETE` |

La transacción **Registro de actividades** involucra a los dos mantenedores: cada actividad pertenece a un **funcionario** y a una **delegación**. Es el proceso central del SGR, porque cada actividad registrada alimenta los indicadores y el semáforo de cumplimiento de la delegación.

El resto de los recursos (`cargos/`, `periodos/`, `evidencias/`, `compromisos/`, etc.) mantiene sus reglas anteriores; ver [MATRIZ_PERMISOS.md](MATRIZ_PERMISOS.md).

### DELETE = baja lógica

Por normativa municipal **ningún registro se elimina**. `DELETE` existe y responde `200`, pero conserva la fila y su historial:

| Recurso | Qué hace `DELETE` | Cómo se revierte |
|---|---|---|
| Funcionario | `is_active=false`: no puede iniciar sesión y sus tokens dejan de funcionar | `PATCH {"is_active": true}` |
| Delegación | `activo=false`; avisa si tiene funcionarios activos o compromisos abiertos | `PATCH {"activo": true}` |
| Actividad | La anula con motivo obligatorio (`?motivo=...`): deja de contar en los indicadores | No se revierte (queda en el historial) |

Cada baja queda registrada en la auditoría inmutable. Una prueba automática impide que un endpoint use el borrado físico de DRF.

## Autenticación JWT

| Endpoint | Uso |
|---|---|
| `POST /api/v1/auth/token/` | Usuario y contraseña → `access` + `refresh` |
| `POST /api/v1/auth/token/refresh/` | `refresh` → nuevo `access` + nuevo `refresh` |
| `POST /api/v1/auth/token/logout/` | Revoca el `refresh` (cierre de sesión) |

- **Access token:** dura 15 minutos y se envía en la cabecera `Authorization: Bearer <access>`.
- **Refresh token:** dura 8 horas. Rota en cada uso, y el anterior queda en una lista negra.
- La web sigue funcionando con su sesión normal: la API acepta tanto JWT como sesión.

### Ejemplo con curl

```bash
# 1. Obtener tokens
curl -X POST https://<IP>/api/v1/auth/token/ \
  -H "Content-Type: application/json" \
  -d '{"username": "admin@laserena.cl", "password": "********"}'
# Si la cuenta tiene verificación en dos pasos, agrega "codigo_2fa": "123456".

# 2. Usar el access token
curl https://<IP>/api/v1/usuarios/ -H "Authorization: Bearer <access>"

# 3. Renovar cuando el access vence (responde 401)
curl -X POST https://<IP>/api/v1/auth/token/refresh/ \
  -H "Content-Type: application/json" -d '{"refresh": "<refresh>"}'
```

### Desde Swagger (botón Authorize)

1. Abre `/api/v1/docs/` y ejecuta `POST /api/v1/auth/token/` con **Try it out**.
2. Copia el valor de `access`.
3. Presiona **Authorize**, pega el token (sin escribir "Bearer") y confirma.
4. Prueba cualquier endpoint protegido. Sin autorizar responde `401`; autorizado responde `200`.

> Para demostrar JWT, abre Swagger en una ventana privada sin sesión web. Si ya iniciaste sesión en la web, la cookie de sesión también te autentica.

## Protección de datos sensibles

| Campo | Recurso | Administrador | Otros perfiles |
|---|---|---|---|
| `email`, `telefono`, `rut_anonimizado`, `requires_2fa` | Funcionarios | ✅ | Omitido |
| `contacto_telefono` (teléfono del vecino) | Actividades | ✅ | Omitido (se exige al registrar) |
| Contraseña, secreto 2FA | Funcionarios | Nunca | Nunca |

Se implementa con `OcultarCamposSensiblesMixin` en [serializers.py](../backend/sgr_app/serializers.py). Además, el contenido del token JWT solo incluye el id y el rol: un JWT está firmado, no cifrado, y cualquiera que lo tenga puede leerlo.

Las delegaciones exponen su teléfono y su correo porque son datos institucionales públicos, no personales.

## Permisos por perfil

| Operación | Administrador | Coordinador | Delegado | Funcionario | Consulta |
|---|---|---|---|---|---|
| Leer funcionarios | Todos | Todos | Su delegación | Solo su ficha | Su ámbito |
| Crear / modificar / dar de baja funcionarios y delegaciones | ✅ | ❌ | ❌ | ❌ | ❌ |
| Leer actividades | Todas | Todas | Su delegación | Propias | Su ámbito |
| Registrar actividad | ✅ | ✅ | Solo con el permiso adicional `REGISTRAR_ACTIVIDAD` | Propias | ❌ |
| Modificar actividad | ✅ | ✅ | ❌ | ❌ | ❌ |
| Anular actividad (`DELETE`) | ✅ | ✅ | Su delegación | ❌ | ❌ |

Un registro fuera del ámbito del perfil responde `404` (no `403`), para no revelar que existe.

## Respuestas y códigos HTTP

Todas las respuestas son JSON. Los errores incluyen `detail` (mensaje legible) y `code` (para programas). Los errores de validación indican el problema de cada campo.

| Código | Cuándo | Ejemplo de cuerpo |
|---|---|---|
| `200 OK` | Lectura, modificación o baja lógica | El recurso o `{"detail": "...", "id": 3}` |
| `201 Created` | Alta exitosa | El recurso creado |
| `400 Bad Request` | Datos inválidos | `{"rut_anonimizado": ["Ingresa el RUN con puntos y guion..."]}` |
| `401 Unauthorized` | Sin token, token vencido/inválido, credenciales o 2FA incorrectos | `{"detail": "...", "code": "not_authenticated"}` |
| `403 Forbidden` | El perfil no tiene permiso | `{"detail": "...", "code": "permission_denied"}` |
| `404 Not Found` | No existe o está fuera de tu ámbito | `{"detail": "...", "code": "no_encontrado"}` |
| `405 Method Not Allowed` | Método no disponible en ese recurso | `{"detail": "...", "code": "method_not_allowed"}` |
| `412 Precondition Failed` | `If-Match` desactualizado (otra persona modificó el registro) | `{"detail": "..."}` |
| `429 Too Many Requests` | Bloqueo por intentos fallidos o exceso de peticiones | `{"detail": "...", "code": "throttled"}` |
| `500 Internal Server Error` | Error no controlado; el detalle queda solo en el log | `{"detail": "Error interno del servidor...", "code": "error_interno"}` |

## Medidas de seguridad aplicadas

Estas son las recomendaciones de desarrollo seguro aplicadas a la API, agrupadas por aspecto. Sirven de base para la sección "Recomendaciones obtenidas mediante IA" del informe.

| Aspecto | Riesgo | Medida |
|---|---|---|
| Configuración JWT | Robo de un token | Access de 15 min; refresh de 8 h con rotación y lista negra; logout que revoca; clave de firma propia (`JWT_SIGNING_KEY`) |
| Emisión de tokens | Saltarse los controles del login web | El token aplica el mismo bloqueo por intentos fallidos, la 2FA, la clave inicial pendiente y la 2FA obligatoria por rol |
| Fuerza bruta | Adivinar contraseñas | Bloqueo temporal por usuario+IP y por IP, y además un límite de peticiones (`20/min`) a los endpoints de tokens |
| Protección de endpoints | Acceso anónimo | `401` en todos los endpoints de datos; Swagger solo muestra la documentación |
| Restricción de permisos | Escalamiento de privilegios | Permisos por rol y acción (`AuthenticatedRolePermission`), filtro por ámbito en cada consulta y `404` fuera del ámbito; el Usuario de consulta es de solo lectura también con JWT |
| Cuentas desactivadas | Acceso de exfuncionarios | Un funcionario dado de baja pierde el acceso de inmediato: sus tokens vigentes se rechazan |
| Exposición de datos sensibles | Fuga de datos personales | Campos sensibles solo para el Administrador; el token no lleva datos personales; nunca se exponen contraseñas ni secretos 2FA |
| Validación de datos | Datos corruptos o inyección | Serializers que validan RUN (dígito verificador), teléfono, correo único, fechas no futuras y coherencia ítem/cargo/período |
| Manejo seguro de errores | Filtrar trazas o rutas internas | `500` genérico en JSON; la traza va solo al log y al correo de alertas |
| Trazabilidad | Acciones sin responsable | Emisión de tokens, altas, cambios y bajas quedan en la auditoría inmutable, con usuario e IP |
| Integridad | Borrado de evidencia legal | Sin borrado físico: `DELETE` es baja lógica, verificada por una prueba automática |
| Concurrencia | Sobrescritura silenciosa | `ETag` / `If-Match` con respuesta `412` |

## Pruebas

```bash
cd backend
python manage.py test sgr_app.test_api_jwt          # API JWT (Sumativa 4)
python manage.py test sgr_app                        # suite completa
```

`test_api_jwt.py` cubre los tokens (emisión, renovación, revocación y vencimiento), el bloqueo y la 2FA, el CRUD de los dos mantenedores, la transacción, los datos sensibles por perfil y los códigos HTTP.
