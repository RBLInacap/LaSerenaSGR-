# Columnas duplicadas heredadas

Algunas tablas guardan el mismo dato en dos columnas: la **vigente**, que usa la lógica actual, y una **heredada** de versiones anteriores. Este documento registra cuáles son, cómo se mantienen alineadas y qué falta para unificarlas.

Por normativa ningún dato se elimina. Por eso ninguna columna se borra sin una decisión explícita, y cualquier valor que se reemplace queda en la auditoría.

## Inventario

| Tabla | Vigente | Heredada | Cómo se mantiene alineada |
|---|---|---|---|
| `sgr_app_compromisoagenda` | `fecha_comprometida` | `fecha_compromiso` | `CompromisoAgenda.save()` |
| `sgr_app_compromisoagenda` | `observacion` | `observaciones` | `CompromisoAgenda.save()`; de solo lectura en la API |
| `sgr_app_actividad` | `actividad_solicitud` | `solicitud_problema` | `Actividad.save()` |
| `sgr_app_actividad` | `accion_ejecutada` | `accion` | `Actividad.save()` |
| `sgr_app_actividad` | `item_medicion` | `item` | `Actividad.save()` (el heredado nunca completa al vigente) |
| Actividades ↔ Compromisos | `CompromisoAgenda.actividad` | `Actividad.compromiso_agenda` | A mano en `web_views.py`; lo vigila `verificar_coherencia` |
| `sgr_app_periodomedicion` | `umbral_semaforo_verde` / `_ambar` | `umbral_verde` / `umbral_ambar` | `PeriodoMedicion.save()` |
| `sgr_app_evidencia` | `archivo_foto` | `archivo` | Ya no se escribe; se lee solo como respaldo en cargas antiguas |
| `sgr_app_evidencia` | `fecha_subida` | `fecha_evidencia` | Ambas se fijan al crear la evidencia |
| `sgr_app_registroauditoria` | `funcionario`, `identificador_registro`, `fecha_auditoria` | `usuario`, `identificador`, `fecha` | `RegistroAuditoria.save()`; registros inmutables |

El sistema de metas heredado (`MetaModel` / `Indicador`, tablas `sgr_app_metamodel` y `sgr_app_indicador`) está **congelado**: según la especificación (CU-10) las metas viven en `ItemMedicion`. Sus registros se conservan como histórico y la aplicación ya no los recalcula.

Desde la migración `0046` todas las tablas usan la convención de Django (`sgr_app_<modelo>`, en minúsculas). Desde la `0047` cada evidencia tiene una sola fotografía: las columnas `archivo_foto_2/_3` y `url_foto_simulada_2/_3` se separaron en evidencias propias.

**No son duplicados**, aunque lo parezcan:
- **Fotografías históricas del nombre:** `tipo_actividad_nombre`, `catalogo_servicio_nombre`, el texto de `AtencionSocial.tipo_atencion` y los campos `AlertaGenerada.regla_*` guardan el valor que tenía el catálogo en ese momento, para que el historial no cambie.
- **Valores derivados:** `Solicitante.apellido` y `CasoSocial.persona_clave`.
- **Columnas con significados distintos:** `PeriodoMedicion.cerrado` frente a `estado`, y `RegistroAuditoria.evento` frente a `accion`.

## Reglas de sincronización (fase 1)

Las aplica `sincronizar_columnas_duplicadas()` en `sgr_app/models.py` cada vez que se guarda un registro, venga el cambio de la web, la API, la shell o un comando:

1. **Si la vigente tiene valor,** la heredada pasa a tener ese mismo valor.
2. **Si la vigente está vacía y la heredada no,** la vigente se completa con la heredada. La excepción es `item`: completarlo cambiaría los indicadores.
3. **Si la heredada tenía un valor distinto,** se reemplaza y el valor anterior queda en la auditoría (`accion = SINCRONIZAR_COLUMNA_DUPLICADA`).
4. **Con `save(update_fields=[...])`,** la columna heredada se agrega a los campos que se guardan.
5. **Toda la lógica lee la columna vigente:** semáforo, panel, alertas, tubo de trabajo, vencimientos y orden por defecto.

Las escrituras masivas con `QuerySet.update()` no pasan por `save()`: no deben usarse sobre estas columnas.

## Fases

| Fase | Contenido | Estado |
|---|---|---|
| 1 | Sincronización en `save()`, lecturas desde la vigente, columna heredada de solo lectura en la API, chequeos en `verificar_coherencia` | ✅ Implementada |
| 2 | Corrección de datos anteriores: completar valores vacíos y resolver diferencias a favor de la vigente, guardando el valor anterior en la auditoría (`python manage.py unificar_columnas_duplicadas --aplicar`) | ✅ Implementada |
| 3 | Congelar las heredadas (ningún código las lee ni escribe). Eliminarlas solo con aprobación, porque borrar una columna borra datos | Pendiente, requiere decisión |

## Revisar la base real

```bash
python manage.py verificar_coherencia
```

Los hallazgos con código `duplicada.*`, `compromiso.fechas_divergentes`, `actividad.item_divergente` y `periodo.umbral_legado_divergente` corresponden a estas columnas. Un registro con diferencias se corrige solo la próxima vez que se guarda; para corregirlos todos de una vez (fase 2):

```bash
python manage.py respaldar_base_datos                     # respaldo previo
python manage.py unificar_columnas_duplicadas             # simulación: informa qué cambiaría
python manage.py unificar_columnas_duplicadas --aplicar   # corrige y audita cada registro
```

Detalles de la fase 2 (`sgr_app/services/columnas_duplicadas.py`):

- Escribe fila por fila con `update()` y un evento de auditoría `UNIFICAR_COLUMNA_DUPLICADA` por registro, con los valores anteriores y nuevos. No pasa por `save()` para no disparar efectos secundarios (por ejemplo, recalcular el estado de un compromiso).
- **Evidencias:** la foto heredada `archivo` solo completa `archivo_foto` cuando está vacía; `archivo` nunca se sobrescribe. `fecha_evidencia` se iguala al día local de `fecha_subida`. La causa de esa divergencia era el valor por defecto en UTC, corregido en la migración `0044`.
- **No se tocan:** `Actividad.item` cuando `item_medicion` está vacío (cambiaría los indicadores), el vínculo recíproco Actividad ↔ Compromiso (requiere revisión manual) y la auditoría (inmutable).
- Es idempotente: una segunda ejecución informa 0 cambios.
