"""Una fotografía por evidencia: se separan las columnas archivo_foto_2/_3.

La especificación de casos de uso dice que el funcionario "adjunta hasta tres
fotos" y que el sistema "les asigna código verificador": cada foto es una
evidencia, que es la tabla hija de Actividad. La web ya trabajaba así, pero una
vía antigua de la API guardaba hasta tres fotos en una sola evidencia, en
columnas repetidas (archivo_foto_2/_3, url_foto_simulada_2/_3).

Qué hace, sin pérdida de datos:
1. Por cada evidencia con contenido en las casillas 2 o 3 crea una evidencia
   nueva por casilla. Copia actividad, estado de validación, verificador,
   fechas (incluida `fecha_subida`, que usa la retención), autor, reemplazo y
   deshabilitación, y le asigna su propio código verificador. Los metadatos y el
   SHA-256 se reparten por archivo cuando se puede asociar cada uno a su foto; si
   no, la evidencia original los conserva completos.
2. Cada separación deja un evento de auditoría (`SEPARAR_FOTOS_EVIDENCIA`) con
   los valores originales y los códigos nuevos.
3. Verificación: compara archivo por archivo y URL por URL (multiconjuntos)
   antes y después. Si algo no cuadra, aborta y revierte todo antes de quitar
   ninguna columna.
4. Solo entonces quita las cuatro columnas, que para ese momento ya están vacías.

No es reversible de forma automática: si fuera necesario, se restaura el
respaldo tomado antes de migrar (`respaldar_base_datos`).
"""

import secrets
import string
from collections import Counter

from django.db import migrations, transaction
from django.db.models import Q

CASILLAS = (
    ('archivo_foto', 'url_foto_simulada'),
    ('archivo_foto_2', 'url_foto_simulada_2'),
    ('archivo_foto_3', 'url_foto_simulada_3'),
)
COPIAR = (
    'actividad_id', 'estado', 'observacion', 'observacion_rechazo', 'verificador_id',
    'fecha_validacion', 'subido_por_id', 'archivos_deshabilitados_en', 'reemplazada_en',
    'reemplazada_por_id', 'fecha_evidencia',
)
CARACTERES_CODIGO = (
    string.ascii_uppercase.replace('O', '').replace('I', '')
    + string.digits.replace('0', '').replace('1', '')
)


def _nombre(archivo):
    return (getattr(archivo, 'name', archivo) or '').strip()


def _texto(valor):
    return (valor or '').strip()


def _inventario(Evidencia, columnas_archivo, columnas_url):
    archivos, urls = Counter(), Counter()
    for fila in Evidencia.objects.values(*columnas_archivo, *columnas_url).iterator():
        archivos.update(n for n in (_texto(fila[c]) for c in columnas_archivo) if n)
        urls.update(u for u in (_texto(fila[c]) for c in columnas_url) if u)
    return archivos, urls


def _metadatos_por_archivo(metadatos, cantidad_archivos):
    if isinstance(metadatos, dict) and isinstance(metadatos.get('archivos'), list):
        lista = [m for m in metadatos['archivos'] if isinstance(m, dict)]
    elif isinstance(metadatos, dict) and metadatos.get('sha256'):
        lista = [metadatos]
    else:
        lista = []
    return lista if lista and len(lista) == cantidad_archivos else None


def _con_casillas_extra():
    # `__gt=''` excluye tanto NULL como el texto vacío (un `__in` con None no sirve:
    # Django descarta el None y trataría NULL como "con contenido").
    return (
        Q(archivo_foto_2__gt='') | Q(archivo_foto_3__gt='')
        | Q(url_foto_simulada_2__gt='') | Q(url_foto_simulada_3__gt='')
    )


def _codigo_unico(Evidencia, prefijo):
    while True:
        codigo = prefijo + ''.join(secrets.choice(CARACTERES_CODIGO) for _ in range(6))
        if not Evidencia.objects.filter(codigo_verificador=codigo).exists():
            return codigo


def separar_fotos(apps, schema_editor):
    Evidencia = apps.get_model('sgr_app', 'Evidencia')
    Auditoria = apps.get_model('sgr_app', 'RegistroAuditoria')

    columnas_archivo = [archivo for archivo, _ in CASILLAS]
    columnas_url = [url for _, url in CASILLAS]

    with transaction.atomic(using=schema_editor.connection.alias):
        archivos_antes, urls_antes = _inventario(Evidencia, columnas_archivo, columnas_url)

        con_extras = Evidencia.objects.select_related('actividad__delegacion').filter(
            _con_casillas_extra()
        )
        for original in con_extras.order_by('pk'):
            casillas = [
                (_nombre(getattr(original, archivo)), _texto(getattr(original, url)))
                for archivo, url in CASILLAS
            ]
            ocupadas = [i for i, (archivo, url) in enumerate(casillas) if archivo or url]
            if not any(i > 0 for i in ocupadas):
                # Casillas 2/3 con solo espacios en blanco: no hay foto que separar.
                Evidencia.objects.filter(pk=original.pk).update(
                    archivo_foto_2=None, archivo_foto_3=None,
                    url_foto_simulada_2=None, url_foto_simulada_3=None,
                )
                continue
            # La evidencia original conserva la casilla 1. Si estaba vacía (y no
            # tiene la foto heredada `archivo`), toma la primera casilla ocupada.
            if casillas[0][0] or casillas[0][1] or _nombre(original.archivo):
                queda_en_original = 0
            else:
                queda_en_original = ocupadas[0]
            a_separar = [i for i in ocupadas if i != queda_en_original]

            con_archivo = [i for i, (archivo, _) in enumerate(casillas) if archivo]
            metadatos = _metadatos_por_archivo(original.metadatos, len(con_archivo))
            metadato_de = (
                {casilla: metadatos[pos] for pos, casilla in enumerate(con_archivo)}
                if metadatos else {}
            )

            anterior = {
                'casillas': [{'archivo': a, 'url': u} for a, u in casillas],
                'metadatos': original.metadatos,
                'hash_sha256': original.hash_sha256,
            }
            prefijo = (
                original.actividad.delegacion.codigo
                if original.actividad_id and original.actividad.delegacion_id else 'SGR'
            )
            nuevas = []
            for i in a_separar:
                archivo, url = casillas[i]
                metadato = metadato_de.get(i)
                nueva = Evidencia.objects.create(
                    codigo_verificador=_codigo_unico(Evidencia, prefijo),
                    archivo_foto=archivo or None,
                    url_foto_simulada=url or None,
                    metadatos=metadato,
                    hash_sha256=(metadato or {}).get('sha256'),
                    **{campo: getattr(original, campo) for campo in COPIAR},
                )
                # `fecha_subida` es auto_now_add: se restaura la original
                # (la retención de evidencias se calcula con ella).
                Evidencia.objects.filter(pk=nueva.pk).update(fecha_subida=original.fecha_subida)
                nuevas.append({
                    'id': nueva.pk, 'codigo_verificador': nueva.codigo_verificador,
                    'casilla': i + 1, 'archivo': archivo, 'url': url,
                })

            archivo_1, url_1 = casillas[queda_en_original]
            metadato_1 = metadato_de.get(queda_en_original)
            cambios = {
                'archivo_foto': archivo_1 or None,
                'url_foto_simulada': url_1 or None,
                'archivo_foto_2': None, 'archivo_foto_3': None,
                'url_foto_simulada_2': None, 'url_foto_simulada_3': None,
            }
            if metadatos:
                cambios['metadatos'] = metadato_1
                cambios['hash_sha256'] = (metadato_1 or {}).get('sha256')
            Evidencia.objects.filter(pk=original.pk).update(**cambios)

            Auditoria.objects.create(
                evento='MODIFICACION',
                accion='SEPARAR_FOTOS_EVIDENCIA',
                entidad='Evidencia',
                identificador=str(original.pk),
                identificador_registro=str(original.pk),
                valor_anterior=anterior,
                valor_nuevo={
                    'casilla_conservada': queda_en_original + 1,
                    'evidencias_nuevas': nuevas,
                },
            )

        # Verificación: ningún archivo ni URL se perdió ni se duplicó.
        archivos_despues, urls_despues = _inventario(Evidencia, columnas_archivo, columnas_url)
        if archivos_despues != archivos_antes or urls_despues != urls_antes:
            raise RuntimeError(
                'Separación de fotos abortada: el inventario de archivos/URL no coincide '
                f'(antes {sum(archivos_antes.values())}/{sum(urls_antes.values())}, '
                f'después {sum(archivos_despues.values())}/{sum(urls_despues.values())}).'
            )
        restantes = Evidencia.objects.filter(_con_casillas_extra()).count()
        if restantes:
            raise RuntimeError(f'Separación de fotos abortada: {restantes} evidencia(s) sin separar.')


class Migration(migrations.Migration):

    dependencies = [
        ('sgr_app', '0046_nombres_uniformes'),
    ]

    operations = [
        migrations.RunPython(separar_fotos),
        migrations.RemoveField(model_name='evidencia', name='archivo_foto_2'),
        migrations.RemoveField(model_name='evidencia', name='archivo_foto_3'),
        migrations.RemoveField(model_name='evidencia', name='url_foto_simulada_2'),
        migrations.RemoveField(model_name='evidencia', name='url_foto_simulada_3'),
    ]
