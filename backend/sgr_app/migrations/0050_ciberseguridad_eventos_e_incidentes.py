"""Ley 21.663 (Ley Marco de Ciberseguridad): eventos e incidentes de seguridad.

- EventoSeguridad: bloqueos por fuerza bruta, accesos denegados repetidos,
  intentos de alterar la auditoría y triggers de auditoría ausentes.
- IncidenteSeguridad: registro y plazos de reporte al CSIRT Nacional
  (alerta temprana 3 h, actualización 72 h, informe final 15 días).
- AccionIncidente: bitácora de acciones (no se edita ni se borra).

Solo crea tablas nuevas: no modifica datos existentes.
"""

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sgr_app', '0049_ajuste_observacion_decision'),
    ]

    operations = [
        migrations.CreateModel(
            name='EventoSeguridad',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tipo', models.CharField(choices=[('BLOQUEO_INICIO_SESION', 'Bloqueo por intentos fallidos de inicio de sesión'), ('BLOQUEO_2FA', 'Bloqueo por códigos 2FA incorrectos'), ('ACCESOS_DENEGADOS_REPETIDOS', 'Accesos denegados repetidos'), ('INTENTO_ALTERAR_AUDITORIA', 'Intento de alterar la auditoría'), ('TRIGGERS_AUDITORIA_AUSENTES', 'Protección de la auditoría desactivada')], db_index=True, max_length=40)),
                ('detalle', models.TextField()),
                ('ip_origen', models.GenericIPAddressField(blank=True, null=True)),
                ('clave_agrupacion', models.CharField(blank=True, db_index=True, default='', max_length=200)),
                ('alertado', models.BooleanField(default=False, help_text='Se envió correo a ALERTAS_EMAIL.')),
                ('creado_en', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('usuario', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='eventos_seguridad', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Evento de seguridad',
                'verbose_name_plural': 'Eventos de seguridad',
                'ordering': ['-creado_en', '-pk'],
            },
        ),
        migrations.CreateModel(
            name='IncidenteSeguridad',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('codigo', models.CharField(editable=False, max_length=20, unique=True)),
                ('titulo', models.CharField(max_length=200, verbose_name='Título')),
                ('descripcion', models.TextField(verbose_name='Descripción de lo ocurrido')),
                ('categoria', models.CharField(choices=[('ACCESO_NO_AUTORIZADO', 'Acceso no autorizado o intrusión'), ('CODIGO_MALICIOSO', 'Código malicioso (malware, ransomware)'), ('DISPONIBILIDAD', 'Afectación de disponibilidad (DoS, caída)'), ('FUGA_INFORMACION', 'Fuga o exposición de información'), ('FRAUDE', 'Fraude o suplantación (phishing)'), ('VULNERABILIDAD', 'Explotación de una vulnerabilidad'), ('OTRO', 'Otro')], max_length=30, verbose_name='Categoría')),
                ('severidad', models.CharField(choices=[('BAJA', 'Baja'), ('MEDIA', 'Media'), ('ALTA', 'Alta'), ('CRITICA', 'Crítica')], default='MEDIA', max_length=10)),
                ('estado', models.CharField(choices=[('ABIERTO', 'Abierto'), ('CONTENIDO', 'Contenido'), ('CERRADO', 'Cerrado')], default='ABIERTO', max_length=10)),
                ('detectado_en', models.DateTimeField(default=django.utils.timezone.now, help_text='Los plazos de reporte corren desde que se tiene conocimiento del incidente.', verbose_name='Detectado el')),
                ('ocurrido_en', models.DateTimeField(blank=True, null=True, verbose_name='Ocurrido el (estimado)')),
                ('afecta_continuidad', models.BooleanField(default=False, verbose_name='Interrumpe la continuidad del servicio')),
                ('afecta_personas', models.BooleanField(default=False, verbose_name='Afecta la integridad física o la salud de las personas')),
                ('afecta_datos_personales', models.BooleanField(default=False, verbose_name='Afecta sistemas con datos personales')),
                ('sistemas_afectados', models.TextField(blank=True, default='', verbose_name='Sistemas afectados')),
                ('impacto', models.TextField(blank=True, default='', verbose_name='Evaluación de gravedad e impacto')),
                ('indicadores_compromiso', models.TextField(blank=True, default='', verbose_name='Indicadores de compromiso (IoC)')),
                ('medidas_contencion', models.TextField(blank=True, default='', verbose_name='Medidas de contención y mitigación')),
                ('causa_raiz', models.TextField(blank=True, default='', verbose_name='Causa raíz y lecciones aprendidas')),
                ('folio_csirt', models.CharField(blank=True, default='', max_length=60, verbose_name='Folio del reporte en la ANCI')),
                ('alerta_temprana_enviada_en', models.DateTimeField(blank=True, null=True)),
                ('actualizacion_enviada_en', models.DateTimeField(blank=True, null=True)),
                ('informe_final_enviado_en', models.DateTimeField(blank=True, null=True)),
                ('alertas_enviadas', models.JSONField(blank=True, default=list, editable=False)),
                ('creado_en', models.DateTimeField(auto_now_add=True)),
                ('actualizado_en', models.DateTimeField(auto_now=True)),
                ('cerrado_en', models.DateTimeField(blank=True, null=True)),
                ('eventos', models.ManyToManyField(blank=True, related_name='incidentes', to='sgr_app.eventoseguridad')),
                ('registrado_por', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='incidentes_registrados', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Incidente de seguridad',
                'verbose_name_plural': 'Incidentes de seguridad',
                'ordering': ['-detectado_en', '-pk'],
            },
        ),
        migrations.CreateModel(
            name='AccionIncidente',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('texto', models.TextField()),
                ('creado_en', models.DateTimeField(auto_now_add=True)),
                ('autor', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='acciones_incidentes', to=settings.AUTH_USER_MODEL)),
                ('incidente', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='acciones', to='sgr_app.incidenteseguridad')),
            ],
            options={
                'verbose_name': 'Acción sobre un incidente',
                'verbose_name_plural': 'Acciones sobre incidentes',
                'ordering': ['creado_en', 'pk'],
            },
        ),
    ]
