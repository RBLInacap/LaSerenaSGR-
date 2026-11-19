"""Gestión de incidentes de ciberseguridad (Ley 21.663, Ley Marco de Ciberseguridad).

El Administrador registra, actualiza y cierra incidentes, marca cada hito del
reporte al CSIRT Nacional y lleva la bitácora de acciones. El Coordinador puede
consultarlos y exportar el reporte. Ningún incidente ni acción se borra.
"""

from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from sgr_app.forms import AccionIncidenteForm, HitoReporteForm, IncidenteSeguridadForm
from sgr_app.models import AccionIncidente, EventoSeguridad, IncidenteSeguridad, RegistroAuditoria
from sgr_app.services.incidentes import notificar_incidente_creado, reporte_texto
from sgr_app.services.seguridad_acceso import obtener_ip_cliente

CAMPOS_AUDITADOS = (
    'titulo', 'categoria', 'severidad', 'estado', 'afecta_continuidad', 'afecta_personas',
    'afecta_datos_personales', 'folio_csirt', 'alerta_temprana_enviada_en',
    'actualizacion_enviada_en', 'informe_final_enviado_en',
)


def _puede_ver(usuario):
    return usuario.is_authenticated and (usuario.es_admin() or usuario.es_coordinador)


def _exigir(usuario, gestionar=False):
    if not _puede_ver(usuario) or (gestionar and not usuario.es_admin()):
        raise PermissionDenied


def _foto(incidente):
    return {
        campo: (valor.isoformat() if hasattr(valor, 'isoformat') else valor)
        for campo in CAMPOS_AUDITADOS
        for valor in [getattr(incidente, campo)]
    }


def _auditar(request, accion, incidente, anterior, nuevo):
    RegistroAuditoria.objects.create(
        usuario=request.user, funcionario=request.user, evento='MODIFICACION' if anterior else 'CREACION',
        accion=accion, entidad='IncidenteSeguridad', identificador=str(incidente.pk),
        identificador_registro=str(incidente.pk), valor_anterior=anterior, valor_nuevo=nuevo,
        ip_origen=obtener_ip_cliente(request) or None,
    )


def incidentes_lista(request):
    _exigir(request.user)
    incidentes = list(IncidenteSeguridad.objects.select_related('registrado_por'))
    ahora = timezone.now()
    for incidente in incidentes:
        incidente.hitos_actuales = incidente.hitos(ahora)
    return render(request, 'incidentes/lista.html', {
        'incidentes': incidentes,
        'eventos': EventoSeguridad.objects.select_related('usuario')[:50],
        'puede_gestionar': request.user.es_admin(),
        'pendientes': sum(
            1 for i in incidentes for h in i.hitos_actuales if h['estado'] in ('VENCIDO', 'POR_VENCER')
        ),
    })


def incidente_crear(request):
    _exigir(request.user, gestionar=True)
    if request.method == 'POST':
        form = IncidenteSeguridadForm(request.POST)
        if form.is_valid():
            with transaction.atomic():
                incidente = form.save(commit=False)
                incidente.registrado_por = request.user
                incidente.save()
                form.save_m2m()
                _auditar(request, 'CREAR_INCIDENTE_SEGURIDAD', incidente, None, _foto(incidente))
            if notificar_incidente_creado(incidente):
                messages.info(request, 'Se envió la alerta con los plazos de reporte a ALERTAS_EMAIL.')
            messages.success(request, f'Incidente {incidente.codigo} registrado.')
            return redirect('web_incidente_detalle', pk=incidente.pk)
    else:
        inicial = {'detectado_en': timezone.localtime().strftime('%Y-%m-%dT%H:%M')}
        evento = EventoSeguridad.objects.filter(pk=request.GET.get('evento') or 0).first()
        if evento:
            inicial.update({
                'titulo': evento.get_tipo_display(), 'descripcion': evento.detalle,
                'detectado_en': timezone.localtime(evento.creado_en).strftime('%Y-%m-%dT%H:%M'),
                'eventos': [evento.pk], 'categoria': IncidenteSeguridad.Categoria.ACCESO_NO_AUTORIZADO,
                'indicadores_compromiso': f'IP de origen: {evento.ip_origen}' if evento.ip_origen else '',
            })
        form = IncidenteSeguridadForm(initial=inicial)
    return render(request, 'incidentes/form.html', {'form': form, 'titulo': 'Registrar incidente'})


def incidente_detalle(request, pk):
    _exigir(request.user)
    incidente = get_object_or_404(IncidenteSeguridad, pk=pk)
    form = IncidenteSeguridadForm(instance=incidente)
    form_hito, form_accion = HitoReporteForm(initial={
        'enviado_en': timezone.localtime().strftime('%Y-%m-%dT%H:%M'), 'folio': incidente.folio_csirt,
    }), AccionIncidenteForm()

    if request.method == 'POST':
        _exigir(request.user, gestionar=True)
        operacion = request.POST.get('operacion')
        anterior = _foto(incidente)
        if operacion == 'actualizar':
            form = IncidenteSeguridadForm(request.POST, instance=incidente)
            if form.is_valid():
                with transaction.atomic():
                    form.save()
                    _auditar(request, 'ACTUALIZAR_INCIDENTE_SEGURIDAD', incidente, anterior, _foto(incidente))
                messages.success(request, 'Incidente actualizado.')
                return redirect('web_incidente_detalle', pk=incidente.pk)
        elif operacion == 'hito':
            form_hito = HitoReporteForm(request.POST)
            if not incidente.requiere_reporte:
                messages.error(request, 'Este incidente no tiene efecto significativo: no requiere reporte.')
                return redirect('web_incidente_detalle', pk=incidente.pk)
            if form_hito.is_valid():
                hito = form_hito.cleaned_data['hito']
                if form_hito.cleaned_data['enviado_en'] < incidente.detectado_en:
                    form_hito.add_error('enviado_en', 'El envío no puede ser anterior a la detección.')
                else:
                    with transaction.atomic():
                        setattr(incidente, IncidenteSeguridad.CAMPO_ENVIO[hito], form_hito.cleaned_data['enviado_en'])
                        if form_hito.cleaned_data['folio']:
                            incidente.folio_csirt = form_hito.cleaned_data['folio']
                        incidente.save()
                        _auditar(request, 'REPORTE_CSIRT_INCIDENTE', incidente, anterior, _foto(incidente))
                    messages.success(request, f'Registrado: {IncidenteSeguridad.NOMBRES_HITO[hito]}.')
                    return redirect('web_incidente_detalle', pk=incidente.pk)
        elif operacion == 'accion':
            form_accion = AccionIncidenteForm(request.POST)
            if form_accion.is_valid():
                with transaction.atomic():
                    accion = AccionIncidente.objects.create(
                        incidente=incidente, autor=request.user, texto=form_accion.cleaned_data['texto'],
                    )
                    _auditar(request, 'ACCION_INCIDENTE_SEGURIDAD', incidente, None,
                             {'accion_id': accion.pk, 'texto': accion.texto[:300]})
                messages.success(request, 'Acción registrada en la bitácora.')
                return redirect('web_incidente_detalle', pk=incidente.pk)
        else:
            messages.error(request, 'Operación no reconocida.')

    return render(request, 'incidentes/detalle.html', {
        'incidente': incidente, 'hitos': incidente.hitos(), 'form': form, 'form_hito': form_hito,
        'form_accion': form_accion, 'acciones': incidente.acciones.select_related('autor'),
        'eventos_asociados': incidente.eventos.all(), 'puede_gestionar': request.user.es_admin(),
    })


def incidente_reporte(request, pk):
    _exigir(request.user)
    incidente = get_object_or_404(IncidenteSeguridad, pk=pk)
    respuesta = HttpResponse(reporte_texto(incidente), content_type='text/plain; charset=utf-8')
    respuesta['Content-Disposition'] = f'attachment; filename="reporte_{incidente.codigo}.txt"'
    return respuesta
