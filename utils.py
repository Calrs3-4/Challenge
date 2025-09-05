from functools import wraps
from datetime import datetime
import logging
from flask_jwt_extended import get_jwt_identity
from flask import request, current_app
from app1.models import Log
from app1 import db
from app1.models import EstadoTarea
from sqlalchemy import create_engine
import traceback
import json

from functools import wraps
from flask import request, current_app, jsonify
import logging
from datetime import datetime
import traceback

def log_operacion(accion, nivel='info', registrar_db=False):
    """
    Decorador definitivo que:
    1. Captura consistentemente proyecto_id y tarea_id
    2. Garantiza compatibilidad con registrar_log_db
    3. Maneja todos los edge cases
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Manejo robusto del request data
            request_data = {}
            try:
                # Obtenemos los datos crudos y hacemos parsing manual
                raw_data = request.get_data(as_text=True)
                if raw_data:
                    try:
                        request_data = json.loads(raw_data)
                    except json.JSONDecodeError:
                        current_app.logger.warning("Failed to decode JSON data")
            except Exception as e:
                current_app.logger.warning(f"Error getting request data: {str(e)}")

            # Obtener usuario_id - manejar casos de autenticación
            usuario_id = None
            try:
                usuario_id = get_jwt_identity()
            except Exception:
                # Para endpoints de login/register, el JWT puede no estar disponible aún
                pass
            
            # Si es endpoint de login/register, intentar obtener usuario del request
            if usuario_id is None and accion in ['registro_usuario', 'inicio_sesion']:
                usuario_id = request_data.get('email') or request_data.get('username') or 'unknown'

            # Preparación de datos del log
            log_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "usuario_id": usuario_id or 'anon',
                "endpoint": request.endpoint,
                "accion": accion,
                "method": request.method,
                "ip": request.remote_addr,
                "user_agent": request.headers.get('User-Agent', 'Desconocido'),
                "request_data": request_data,
                "entity_data": {
                    'proyecto_id': kwargs.get('proyecto_id'),
                    'tarea_id': None
                }
            }

            # Resto de la lógica del decorador...

            # 2. Extracción segura de IDs
            try:
                log_data['entity_data']['proyecto_id'] = (
                    kwargs.get('proyecto_id') or
                    (request_data.get('proyecto_id') if isinstance(request_data, dict) else None) or
                    (request_data.get('project_id') if isinstance(request_data, dict) else None)
                )
                
                log_data['entity_data']['tarea_id'] = (
                    kwargs.get('tarea_id') or
                    (request_data.get('tarea_id') if isinstance(request_data, dict) else None) or
                    (request_data.get('task_id') if isinstance(request_data, dict) else None)
                )
            except Exception as e:
                current_app.logger.error(f"Error extracting IDs: {str(e)}")
    
    # Resto del decorador...
            try:
                # 3. Ejecutar la función principal
                resultado = f(*args, **kwargs)
                response, status_code = (resultado if isinstance(resultado, tuple) 
                                      else (resultado, 200))
                log_data['status_code'] = status_code

                # 4. Procesamiento de respuesta
                response_data = {}
                if hasattr(response, 'get_json'):
                    response_data = response.get_json() or {}
                elif isinstance(response, dict):
                    response_data = response
                elif isinstance(response, list):
                    response_data = {"items": response, "count": len(response)}

                # 5. Extracción reforzada de IDs desde múltiples fuentes
                def extract_ids(data, prefix=""):
                    ids = {}
                    for key in ['proyecto_id', 'project_id', 'tarea_id', 'task_id', 'id']:
                        if key in data:
                            if 'proyecto' in key or 'project' in key:
                                ids['proyecto_id'] = data[key]
                            elif 'tarea' in key or 'task' in key:
                                ids['tarea_id'] = data[key]
                            elif key == 'id' and prefix == 'data_':
                                # Solo considerar 'id' si viene de data para evitar falsos positivos
                                if 'tasks' in request.path or 'tareas' in request.path:
                                    ids['tarea_id'] = data[key]
                                elif 'projects' in request.path or 'proyectos' in request.path:
                                    ids['proyecto_id'] = data[key]
                    return ids

                # Buscar IDs en response_data y en data anidado
                ids_from_response = extract_ids(response_data)
                if 'data' in response_data and isinstance(response_data['data'], dict):
                    ids_from_data = extract_ids(response_data['data'], 'data_')
                    ids_from_response.update(ids_from_data)

                # Actualizar IDs solo si se encontraron valores
                for key, value in ids_from_response.items():
                    if value is not None:
                        log_data['entity_data'][key] = value

                # 6. Determinación final de entity_type
                entity_type = None
                entity_id = None
                
                if log_data['entity_data']['tarea_id']:
                    entity_type = 'tarea'
                    entity_id = log_data['entity_data']['tarea_id']
                elif log_data['entity_data']['proyecto_id']:
                    entity_type = 'proyecto'
                    entity_id = log_data['entity_data']['proyecto_id']

                # 7. Registro estructurado
                current_app.logger.log(
                    getattr(logging, nivel.upper()),
                    f"{accion} - {entity_type or 'operacion'} {entity_id or 'N/A'}",
                    extra={
                        "audit_data": log_data,
                        "entity_type": entity_type,
                        "entity_id": entity_id
                    }
                )

                # 8. Preparación para registrar_log_db
                if registrar_db:
                    db_log_data = {
                        'usuario_id': log_data['usuario_id'],
                        'proyecto_id': log_data['entity_data']['proyecto_id'],
                        'tarea_id': log_data['entity_data']['tarea_id'],
                        'accion': accion,
                        'method': log_data['method'],
                        'endpoint': log_data['endpoint'],
                        'status_code': status_code,
                        'ip': log_data['ip'],
                        'user_agent': log_data['user_agent'],
                        'entity_type': entity_type,
                        'entity_id': entity_id,
                        'response_data': {
                            'ids': {
                                'proyecto_id': log_data['entity_data']['proyecto_id'],
                                'tarea_id': log_data['entity_data']['tarea_id']
                            },
                            'items_count': len(response_data.get('items', [])) if isinstance(response_data.get('items'), list) else None
                        }
                    }
                    
                    if not registrar_log_db(db_log_data):
                        current_app.logger.warning("Fallo secundario en registro DB", extra=db_log_data)

                return resultado

            except Exception as exc:
                # 9. Manejo de errores completo
                error_data = {
                    'error': str(exc),
                    'stack_trace': traceback.format_exc(),
                    'request_headers': dict(request.headers),
                    'request_data': request_data,
                    'entity_data': log_data['entity_data']
                }
                
                current_app.logger.error(
                    f"Error en {accion}",
                    extra={
                        "audit_data": {**log_data, **error_data},
                        "entity_type": 'tarea' if log_data['entity_data']['tarea_id'] else 'proyecto' if log_data['entity_data']['proyecto_id'] else None,
                        "entity_id": log_data['entity_data']['tarea_id'] or log_data['entity_data']['proyecto_id']
                    },
                    exc_info=True
                )

                if registrar_db:
                    db_log_data = {
                        'usuario_id': log_data['usuario_id'],
                        'proyecto_id': log_data['entity_data']['proyecto_id'],
                        'tarea_id': log_data['entity_data']['tarea_id'],
                        'accion': accion,
                        'method': log_data['method'],
                        'endpoint': log_data['endpoint'],
                        'error': str(exc),
                        'stack_trace': traceback.format_exc(),
                        'ip': log_data['ip'],
                        'user_agent': log_data['user_agent']
                    }
                    
                    registrar_log_db(db_log_data)

                raise exc

        return wrapper
    return decorator


    
def registrar_log_db(log_data):
    """Versión más flexible que mantiene la trazabilidad"""
    try:
        # Validación esencial (sin fallar por campos opcionales)
        essentials = {
            'usuario_id': log_data.get('usuario_id', 'unknown'),
            'accion': log_data.get('accion', 'unspecified'),
            'method': log_data.get('method', request.method if hasattr(request, 'method') else 'UNKNOWN')
        }

        # Crear registro con datos disponibles
        log = Log(
            usuario_id=essentials['usuario_id'],
            proyecto_id=log_data.get('proyecto_id'),
            tarea_id=log_data.get('tarea_id'),
            accion=essentials['accion'],
            detalles={
                'method': essentials['method'],
                'endpoint': log_data.get('endpoint'),
                'status_code': log_data.get('status_code'),
                'error': log_data.get('error'),
                'response_data': log_data.get('response_data', {}),
                'entity_type': log_data.get('entity_type'),
                'entity_id': log_data.get('entity_id')
            },
            ip_origen=log_data.get('ip', ''),
            user_agent=log_data.get('user_agent', ''),
            fecha_creacion=datetime.utcnow()
        )

        db.session.add(log)
        db.session.commit()

        # Verificación opcional (solo log, no bloqueante)
        if log.tarea_id is None and 'task' in (log_data.get('endpoint') or '').lower():
            current_app.logger.info(
                "Registro de tarea sin ID",
                extra={'log_id': log.id, 'endpoint': log_data.get('endpoint')}
            )

        return True

    except Exception as e:
        current_app.logger.error(
            "Fallo al registrar log (datos recibidos)",
            exc_info=True,
            extra={
                'log_data_keys': list(log_data.keys()),
                'essentials': essentials
            }
        )
        db.session.rollback()
        return False


def verificar_estado_proyecto(proyecto_id):
    """
    Actualiza automáticamente el estado del proyecto basado en sus tareas
    """
    from app1.models import Proyecto, Tarea, EstadoTarea
    
    proyecto = Proyecto.query.get(proyecto_id)
    if not proyecto:
        return False
    
    tareas = Tarea.query.filter_by(proyecto_id=proyecto_id).all()
    
    if not tareas:
        proyecto.estado = 'pendiente'
    else:
        todas_completas = all(t.estado == EstadoTarea.COMPLETADO for t in tareas)
        alguna_en_progreso = any(t.estado == EstadoTarea.EN_PROGRESO for t in tareas)
        
        if todas_completas:
            proyecto.estado = 'completado'
            proyecto.fecha_completado = datetime.utcnow()
        elif alguna_en_progreso:
            proyecto.estado = 'en_progreso'
        else:
            proyecto.estado = 'pendiente'
    
    try:
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error actualizando estado proyecto {proyecto_id}: {str(e)}")
        return False

def puede_finalizar_proyecto(proyecto_id):
    """
    Verifica si un proyecto puede marcarse como completado
    Devuelve: (bool_puede_finalizar, str_mensaje_error)
    """
    from app1.models import Proyecto, Tarea, EstadoTarea
    
    proyecto = Proyecto.query.get(proyecto_id)
    if not proyecto:
        return False, "Proyecto no encontrado"
    
    tareas = Tarea.query.filter_by(proyecto_id=proyecto_id).all()
    
    if not tareas:
        return False, "El proyecto no tiene tareas"
    
    incompletas = [t for t in tareas if t.estado != EstadoTarea.COMPLETADO]
    
    if incompletas:
        nombres_incompletas = [t.titulo for t in incompletas[:3]]  # Mostrar hasta 3 tareas
        mensaje = f"{len(incompletas)} tareas pendientes"
        if nombres_incompletas:
            mensaje += f" (ej: {', '.join(nombres_incompletas)}{'...' if len(incompletas) > 3 else ''})"
        return False, mensaje
    
    return True, ""



def log_registro_usuario(f):
    """Decorador específico para registro de usuarios"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        return log_operacion('registro_usuario', 'info', True)(f)(*args, **kwargs)
    return wrapper

def log_inicio_sesion(f):
    """Decorador específico para inicio de sesión"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        return log_operacion('inicio_sesion', 'info', True)(f)(*args, **kwargs)
    return wrapper

def log_cierre_sesion(f):
    """Decorador específico para cierre de sesión"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        return log_operacion('cierre_sesion', 'info', True)(f)(*args, **kwargs)
    return wrapper
