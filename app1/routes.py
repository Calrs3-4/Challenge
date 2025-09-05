# Importación de librerías y módulos necesarios
from flask import Blueprint, request, jsonify, current_app, g  # Componentes de Flask
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request  # Autenticación JWT
from app1.models import Usuario, Proyecto, MiembroProyecto, Tarea, EstadoTarea  # Modelos de datos
from . import db  # Instancia de la base de datos
from sqlalchemy import select  # Consultas SQLAlchemy
from app1.models import Log  # Modelo de logs
from utils import verificar_estado_proyecto, puede_finalizar_proyecto  # Utilidades personalizadas
import json  # Manejo de JSON
import traceback  # Traza de errores
from error_code import ProjectErrorCodes, SuccessCodes, SystemErrorCodes, CollaboratorErrorCodes, TaskErrorCodes  # Códigos de error
from sqlalchemy.exc import SQLAlchemyError  # Excepciones de SQLAlchemy
from http import HTTPStatus  # Códigos de estado HTTP
from werkzeug.exceptions import NotFound  # Excepción de recurso no encontrado
from sqlalchemy import func  # Funciones de SQLAlchemy
from markupsafe import escape  # Escapado de caracteres
from marshmallow import ValidationError  # Validación de datos
from utils import log_operacion  # Utilidad para logging de operaciones
from datetime import datetime  # Manejo de fechas
from app1.schema import ProjectSchema, TareaSchema  # Esquemas de validación

# Definición del blueprint para rutas de proyectos
project_bp = Blueprint('projects', __name__)

# Endpoint para crear un nuevo proyecto
@project_bp.route('/', methods=['POST'])
@jwt_required()  # Requiere autenticación JWT
@log_operacion("CREACION_PROYECTO", nivel='info', registrar_db=True)  # Log de la operación
def crear_proyecto():
    usuario_id = get_jwt_identity()  # Obtiene ID del usuario autenticado
    
    # 1. Validar entrada con el schema
    schema = ProjectSchema()
    try:
        data = schema.load(request.get_json())  # Valida y carga datos JSON
    except ValidationError as err:
        return jsonify({
            "error_code": "VALIDATION_ERROR",
            "message": "Error de validación",
            "errors": err.messages,
            "http_status": HTTPStatus.BAD_REQUEST.value
        }), HTTPStatus.BAD_REQUEST

    # 2. Normalizar y validar el nombre del proyecto
    nombre_proyecto = data['nombre'].strip()  # Elimina espacios en blanco
    
    if not nombre_proyecto:
        return jsonify({
            "error_code": "EMPTY_NAME",
            "message": "El nombre del proyecto no puede estar vacío",
            "http_status": HTTPStatus.BAD_REQUEST.value
        }), HTTPStatus.BAD_REQUEST

    # 3. Validar que el nombre sea único (case-insensitive)
    proyecto_existente = Proyecto.query.filter(
        db.func.lower(Proyecto.nombre) == db.func.lower(nombre_proyecto),
        Proyecto.propietario_id == usuario_id
    ).first()

    if proyecto_existente:
        return jsonify({
            "error_code": "DUPLICATE_PROJECT",
            "message": f"Ya existe un proyecto con el nombre '{nombre_proyecto}'",
            "http_status": HTTPStatus.CONFLICT.value,
            "existing_project_id": proyecto_existente.id
        }), HTTPStatus.CONFLICT

    # 4. Crear el proyecto 
    try:
        with db.session.begin_nested():  # Transacción anidada
            proyecto = Proyecto(
                nombre=nombre_proyecto,
                descripcion=data.get('descripcion', ''),
                propietario_id=usuario_id
            )
            db.session.add(proyecto)
            db.session.flush()  # Flush para obtener ID

            # Crear miembro como admin del proyecto
            miembro = MiembroProyecto(
                usuario_id=usuario_id,
                proyecto_id=proyecto.id,
                rol='admin'
            )
            db.session.add(miembro)

        # 5. Retornar respuesta serializada
        return jsonify({
            "code": "PROJECT_CREATED",
            "message": "Proyecto creado exitosamente",
            "data": schema.dump(proyecto),
            "http_status": HTTPStatus.CREATED.value
        }), HTTPStatus.CREATED

    except Exception as e:
        db.session.rollback()  # Rollback en caso de error
        current_app.logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        return jsonify({
            "error_code": "INTERNAL_ERROR",
            "message": "Error interno del servidor"
        }), HTTPStatus.INTERNAL_SERVER_ERROR

# Endpoint para listar proyectos del usuario
@project_bp.route('/', methods=['GET'])
@jwt_required()
@log_operacion("LISTADO_PROYECTOS", nivel='info')
def listar_proyectos():
    try:
        usuario_id = get_jwt_identity()
        estado = request.args.get('estado')  # Filtro opcional por estado
        
        # Consulta base: proyectos donde el usuario es miembro
        query = Proyecto.query.filter(
            Proyecto.miembros.any(usuario_id=usuario_id)
        )
        
        if estado:
            query = query.filter_by(estado=estado)  # Aplicar filtro de estado
            
        proyectos = query.all()

        return jsonify({
            "proyectos": [{
                "id": p.id,
                "nombre": p.nombre,
                "estado": p.estado,
                "descripcion": p.descripcion
            } for p in proyectos]
        }), HTTPStatus.OK

    except Exception as e:
        current_app.logger.error(f"Error: {str(e)}")
        return jsonify({"error": "Internal server error"}), HTTPStatus.INTERNAL_SERVER_ERROR

# Endpoint para ver detalles de un proyecto específico
@project_bp.route('/<int:id>', methods=['GET'])
@jwt_required()
@log_operacion("DETALLE_PROYECTO", nivel='info', registrar_db=False)
def ver_proyecto(id):
    try:
        usuario_id = get_jwt_identity()
        
        # Verificar acceso al proyecto
        miembro = db.session.scalar(select(MiembroProyecto).filter_by(
            usuario_id=usuario_id, 
            proyecto_id=id
        ))
        if not miembro:
            raise PermissionError("No tienes acceso a este proyecto")

        # Obtener proyecto
        proyecto = Proyecto.query.get_or_404(id)
        
        return jsonify({
            "code": SuccessCodes.SUCCESS,
            "proyecto": {
                **proyecto.to_dict(),
                "miembros": [{
                    "usuario_id": m.usuario_id, 
                    "rol": m.rol, 
                    "nombre": getattr(m.usuario, 'nombre', '')
                } for m in proyecto.miembros]
            },
            "access_info": {
                "tu_rol": miembro.rol,
                "fecha_acceso": datetime.utcnow().isoformat()
            },
            "http_status": HTTPStatus.OK.value
        }), HTTPStatus.OK

    except PermissionError as e:
        current_app.logger.warning(f"Acceso denegado al proyecto {id} - Usuario: {usuario_id}")
        return jsonify({
            "error_code": CollaboratorErrorCodes.USER_NOT_COLLABORATOR,
            "message": str(e),
            "http_status": HTTPStatus.FORBIDDEN.value
        }), HTTPStatus.FORBIDDEN
        
    except NotFound:
        return jsonify({
            "error_code": ProjectErrorCodes.PROJECT_NOT_FOUND,
            "message": "El proyecto solicitado no existe",
            "http_status": HTTPStatus.NOT_FOUND.value
        }), HTTPStatus.NOT_FOUND
        
    except SQLAlchemyError as e:
        current_app.logger.error(f"Error de DB al obtener proyecto {id}: {str(e)}")
        return jsonify({
            "error_code": SystemErrorCodes.DATABASE_ERROR,
            "message": "Error al acceder a los datos del proyecto",
            "http_status": HTTPStatus.INTERNAL_SERVER_ERROR.value
        }), HTTPStatus.INTERNAL_SERVER_ERROR
        
    except Exception as e:
        current_app.logger.error(f"Error inesperado en proyecto {id}: {str(e)}", exc_info=True)
        return jsonify({
            "error_code": SystemErrorCodes.INTERNAL_SERVER_ERROR,
            "message": "Error interno al procesar la solicitud",
            "http_status": HTTPStatus.INTERNAL_SERVER_ERROR.value
        }), HTTPStatus.INTERNAL_SERVER_ERROR

# Endpoint para actualizar un proyecto existente
@project_bp.route('/<int:id>', methods=['PUT'])
@jwt_required()
@log_operacion("ACTUALIZACION_PROYECTO", nivel='info', registrar_db=True)
def actualizar_proyecto(id):
    usuario_id = get_jwt_identity()
    
    try:
        # 1. Verificación de permisos (solo admin puede actualizar)
        miembro = MiembroProyecto.query.filter_by(
            usuario_id=usuario_id,
            proyecto_id=id,
            rol='admin'
        ).first()

        if not miembro:
            raise PermissionError("Se requieren privilegios de administrador")

        # 2. Validación de datos
        if not request.is_json:
            return jsonify({
                "error_code": SystemErrorCodes.INVALID_REQUEST_FORMAT,
                "message": "El contenido debe ser JSON",
                "http_status": HTTPStatus.BAD_REQUEST.value
            }), HTTPStatus.BAD_REQUEST

        data = request.get_json()
        
        # Validar campos permitidos
        campos_permitidos = {'nombre', 'descripcion'}
        campos_invalidos = set(data.keys()) - campos_permitidos
        
        if campos_invalidos:
            return jsonify({
                "error_code": ProjectErrorCodes.INVALID_PROJECT_NAME,
                "message": f"Campos no permitidos: {', '.join(campos_invalidos)}",
                "http_status": HTTPStatus.BAD_REQUEST.value
            }), HTTPStatus.BAD_REQUEST

        # Validar longitud del nombre (3-100 caracteres)
        if 'nombre' in data:
            if len(data['nombre']) < 3:
                return jsonify({
                    "error_code": ProjectErrorCodes.INVALID_PROJECT_NAME_LENGTH,
                    "message": "El nombre debe tener al menos 3 caracteres",
                    "http_status": HTTPStatus.BAD_REQUEST.value
                }), HTTPStatus.BAD_REQUEST
            if len(data['nombre']) > 100:
                return jsonify({
                    "error_code": ProjectErrorCodes.INVALID_PROJECT_NAME_LENGTH,
                    "message": "El nombre no puede exceder 100 caracteres",
                    "http_status": HTTPStatus.BAD_REQUEST.value
                }), HTTPStatus.BAD_REQUEST

        # 3. Obtener proyecto
        proyecto = Proyecto.query.get_or_404(id)

        # 4. Detección de cambios
        cambios = {}
        for field in campos_permitidos:
            if field in data and data[field] != getattr(proyecto, field):
                cambios[field] = {
                    'valor_anterior': getattr(proyecto, field),
                    'valor_nuevo': data[field]
                }

        if not cambios:
            return jsonify({
                "code": SuccessCodes.SUCCESS,
                "message": "No se detectaron cambios para actualizar",
                "http_status": HTTPStatus.OK.value
            }), HTTPStatus.OK

        # 5. Aplicar cambios
        for field, values in cambios.items():
            setattr(proyecto, field, values['valor_nuevo'])

        db.session.commit()

        # 6. Respuesta exitosa
        return jsonify({
            "code": SuccessCodes.PROJECT_UPDATED,
            "message": "Proyecto actualizado exitosamente",
            "proyecto_id": proyecto.id,
            "cambios": cambios,
            "http_status": HTTPStatus.OK.value
        }), HTTPStatus.OK

    except PermissionError as e:
        current_app.logger.warning(
            f"Acceso no autorizado a actualizar proyecto {id}",
            extra={'usuario_id': usuario_id, 'proyecto_id': id}
        )
        return jsonify({
            "error_code": CollaboratorErrorCodes.INSUFFICIENT_PERMISSIONS,
            "message": str(e),
            "http_status": HTTPStatus.FORBIDDEN.value
        }), HTTPStatus.FORBIDDEN

    except NotFound:
        return jsonify({
            "error_code": ProjectErrorCodes.PROJECT_NOT_FOUND,
            "message": "El proyecto no existe",
            "http_status": HTTPStatus.NOT_FOUND.value
        }), HTTPStatus.NOT_FOUND

    except SQLAlchemyError as e:
        db.session.rollback()
        current_app.logger.error(f"Error de DB al actualizar proyecto {id}: {str(e)}")
        return jsonify({
            "error_code": SystemErrorCodes.DATABASE_ERROR,
            "message": "Error al guardar los cambios",
            "http_status": HTTPStatus.INTERNAL_SERVER_ERROR.value
        }), HTTPStatus.INTERNAL_SERVER_ERROR

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error inesperado: {str(e)}", exc_info=True)
        return jsonify({
            "error_code": SystemErrorCodes.INTERNAL_SERVER_ERROR,
            "message": "Error interno al procesar la solicitud",
            "http_status": HTTPStatus.INTERNAL_SERVER_ERROR.value
        }), HTTPStatus.INTERNAL_SERVER_ERROR

# Endpoint para eliminar un proyecto
@project_bp.route('/<int:id>', methods=['DELETE'])
@jwt_required()
@log_operacion("ELIMINACION_PROYECTO", nivel='info', registrar_db=True)
def eliminar_proyecto(id):
    usuario_id = int(get_jwt_identity())
    proyecto_id = id
    g.proyecto_data = None  # Para auditoría

    try:
        # 1. Obtener proyecto para auditoría
        proyecto = Proyecto.query.get(proyecto_id)
        if not proyecto:
            return jsonify({
                "http_status": HTTPStatus.NOT_FOUND.value,
                "status": "error",
                "code": ProjectErrorCodes.PROJECT_NOT_FOUND,
                "error": "Proyecto no encontrado",
                "proyecto_id": proyecto_id,
                "timestamp": datetime.utcnow().isoformat()
            }), HTTPStatus.NOT_FOUND

        # Guardar datos para auditoría
        g.proyecto_data = {
            "nombre": proyecto.nombre,
            "propietario_id": proyecto.propietario_id,
            "estado": proyecto.estado,
            "miembros": MiembroProyecto.query.filter_by(proyecto_id=proyecto_id).count(),
            "tareas": Tarea.query.filter_by(proyecto_id=proyecto_id).count()
        }

        # 2. Verificar permisos
        miembro = MiembroProyecto.query.filter_by(
            proyecto_id=proyecto_id,
            usuario_id=usuario_id
        ).first()

        es_propietario = usuario_id == proyecto.propietario_id
        es_admin = miembro and miembro.rol == 'admin'
        
        if not (es_propietario or es_admin):
            return jsonify({
                "http_status": HTTPStatus.FORBIDDEN.value,
                "status": "error",
                "code": CollaboratorErrorCodes.INSUFFICIENT_PERMISSIONS,
                "error": "Acceso denegado",
                "details": {
                    "requerido": "admin o propietario",
                    "rol_actual": miembro.rol if miembro else "no miembro"
                },
                "proyecto_id": proyecto_id
            }), HTTPStatus.FORBIDDEN

        # 3. Validar estado del proyecto
        if proyecto.estado == "completado":
            return jsonify({
                "http_status": HTTPStatus.BAD_REQUEST.value,
                "status": "error",
                "code": ProjectErrorCodes.PROJECT_ALREADY_COMPLETED,
                "error": "Proyecto completado",
                "details": "No se pueden eliminar proyectos completados",
                "solucion": "Cambie el estado antes de eliminar",
                "proyecto_id": proyecto_id
            }), HTTPStatus.BAD_REQUEST

        # 4. Eliminación en transacción
        with db.session.begin_nested():
            # Eliminar relaciones primero (tareas y miembros)
            Tarea.query.filter_by(proyecto_id=proyecto_id).delete()
            MiembroProyecto.query.filter_by(proyecto_id=proyecto_id).delete()
            
            # Eliminar proyecto
            db.session.delete(proyecto)
        
        db.session.commit()

        # 5. Respuesta exitosa
        return jsonify({
            "http_status": HTTPStatus.OK.value,
            "status": "success",
            "code": SuccessCodes.PROJECT_DELETED,
            "message": "Proyecto eliminado exitosamente",
            "proyecto_id": proyecto_id,
            "metadata": {
                **g.proyecto_data,
                "eliminado_por": "admin" if es_admin else "propietario",
                "deleted_at": datetime.utcnow().isoformat()
            }
        }), HTTPStatus.OK

    except SQLAlchemyError as e:
        db.session.rollback()
        current_app.logger.error(
            f"Error de DB eliminando proyecto {proyecto_id}",
            exc_info=True,
            extra={
                "usuario": usuario_id,
                "error": str(e),
                "proyecto_data": g.proyecto_data
            }
        )
        return jsonify({
            "http_status": HTTPStatus.INTERNAL_SERVER_ERROR.value,
            "status": "error",
            "code": SystemErrorCodes.DATABASE_ERROR,
            "error": "Error de base de datos",
            "details": "No se completó la eliminación",
            "proyecto_id": proyecto_id
        }), HTTPStatus.INTERNAL_SERVER_ERROR
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(
            f"Error inesperado eliminando proyecto {proyecto_id}",
            exc_info=True,
            extra={
                "usuario": usuario_id,
                "error": str(e),
                "proyecto_data": g.proyecto_data
            }
        )
        return jsonify({
            "http_status": HTTPStatus.INTERNAL_SERVER_ERROR.value,
            "status": "error",
            "code": SystemErrorCodes.INTERNAL_SERVER_ERROR,
            "error": "Error interno",
            "details": "Error inesperado durante la eliminación",
            "proyecto_id": proyecto_id
        }), HTTPStatus.INTERNAL_SERVER_ERROR

# Endpoint para agregar un miembro a un proyecto
@project_bp.route('/<int:proyecto_id>/add_member', methods=['POST'])
@jwt_required()
@log_operacion(
    "AGREGAR_MIEMBRO",
    nivel='info',
    registrar_db=True
)
def agregar_colaborador(proyecto_id):
    usuario_admin_id = get_jwt_identity()
    
    try:
        # 1. Validación inicial del request
        if not request.is_json:
            return jsonify({
                "http_status": HTTPStatus.BAD_REQUEST.value,
                "status": "error",
                "code": SystemErrorCodes.INVALID_REQUEST_FORMAT,
                "error": "Formato inválido",
                "details": "El contenido debe ser JSON",
                "metadata": {
                    "content_type": request.content_type,
                    "proyecto_id": proyecto_id
                }
            }), HTTPStatus.BAD_REQUEST

        data = request.get_json()
        
        # 2. Validación de campos requeridos
        if 'usuario_id' not in data:
            return jsonify({
                "http_status": HTTPStatus.BAD_REQUEST.value,
                "status": "error",
                "code": ProjectErrorCodes.MISSING_REQUIRED_FIELDS,
                "error": "Campo requerido faltante",
                "details": "El campo 'usuario_id' es obligatorio",
                "metadata": {
                    "campos_requeridos": ["usuario_id"],
                    "campos_recibidos": list(data.keys()),
                    "proyecto_id": proyecto_id
                }
            }), HTTPStatus.BAD_REQUEST

        # 3. Iniciar transacción
        db.session.begin_nested()

        # 4. Verificación de permisos de admin
        admin = MiembroProyecto.query.filter_by(
            usuario_id=usuario_admin_id,
            proyecto_id=proyecto_id,
            rol='admin'
        ).first()

        if not admin:
            db.session.rollback()
            return jsonify({
                "http_status": HTTPStatus.FORBIDDEN.value,
                "status": "error",
                "code": CollaboratorErrorCodes.INSUFFICIENT_PERMISSIONS,
                "error": "Permisos insuficientes",
                "details": "Se requieren privilegios de administrador",
                "metadata": {
                    "usuario_intento": usuario_admin_id,
                    "proyecto_id": proyecto_id
                }
            }), HTTPStatus.FORBIDDEN

        # 5. Validación de rol
        rol = data.get('rol', 'colaborador')
        if rol not in {'admin', 'colaborador'}:
            db.session.rollback()
            return jsonify({
                "http_status": HTTPStatus.BAD_REQUEST.value,
                "status": "error",
                "code": CollaboratorErrorCodes.INVALID_ROLE,
                "error": "Rol no válido",
                "details": f"Rol proporcionado: {rol}",
                "metadata": {
                    "roles_permitidos": ["admin", "colaborador"],
                    "proyecto_id": proyecto_id
                }
            }), HTTPStatus.BAD_REQUEST

        # 6. Verificar si ya es miembro
        if MiembroProyecto.query.filter_by(
            usuario_id=data['usuario_id'],
            proyecto_id=proyecto_id
        ).first():
            db.session.rollback()
            return jsonify({
                "http_status": HTTPStatus.BAD_REQUEST.value,
                "status": "error",
                "code": CollaboratorErrorCodes.USER_ALREADY_ADDED,
                "error": "Usuario ya es miembro",
                "details": "El usuario ya pertenece al proyecto",
                "metadata": {
                    "usuario_id": data['usuario_id'],
                    "proyecto_id": proyecto_id
                }
            }), HTTPStatus.BAD_REQUEST

        # 7. Verificar existencia del usuario
        if not Usuario.query.get(data['usuario_id']):
            db.session.rollback()
            return jsonify({
                "http_status": HTTPStatus.NOT_FOUND.value,
                "status": "error",
                "code": CollaboratorErrorCodes.USER_NOT_FOUND,
                "error": "Usuario no encontrado",
                "details": "El ID de usuario no existe",
                "metadata": {
                    "usuario_id": data['usuario_id'],
                    "proyecto_id": proyecto_id
                }
            }), HTTPStatus.NOT_FOUND

        # 8. Crear nuevo miembro
        nuevo_miembro = MiembroProyecto(
            usuario_id=data['usuario_id'],
            proyecto_id=proyecto_id,
            rol=rol
        )

        db.session.add(nuevo_miembro)
        db.session.commit()

        # 9. Obtener datos para respuesta
        proyecto = Proyecto.query.get(proyecto_id)
        usuario = Usuario.query.get(data['usuario_id'])

        return jsonify({
            "http_status": HTTPStatus.CREATED.value,
            "status": "success",
            "code": SuccessCodes.MEMBER_ADDED,
            "message": "Miembro agregado exitosamente",
            "data": {
                "proyecto": {
                    "id": proyecto.id,
                    "nombre": proyecto.nombre
                },
                "miembro": {
                    "id": nuevo_miembro.usuario_id,
                    "nombre": usuario.nombre,
                    "rol": nuevo_miembro.rol,
                }
            },
            "metadata": {
                "agregado_por": usuario_admin_id,
                "timestamp": datetime.utcnow().isoformat()
            }
        }), HTTPStatus.CREATED

    except SQLAlchemyError as e:
        db.session.rollback()
        current_app.logger.error(
            f"Error de DB al agregar miembro al proyecto {proyecto_id}",
            exc_info=True,
            extra={
                "usuario_admin": usuario_admin_id,
                "error": str(e)
            }
        )
        return jsonify({
            "http_status": HTTPStatus.INTERNAL_SERVER_ERROR.value,
            "status": "error",
            "code": SystemErrorCodes.DATABASE_ERROR,
            "error": "Error de base de datos",
            "details": "No se pudo completar la operación",
            "metadata": {
                "proyecto_id": proyecto_id,
                "operacion": "agregar_miembro"
            }
        }), HTTPStatus.INTERNAL_SERVER_ERROR
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(
            f"Error inesperado al agregar miembro al proyecto {proyecto_id}",
            exc_info=True,
            extra={
                "usuario_admin": usuario_admin_id,
                "error": str(e)
            }
        )
        return jsonify({
            "http_status": HTTPStatus.INTERNAL_SERVER_ERROR.value,
            "status": "error",
            "code": SystemErrorCodes.INTERNAL_SERVER_ERROR,
            "error": "Error interno",
            "details": "Ocurrió un error inesperado",
            "metadata": {
                "proyecto_id": proyecto_id,
                "trace_id": request.headers.get('X-Request-ID')
            }
        }), HTTPStatus.INTERNAL_SERVER_ERROR

# Endpoint para crear una nueva tarea en un proyecto
@project_bp.route('/<int:proyecto_id>/tasks', methods=['POST'])
@jwt_required()
@log_operacion(accion="create_task", nivel='info', registrar_db=True)
def crear_tarea(proyecto_id):
    usuario_id = get_jwt_identity()

    try:
        # 1. Verificación de permisos
        miembro = MiembroProyecto.query.filter_by(
            usuario_id=usuario_id, 
            proyecto_id=proyecto_id
        ).first()

        if not miembro:
            return jsonify({
                "error": "No tienes acceso a este proyecto",
                "codigo_error": CollaboratorErrorCodes.USER_NOT_COLLABORATOR  
            }), HTTPStatus.FORBIDDEN
        
        # Validación con esquema
        schema = TareaSchema()
        json_data = request.get_json()
        
        try:
            data = schema.load(request.get_json())
            data = schema.load(json_data)
        except ValidationError as err:
            return jsonify({
                "error": "Datos de tarea inválidos",
                "detalles": err.messages,
                "codigo_error": TaskErrorCodes.INVALID_TASK_DATA
            }), HTTPStatus.BAD_REQUEST

        # 3. Verificación de tarea duplicada
        tarea_existente = Tarea.query.filter_by(
            titulo=data['titulo'], 
            proyecto_id=proyecto_id
        ).first()

        if tarea_existente:
            return jsonify({
                "error": "Ya existe una tarea con este título en el proyecto",
                "codigo_error": TaskErrorCodes.DUPLICATE_TASK  
            }), HTTPStatus.BAD_REQUEST

        # 4. Creación de la tarea
        tarea = Tarea(
            titulo=data['titulo'],
            descripcion=data['descripcion'],
            proyecto_id=proyecto_id,
            asignado_a_id=data.get('asignado_a_id'),
            estado="pendiente",
            creador_id=usuario_id,
            subject=data.get('subject')  # Campo opcional
        )

        db.session.add(tarea)
        db.session.commit()

        # Serializar la respuesta
        response_data = schema.dump(tarea)

        # 5. Respuesta exitosa
        return jsonify({
            "tarea_id": tarea.id,
            "http_status": HTTPStatus.CREATED.value,
            "mensaje": "Tarea creada correctamente",
            "codigo_exito": SuccessCodes.TASK_CREATED, 
            "data": response_data
        }), HTTPStatus.CREATED

    except Exception as e:
        db.session.rollback()
        print(f"Error inesperado: {str(e)}")
        return jsonify({
            "error": "Error interno al crear la tarea",
            "detalles": str(e),
            "codigo_error": SystemErrorCodes.INTERNAL_SERVER_ERROR  
        }), HTTPStatus.INTERNAL_SERVER_ERROR

# Endpoint para listar tareas de un proyecto
@project_bp.route('/<int:proyecto_id>/tasks', methods=['GET'])
@jwt_required()
@log_operacion(accion="list_tasks", nivel='info', registrar_db=False)
def listar_tareas(proyecto_id):
    usuario_id = get_jwt_identity()

    try:
        # Verificación de permisos
        if not MiembroProyecto.query.filter_by(usuario_id=usuario_id, proyecto_id=proyecto_id).first():
            return jsonify({
                "error": "No tienes acceso a este proyecto",
                "proyecto_id": proyecto_id,
                "data": None
            }), 403

        # Obtención de tareas
        tareas = Tarea.query.filter_by(proyecto_id=proyecto_id).all()

        # Estructura compatible con el decorador
        return jsonify({
            "data": [{
                "titulo": tarea.titulo,
                "descripcion": tarea.descripcion,
                "asignado_a": tarea.asignado_a_id,
                "tarea_id": tarea.id, 
                "proyecto_id": proyecto_id
            } for tarea in tareas],
            "proyecto_id": proyecto_id
        }), 200

    except Exception as exc:
        return jsonify({
            "error": str(exc),
            "proyecto_id": proyecto_id,
            "data": None
        }), 500

# Endpoint para actualizar una tarea existente
@project_bp.route('/<int:proyecto_id>/tasks/<int:tarea_id>', methods=['PUT'])
@jwt_required()
@log_operacion(accion="update_task", nivel='info', registrar_db=True)
def actualizar_tarea(proyecto_id, tarea_id):
    try:
        # 1. Validación de formato JSON
        if not request.is_json:
            return jsonify({
                "error": "Se requiere formato JSON",
                "codigo_error": SystemErrorCodes.INVALID_REQUEST_FORMAT,
                "metadata": {
                    "content_type": request.content_type,
                    "proyecto_id": proyecto_id,
                    "tarea_id": tarea_id
                }
            }), HTTPStatus.BAD_REQUEST

        data = request.get_json()
        if not data:
            return jsonify({
                "error": "Datos no proporcionados",
                "codigo_error": ProjectErrorCodes.MISSING_REQUIRED_FIELDS,
                "metadata": {
                    "campos_esperados": ["titulo", "descripcion", "asignado_a_id"],
                    "proyecto_id": proyecto_id
                }
            }), HTTPStatus.BAD_REQUEST

        # 2. Validación de cambio de estado incorrecto
        if 'estado' in data:
            return jsonify({
                "error": "Para cambiar el estado use el endpoint específico",
                "codigo_error": TaskErrorCodes.INVALID_STATUS_TRANSITION,
                "metadata": {
                    "endpoint_correcto": f"/projects/{proyecto_id}/tasks/{tarea_id}/status",
                    "proyecto_id": proyecto_id
                }
            }), HTTPStatus.BAD_REQUEST

        usuario_id = get_jwt_identity()
        
        # 3. Verificación de permisos
        miembro = MiembroProyecto.query.filter_by(
            usuario_id=usuario_id,
            proyecto_id=proyecto_id
        ).first()

        if not miembro:
            return jsonify({
                "error": "Acceso denegado",
                "codigo_error": CollaboratorErrorCodes.USER_NOT_COLLABORATOR,
                "metadata": {
                    "usuario_id": usuario_id,
                    "proyecto_id": proyecto_id,
                    "tarea_id": tarea_id
                }
            }), HTTPStatus.FORBIDDEN

        # 4. Obtención de tarea
        tarea = Tarea.query.filter_by(
            id=tarea_id,
            proyecto_id=proyecto_id
        ).first()

        if not tarea:
            return jsonify({
                "error": "Tarea no encontrada",
                "codigo_error": TaskErrorCodes.TASK_NOT_FOUND,
                "metadata": {
                    "proyecto_id": proyecto_id,
                    "tarea_id": tarea_id
                }
            }), HTTPStatus.NOT_FOUND

        # 5. Registro de cambios previos
        cambios = {}
        if 'titulo' in data:
            if not data['titulo'] or not isinstance(data['titulo'], str):
                return jsonify({
                    "error": "Título no válido",
                    "codigo_error": ProjectErrorCodes.INVALID_PROJECT_NAME,
                    "metadata": {
                        "valor_recibido": data['titulo'],
                        "tipo_esperado": "string no vacío"
                    }
                }), HTTPStatus.BAD_REQUEST
            cambios['titulo'] = {"anterior": tarea.titulo, "nuevo": data['titulo'].strip()}
            tarea.titulo = cambios['titulo']['nuevo']

        if 'descripcion' in data:
            if not isinstance(data['descripcion'], str):
                return jsonify({
                    "error": "Descripción no válida",
                    "codigo_error": TaskErrorCodes.INVALID_TASK_DESCRIPTION,
                    "metadata": {
                        "valor_recibido": data['descripcion'],
                        "tipo_esperado": "string"
                    }
                }), HTTPStatus.BAD_REQUEST
            cambios['descripcion'] = {"anterior": tarea.descripcion, "nuevo": data['descripcion'].strip()}
            tarea.descripcion = cambios['descripcion']['nuevo']

        # 6. Procesamiento de reasignación
        if 'asignado_a_id' in data:
            if data['asignado_a_id'] is not None:
                if not isinstance(data['asignado_a_id'], int):
                    return jsonify({
                        "error": "ID de asignación debe ser entero",
                        "codigo_error": CollaboratorErrorCodes.INVALID_USER_ID,
                        "metadata": {
                            "valor_recibido": data['asignado_a_id'],
                            "tipo_esperado": "integer"
                        }
                    }), HTTPStatus.BAD_REQUEST
                
                asignado_valido = MiembroProyecto.query.filter_by(
                    usuario_id=data['asignado_a_id'],
                    proyecto_id=proyecto_id
                ).first()
                
                if not asignado_valido:
                    return jsonify({
                        "error": "El usuario asignado no es miembro del proyecto",
                        "codigo_error": CollaboratorErrorCodes.USER_NOT_COLLABORATOR,
                        "metadata": {
                            "usuario_asignado": data['asignado_a_id'],
                            "proyecto_id": proyecto_id
                        }
                    }), HTTPStatus.BAD_REQUEST

            if miembro.rol == 'admin':
                cambios['asignado_a_id'] = {
                    "anterior": tarea.asignado_a_id,
                    "nuevo": data['asignado_a_id'],
                    "changed_by_admin": True
                }
                tarea.asignado_a_id = data['asignado_a_id']
                
                if tarea.estado == EstadoTarea.EN_PROGRESO.value:
                    cambios['estado'] = {
                        "anterior": tarea.estado,
                        "nuevo": EstadoTarea.PENDIENTE.value,
                        "reason": "Reasignación por admin"
                    }
                    tarea.estado = EstadoTarea.PENDIENTE.value
                    
            elif tarea.asignado_a_id != usuario_id:
                return jsonify({
                    "error": "Solo el administrador puede reasignar tareas de otros usuarios",
                    "codigo_error": CollaboratorErrorCodes.INSUFFICIENT_PERMISSIONS,
                    "metadata": {
                        "rol_requerido": "admin",
                        "rol_actual": miembro.rol
                    }
                }), HTTPStatus.FORBIDDEN

        # 7. Aplicar actualización
        tarea.actualizado_en = datetime.utcnow()
        db.session.commit()

        return jsonify({
            "mensaje": "Tarea actualizada correctamente",
            "codigo_exito": SuccessCodes.TASK_UPDATED,
            "http_status": HTTPStatus.OK.value,
            "tarea": {
                "id": tarea_id,
                "titulo": tarea.titulo,
                "descripcion": tarea.descripcion,
                "asignado_a_id": tarea.asignado_a_id,
                "project_id": tarea.proyecto_id,
                "actualizado_en": tarea.actualizado_en.isoformat()
            },
            "changes": cambios,
            "metadata": {
                "proyecto_id": proyecto_id,
                "usuario_actualizacion": usuario_id,
                "timestamp": datetime.utcnow().isoformat()
            }
        }), HTTPStatus.OK
    
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "error": "Error interno del servidor",
            "codigo_error": SystemErrorCodes.INTERNAL_SERVER_ERROR,
            "metadata": {
                "proyecto_id": proyecto_id,
                "tarea_id": tarea_id,
                "timestamp": datetime.utcnow().isoformat()
            }
        }), HTTPStatus.INTERNAL_SERVER_ERROR

# Endpoint para cambiar el estado de una tarea
@project_bp.route('/<int:proyecto_id>/tasks/<int:tarea_id>/status', methods=['PUT'])
@jwt_required()
@log_operacion(accion="change_task_status", nivel='info', registrar_db=True)
def cambiar_estado_tarea(proyecto_id, tarea_id):
    usuario_id = int(get_jwt_identity())
    
    try:
        # 1. Validación básica del request
        if not request.is_json:
            return jsonify({
                "http_status": HTTPStatus.BAD_REQUEST.value,
                "error": "Se requiere formato JSON",
                "code": SystemErrorCodes.INVALID_REQUEST_FORMAT,
                "metadata": {
                    "content_type": request.content_type,
                    "proyecto_id": proyecto_id,
                    "tarea_id": tarea_id
                }
            }), HTTPStatus.BAD_REQUEST

        data = request.get_json()
        nuevo_estado = data.get('estado')
        
        if not nuevo_estado:
            return jsonify({
                "http_status": HTTPStatus.BAD_REQUEST.value,
                "error": "El campo 'estado' es requerido",
                "code": ProjectErrorCodes.MISSING_REQUIRED_FIELDS,
                "metadata": {
                    "campos_requeridos": ["estado"],
                    "campos_recibidos": list(data.keys()) if data else [],
                    "proyecto_id": proyecto_id
                }
            }), HTTPStatus.BAD_REQUEST

        # 2. Verificar que el estado sea válido
        if nuevo_estado not in [e.value for e in EstadoTarea]:
            return jsonify({
                "http_status": HTTPStatus.BAD_REQUEST.value,
                "error": f"Estado no válido. Estados permitidos: {[e.value for e in EstadoTarea]}",
                "code": TaskErrorCodes.INVALID_STATUS_TRANSITION,
                "metadata": {
                    "estado_recibido": nuevo_estado,
                    "estados_permitidos": [e.value for e in EstadoTarea],
                    "proyecto_id": proyecto_id,
                    "tarea_id": tarea_id
                }
            }), HTTPStatus.BAD_REQUEST

        # 3. Verificar permisos en el proyecto
        miembro = MiembroProyecto.query.filter_by(
            usuario_id=usuario_id,
            proyecto_id=proyecto_id
        ).first()
        
        if not miembro:
            return jsonify({
                "http_status": HTTPStatus.FORBIDDEN.value,
                "error": "No tienes acceso a este proyecto",
                "code": CollaboratorErrorCodes.USER_NOT_COLLABORATOR,
                "metadata": {
                    "usuario_id": usuario_id,
                    "proyecto_id": proyecto_id,
                    "tarea_id": tarea_id
                }
            }), HTTPStatus.FORBIDDEN

        # 4. Obtener la tarea con bloqueo para evitar condiciones de carrera
        tarea = Tarea.query.filter_by(
            id=tarea_id,
            proyecto_id=proyecto_id
        ).with_for_update().first()
        
        if not tarea:
            return jsonify({
                "http_status": HTTPStatus.NOT_FOUND.value,
                "error": "Tarea no encontrada",
                "code": TaskErrorCodes.TASK_NOT_FOUND,
                "metadata": {
                    "proyecto_id": proyecto_id,
                    "tarea_id": tarea_id
                }
            }), HTTPStatus.NOT_FOUND

        # 5. Validaciones específicas de estado
        es_admin = miembro.rol == 'admin'
        estado_anterior = tarea.estado

        # Validar si el usuario puede cambiar el estado
        if nuevo_estado == EstadoTarea.COMPLETADO.value:
            if tarea.asignado_a_id is None:
                return jsonify({
                    "http_status": HTTPStatus.BAD_REQUEST.value,
                    "error": "La tarea no está asignada a nadie",
                    "code": TaskErrorCodes.CANNOT_COMPLETE_UNASSIGNED,
                    "metadata": {
                        "proyecto_id": proyecto_id,
                        "tarea_id": tarea_id
                    }
                }), HTTPStatus.BAD_REQUEST
            
            if not es_admin and tarea.asignado_a_id != usuario_id:
                return jsonify({
                    "http_status": HTTPStatus.FORBIDDEN.value,
                    "error": "Solo el asignado o un admin pueden completar la tarea",
                    "code": CollaboratorErrorCodes.INSUFFICIENT_PERMISSIONS,
                    "metadata": {
                        "usuario_intento": usuario_id,
                        "usuario_asignado": tarea.asignado_a_id,
                        "es_admin": es_admin,
                        "proyecto_id": proyecto_id
                    }
                }), HTTPStatus.FORBIDDEN

        # 6. Realizar el cambio de estado
        tarea.estado = nuevo_estado
        tarea.actualizado_en = datetime.utcnow()
        
        # Manejo de estados especiales
        if nuevo_estado == EstadoTarea.COMPLETADO.value:
            tarea.fecha_completado = datetime.utcnow()
            tarea.completado_por_id = usuario_id
        elif estado_anterior == EstadoTarea.COMPLETADO.value:
            tarea.fecha_completado = None
            tarea.completado_por_id = None
        
        # 7. Verificar y actualizar estado del proyecto automáticamente
        proyecto_actualizado = verificar_estado_proyecto(proyecto_id)
        if not proyecto_actualizado:
            current_app.logger.warning(f"No se pudo actualizar estado del proyecto {proyecto_id}")

        # 8. Verificar si el proyecto puede marcarse como completado (para feedback)
        puede_finalizar, mensaje_finalizacion = puede_finalizar_proyecto(proyecto_id)
        
        db.session.commit()
        
        # 9. Preparar respuesta
        response_data = {
            "http_status": HTTPStatus.OK.value,
            "status": "success",
            "code": SuccessCodes.TASK_COMPLETED if nuevo_estado == EstadoTarea.COMPLETADO.value else SuccessCodes.TASK_UPDATED,
            "mensaje": "Estado actualizado correctamente",
            "data": {
                "tarea": {
                    "id": tarea.id,
                    "titulo": tarea.titulo,
                    "estado_anterior": estado_anterior.value,
                    "estado_actual": tarea.estado.value,
                    "asignado_a": tarea.asignado_a_id,
                    "ultima_actualizacion": tarea.actualizado_en.isoformat(),
                    "fecha_completado": tarea.fecha_completado.isoformat() if tarea.fecha_completado else None
                },
                "proyecto": {
                    "id": proyecto_id,
                    "estado_actual": Proyecto.query.get(proyecto_id).estado,
                    "puede_finalizar": puede_finalizar,
                    "mensaje_finalizacion": mensaje_finalizacion if not puede_finalizar else None
                }
            },
            "metadata": {
                "changed_by_admin": es_admin,
                "usuario_id": usuario_id,
                "timestamp": datetime.utcnow().isoformat()
            }
        }

        return jsonify(response_data), HTTPStatus.OK
    
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(
            f"Error cambiando estado de tarea {tarea_id} en proyecto {proyecto_id}: {str(e)}",
            exc_info=True,
            extra={
                "usuario_id": usuario_id,
                "proyecto_id": proyecto_id,
                "tarea_id": tarea_id
            }
        )
        return jsonify({
            "http_status": HTTPStatus.INTERNAL_SERVER_ERROR.value,
            "status": "error",
            "code": SystemErrorCodes.INTERNAL_SERVER_ERROR,
            "error": "Error interno del servidor",
            "details": str(e),
            "metadata": {
                "proyecto_id": proyecto_id,
                "tarea_id": tarea_id,
                "timestamp": datetime.utcnow().isoformat()
            }
        }), HTTPStatus.INTERNAL_SERVER_ERROR

# Endpoint para eliminar una tarea
@project_bp.route('/<int:proyecto_id>/tasks/<int:tarea_id>', methods=['DELETE'])
@jwt_required()
@log_operacion(accion="delete_task", nivel='info', registrar_db=True)
def eliminar_tarea(proyecto_id, tarea_id):
    usuario_id = get_jwt_identity()

    try:
        # Verifica si el usuario tiene acceso al proyecto
        miembro = MiembroProyecto.query.filter_by(usuario_id=usuario_id, proyecto_id=proyecto_id).first()
        if not miembro:
            return jsonify({
                "http_status": HTTPStatus.FORBIDDEN.value,
                "error": "No tienes acceso a este proyecto"
            }), HTTPStatus.FORBIDDEN
        
        # Obtener la tarea
        tarea = Tarea.query.filter_by(id=tarea_id, proyecto_id=proyecto_id).first()
        if not tarea:
            return jsonify({
                "http_status": HTTPStatus.NOT_FOUND.value,
                "error": "La tarea no existe"
            }), HTTPStatus.NOT_FOUND
        
        # Verifica permiso (solo admin puede eliminar)
        if miembro.rol != 'admin':
            return jsonify({
                "http_status": HTTPStatus.FORBIDDEN.value,
                "error": "No tienes permisos para eliminar esta tarea"
            }), HTTPStatus.FORBIDDEN
        
        # Elimina la tarea
        db.session.delete(tarea)
        db.session.commit()

        return jsonify({
            "http_status": HTTPStatus.OK.value,
            "mensaje": "Tarea eliminada correctamente",
            "tarea_id": tarea_id,
            "proyecto_id": proyecto_id,
            "deleted_at": datetime.utcnow().isoformat(),
            "metadata": {
                "usuario_id": usuario_id,
                "timestamp": datetime.utcnow().isoformat()
            }
        }), HTTPStatus.OK

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "http_status": HTTPStatus.INTERNAL_SERVER_ERROR.value,
            "error": "Error al eliminar la tarea",
            "detalle": str(e),
            "metadata": {
                "proyecto_id": proyecto_id,
                "tarea_id": tarea_id,
                "timestamp": datetime.utcnow().isoformat()
            }
        }), HTTPStatus.INTERNAL_SERVER_ERROR

# Endpoint para marcar un proyecto como completado
@project_bp.route('/<int:proyecto_id>/complete', methods=['PUT'])
@jwt_required()
@log_operacion(accion="complete_project", nivel='info', registrar_db=True)
def finalizar_proyecto(proyecto_id):
    usuario_id = get_jwt_identity()
    
    try:
        # 1. Validación de formato JSON
        if not request.is_json:
            return jsonify({
                "http_status": HTTPStatus.BAD_REQUEST.value,
                "code": SystemErrorCodes.INVALID_REQUEST_FORMAT,
                "error": "Se requiere formato JSON",
                "metadata": {
                    "content_type": request.content_type,
                    "proyecto_id": proyecto_id
                }
            }), HTTPStatus.BAD_REQUEST

        data = request.get_json()
        forzar = data.get('forzar', False)

        # 2. Obtener proyecto
        proyecto = Proyecto.query.get(proyecto_id)
        if not proyecto:
            return jsonify({
                "http_status": HTTPStatus.NOT_FOUND.value,
                "code": ProjectErrorCodes.PROJECT_NOT_FOUND,
                "error": "Proyecto no encontrado",
                "metadata": {
                    "proyecto_id": proyecto_id,
                    "usuario_id": usuario_id
                }
            }), HTTPStatus.NOT_FOUND

        # 3. Verificar permisos
        miembro = MiembroProyecto.query.filter_by(
            usuario_id=usuario_id, 
            proyecto_id=proyecto_id
        ).first()

        if not miembro or miembro.rol not in ['admin', 'propietario']:
            return jsonify({
                "http_status": HTTPStatus.FORBIDDEN.value,
                "code": CollaboratorErrorCodes.INSUFFICIENT_PERMISSIONS,
                "error": "Permisos insuficientes",
                "details": "Se requieren privilegios de administrador o propietario",
                "metadata": {
                    "rol_requerido": ["admin", "propietario"],
                    "rol_actual": miembro.rol if miembro else None,
                    "usuario_id": usuario_id
                }
            }), HTTPStatus.FORBIDDEN

        # 4. Validar si puede completarse
        puede_finalizar, mensaje = puede_finalizar_proyecto(proyecto_id)
        if not puede_finalizar and not forzar:
            return jsonify({
                "http_status": HTTPStatus.BAD_REQUEST.value,
                "code": ProjectErrorCodes.UNFINISHED_TASKS,
                "error": "No se puede completar el proyecto",
                "details": mensaje,
                "solucion": "Complete las tareas pendientes o use el parámetro 'forzar'",
                "metadata": {
                    "proyecto_id": proyecto_id,
                    "tareas_pendientes": [t.id for t in proyecto.tareas if t.estado != EstadoTarea.COMPLETADO]
                }
            }), HTTPStatus.BAD_REQUEST

        # 5. Completar proyecto
        proyecto.estado = 'completado'
        proyecto.fecha_completado = datetime.utcnow()
        proyecto.completado_por_id = usuario_id

        # 6. Manejar tareas pendientes si se fuerza
        tareas_afectadas = 0
        if forzar:
            for tarea in proyecto.tareas:
                if tarea.estado != EstadoTarea.COMPLETADO:
                    tarea.estado = EstadoTarea.CANCELADA
                    tarea.actualizado_en = datetime.utcnow()
                    tareas_afectadas += 1

        db.session.commit()

        # 7. Preparar respuesta exitosa
        return jsonify({
            "http_status": HTTPStatus.OK.value,
            "code": SuccessCodes.PROJECT_COMPLETED,
            "message": "Proyecto completado exitosamente",
            "data": {
                "proyecto": {
                    "id": proyecto.id,
                    "nombre": proyecto.nombre,
                    "estado": proyecto.estado,
                    "fecha_completado": proyecto.fecha_completado.isoformat(),
                    "completado_por": usuario_id
                },
                "tareas": {
                    "canceladas": tareas_afectadas,
                    "total": len(proyecto.tareas)
                }
            },
            "metadata": {
                "forzado": forzar,
                "usuario_id": usuario_id,
                "timestamp": datetime.utcnow().isoformat()
            }
        }), HTTPStatus.OK

    except SQLAlchemyError as e:
        db.session.rollback()
        current_app.logger.error(
            f"Error de base de datos al completar proyecto {proyecto_id}",
            exc_info=True,
            extra={
                "usuario_id": usuario_id,
                "proyecto_id": proyecto_id,
                "error": str(e)
            }
        )
        return jsonify({
            "http_status": HTTPStatus.INTERNAL_SERVER_ERROR.value,
            "code": SystemErrorCodes.DATABASE_ERROR,
            "error": "Error de base de datos",
            "details": "No se pudo completar la operación",
            "metadata": {
                "proyecto_id": proyecto_id,
                "timestamp": datetime.utcnow().isoformat()
            }
        }), HTTPStatus.INTERNAL_SERVER_ERROR
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(
            f"Error inesperado al completar proyecto {proyecto_id}",
            exc_info=True,
            extra={
                "usuario_id": usuario_id,
                "proyecto_id": proyecto_id,
                "error": str(e)
            }
        )
        return jsonify({
            "http_status": HTTPStatus.INTERNAL_SERVER_ERROR.value,
            "code": SystemErrorCodes.INTERNAL_SERVER_ERROR,
            "error": "Error interno",
            "details": "Ocurrió un error inesperado al completar el proyecto",
            "metadata": {
                "proyecto_id": proyecto_id,
                "timestamp": datetime.utcnow().isoformat()
            }
        }), HTTPStatus.INTERNAL_SERVER_ERROR

# Endpoint para obtener métricas detalladas del sistema
@project_bp.route('/metrics/detailed-stats', methods=['GET'])
@jwt_required()
def obtener_metricas_detalladas():
    usuario_id = get_jwt_identity()
    
    try:
        # Proyectos por estado
        proyectos_por_estado = db.session.query(
            Proyecto.estado,
            db.func.count(Proyecto.id)
        ).filter_by(propietario_id=usuario_id
        ).group_by(Proyecto.estado).all()

        # Tareas por estado en proyectos propios
        tareas_propias_por_estado = db.session.query(
            Tarea.estado,
            db.func.count(Tarea.id)
        ).join(Proyecto).filter(
            Proyecto.propietario_id == usuario_id
        ).group_by(Tarea.estado).all()

        # Tareas asignadas por estado
        tareas_asignadas_por_estado = db.session.query(
            Tarea.estado,
            db.func.count(Tarea.id)
        ).filter(
            Tarea.asignado_a_id == usuario_id
        ).group_by(Tarea.estado).all()

        # Proyectos donde colabora
        proyectos_colaboracion = db.session.query(
            Proyecto.estado,
            db.func.count(Proyecto.id)
        ).join(MiembroProyecto).filter(
            MiembroProyecto.usuario_id == usuario_id,
            Proyecto.propietario_id != usuario_id
        ).group_by(Proyecto.estado).all()

        return jsonify({
            "estado_http": HTTPStatus.OK.value,
            "code": SuccessCodes.SUCCESS,
            "datos": {
                "id_usuario": usuario_id,
                "proyectos": {
                    "total_por_estado": dict(proyectos_por_estado),
                    "proyectos_colaboracion": sum(count for _, count in proyectos_colaboracion)
                },
                "tareas": {
                    "creadas_por_estado": dict(tareas_propias_por_estado),
                    "asignadas_por_estado": dict(tareas_asignadas_por_estado)
                },
                "estadisticas": {
                    "proyectos_activos": next((count for status, count in proyectos_por_estado if status == 'activo'), 0),
                    "proyectos_completados": next((count for status, count in proyectos_por_estado if status == 'completado'), 0),
                    "tareas_pendientes": next((count for status, count in tareas_asignadas_por_estado if status == 'pendiente'), 0),
                    "tareas_completadas": next((count for status, count in tareas_asignadas_por_estado if status == 'completada'), 0)
                }
            },
            "marca_tiempo": datetime.utcnow().isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Error en métricas detalladas: {str(e)}", exc_info=True)
        return jsonify({
            "http_status": HTTPStatus.INTERNAL_SERVER_ERROR.value,
            "status": "error",
            "message": "Error al generar métricas detalladas"
        }), HTTPStatus.INTERNAL_SERVER_ERROR