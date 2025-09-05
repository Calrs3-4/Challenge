from flask import Blueprint, request, jsonify,make_response
# from werkzeug.security import generate_password_hash, check_password_hash
# from flask_bcrypt import generate_password_hash
from flask_jwt_extended import create_access_token, set_access_cookies, create_refresh_token, set_refresh_cookies
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_jwt_extended.exceptions import JWTExtendedException, NoAuthorizationError, InvalidHeaderError, WrongTokenError, RevokedTokenError
from flask import jsonify
# from flask import session
from .models import Usuario
from datetime import timedelta
from error_code import AuthErrorCodes, SuccessCodes
from . import db
import jwt

from http import HTTPStatus
import datetime
from app1.constants import TokenFields,UserFields
from flask import current_app 
from sqlalchemy.exc import SQLAlchemyError
import re
from error_code import SuccessCodes
# from utils import log_registro_usuario, log_inicio_sesion

"=====================creando=============================="
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))  # Asegura que Python encuentra app1

from app1.constants import TokenFields, UserFields

"=========================lll==============================="


auth_bp = Blueprint('auth', __name__)
SECRET_KEY = "Admin781"

@auth_bp.route('/', methods=['POST'])
# @log_registro_usuario
def registro():
    try:
        # Validación básica
        if not request.is_json:
            return jsonify({"error": "Se requiere JSON", "code": "INVALID_FORMAT"}), 400

        data = request.get_json()
        current_app.logger.debug(f"Datos recibidos: {data}")

        # Validación de campos
        required_fields = ['nombre', 'email', 'password']
        if missing := [f for f in required_fields if f not in data]:
            return jsonify({
                "error": f"Faltan campos: {', '.join(missing)}",
                "code": "MISSING_FIELDS"
            }), 400

        # Normalización
        nombre = data['nombre'].strip()
        email = data['email'].lower().strip()
        password = data['password']

        # Validación de email
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return jsonify({
                "error": "Email inválido",
                "code": "INVALID_EMAIL"
            }), 400

        # Verificar email único
        if Usuario.query.filter_by(email=email).first():
            return jsonify({
                "error": "Email ya registrado",
                "code": "EMAIL_EXISTS"
            }), 409

        # Crear usuario (sin password inicialmente)
        nuevo_usuario = Usuario(
            nombre=nombre,
            email=email,
            rol='usuario'
        )
        
        # Establecer contraseña
        nuevo_usuario.set_password(password)
        
        # Validación final
        nuevo_usuario.validate_password()

        # Guardar en BD
        db.session.add(nuevo_usuario)
        db.session.commit()

        return jsonify({
            "message": "Registro exitoso",
            "user": {
                "id": nuevo_usuario.id,
                "nombre": nuevo_usuario.nombre,
                "email": nuevo_usuario.email,
                "rol": nuevo_usuario.rol
            },
            "code": SuccessCodes.LOGIN_SUCCESS
        }), 201

    except ValueError as e:
        db.session.rollback()
        return jsonify({
            "error": str(e),
            "code": "VALIDATION_ERROR"
        }), 400
        
    except SQLAlchemyError as e:
        db.session.rollback()
        current_app.logger.error(f"Error de BD: {str(e)}")
        return jsonify({
            "error": "Error en la base de datos",
            "code": "DB_ERROR"
        }), 500
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error inesperado: {str(e)}")
        return jsonify({
            "error": "Error interno del servidor",
            "code": "SERVER_ERROR"
        }), 500



@auth_bp.route('/login', methods=['POST'])
# @log_inicio_sesion
def login():
    # 1. Validar que es JSON
    if not request.is_json:
        response = jsonify({
            "status": "error",
            "code": HTTPStatus.BAD_REQUEST,
            "error": {
                "type": "INVALID_REQUEST",
                "message": "El contenido debe ser JSON"
            }
        })
        response.status_code = HTTPStatus.BAD_REQUEST
        return response  # Return explícito

    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        # 2. Validar campos requeridos
        if not email or not password:
            response = jsonify({
                "status": "error",
                "code": HTTPStatus.BAD_REQUEST,
                "error": {
                    "type": "MISSING_FIELDS",
                    "message": "Email y contraseña son requeridos"
                }
            })
            response.status_code = HTTPStatus.BAD_REQUEST
            return response

        # 3. Buscar usuario
        usuario = Usuario.query.filter_by(email=email).first()

        # 4. Validar credenciales
        if not usuario or not usuario.check_password(password):
            response = jsonify({
                "status": "error",
                "code": HTTPStatus.UNAUTHORIZED,
                "error": {
                    "type": "AUTHENTICATION_FAILED",
                    "message": "Credenciales inválidas"
                }
            })
            response.status_code = HTTPStatus.UNAUTHORIZED
            return response

        # 5. Generar tokens
        access_token = create_access_token(identity=str(usuario.id))
        refresh_token = create_refresh_token(identity=str(usuario.id))
        expires_in = current_app.config.get('JWT_ACCESS_TOKEN_EXPIRES', timedelta(hours=1)).total_seconds()

        # 6. Construir respuesta
        response_data = {
            "status": "success",
            "code": HTTPStatus.OK,
            "data": {
                "user": {
                    "id": usuario.id,
                    "email": usuario.email,
                    "name": usuario.nombre,
                    "role": usuario.rol
                }
            }
        }

        response = make_response(jsonify(response_data))
        response.status_code = HTTPStatus.OK

        # Configurar cookies
        response.set_cookie(
            key='access_token',
            value=access_token,
            httponly=True,
            secure=current_app.config.get('SECURE_COOKIES', False),
            samesite='Lax',
            path='/',
            max_age=int(expires_in)
        )
        response.set_cookie(
            key='refresh_token',
            value=refresh_token,
            httponly=True,
            secure=current_app.config.get('SECURE_COOKIES', False),
            samesite='Lax',
            path='/auth/refresh'
        )

        return response

    except Exception as e:
        current_app.logger.error(f"Error en login: {str(e)}", exc_info=True)
        response = jsonify({
            "status": "error",
            "code": HTTPStatus.INTERNAL_SERVER_ERROR,
            "error": {
                "type": "SERVER_ERROR",
                "message": "Error en el servidor"
            }
        })
        response.status_code = HTTPStatus.INTERNAL_SERVER_ERROR
        return response

    
@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    try:
        # 1. Obtener identidad del usuario desde el refresh token
        current_user = get_jwt_identity()
        
        # 2. Validar que se obtuvo la identidad
        if not current_user:
            error_data = {
                "error_code": AuthErrorCodes.REFRESH_FAILED,
                "message": "No se pudo obtener la identidad del usuario",
                "http_status": HTTPStatus.UNAUTHORIZED
            }
            response = make_response(jsonify(error_data))
            response.status_code = HTTPStatus.UNAUTHORIZED
            return response

        # 3. Generar nuevo access token
        new_access_token = create_access_token(identity=current_user)

        # 4. Configurar la respuesta
        response_data = {
            "code": "TOKEN_REFRESHED",
            "message": "Access token renovado exitosamente",
            "http_status": HTTPStatus.OK
        }
        response = make_response(jsonify(response_data))
        response.status_code = HTTPStatus.OK

        # 5. Configurar la cookie del access token
        expires_in = current_app.config.get('JWT_ACCESS_TOKEN_EXPIRES', timedelta(hours=1)).total_seconds()
        response.set_cookie(
            key='access_token',
            value=new_access_token,
            httponly=True,
            secure=current_app.config.get('SECURE_COOKIES', False),
            samesite='Lax',
            path='/',
            max_age=int(expires_in)
        )
        
        return response

    except NoAuthorizationError as e:
        error_data = {
            "error_code": AuthErrorCodes.INVALID_CREDENTIALS,
            "message": "Token no proporcionado",
            "http_status": HTTPStatus.UNAUTHORIZED
        }
        return make_response(jsonify(error_data)), HTTPStatus.UNAUTHORIZED

    except (WrongTokenError, RevokedTokenError) as e:
        error_data = {
            "error_code": AuthErrorCodes.INVALID_CREDENTIALS,
            "message": "Token inválido o revocado",
            "http_status": HTTPStatus.UNAUTHORIZED
        }
        return make_response(jsonify(error_data)), HTTPStatus.UNAUTHORIZED

    except Exception as e:
        current_app.logger.error(f"Error inesperado en refresh: {str(e)}")
        error_data = {
            "error_code": AuthErrorCodes.INTERNAL_SERVER_ERROR,
            "message": "Error interno del servidor",
            "http_status": HTTPStatus.INTERNAL_SERVER_ERROR
        }
        return make_response(jsonify(error_data)), HTTPStatus.INTERNAL_SERVER_ERROR

# Ruta para refrescar el token
# @auth_bp.route('/refresh', methods=['POST'])
# @jwt_required(refresh=True)  # Requiere un refresh token válido
# def refresh():
#     usuario_id = get_jwt_identity()  # Obtiene el ID del usuario desde el refresh token

#     # Crear un nuevo access token
#     new_access_token = create_access_token(identity=usuario_id)

#     return jsonify({
#         "mensaje": "Token refrescado",
#         "token": new_access_token  # Nuevo token de acceso
#     }), 200


# @auth_bp.route('/logout', methods=['GET','POST'])
# @jwt_required()  # Asegura que el usuario esté autenticado para poder cerrar sesión
# def logout():
#     # Obtiene la identidad del usuario actual (en este caso, el ID del usuario)
#     user_id = get_jwt_identity()

#     #redirige
#     respuesta = make_response(redirect(url_for('auth.login')))

#     # Eliminar las cookies de JWT
#     unset_jwt_cookies(respuesta)

#     flash('Sesión cerrada exitosamente', 'success')
#     return respuesta


# @auth_bp.route('/refresh', methods=['POST'])
# @jwt_required(refresh=True)  # Solo se permite con un refresh token válido
# def refresh():
#     usuario_id = get_jwt_identity()  # Obtener el ID del usuario desde el refresh token
#     access_token = create_access_token(identity=usuario_id)  # Crear un nuevo access token
#     return jsonify(access_token=access_token), 200
