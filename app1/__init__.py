from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from .config import Config
import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import timedelta, datetime, timezone
from dotenv import load_dotenv
from flask_restx import Namespace, Resource, fields
import os
from .extensions import db, bcrypt, jwt, migrate, ma


import json

# Inicialización de extensiones (fuera de create_app para evitar duplicaciones)
# db = SQLAlchemy(session_options={"autoflush": False})
# bcrypt = Bcrypt()
# jwt = JWTManager()
# migrate = Migrate()
# ma = Marshmallow()



def configure_logging(app):
    """Configuración centralizada de logging con JSON estructurado y consola"""
    try:
        os.makedirs('logs', exist_ok=True, mode=0o755)
    except OSError as e:
        logging.error(f"Error creando carpeta logs: {str(e)}")
        return

    class AuditLogFormatter(logging.Formatter):
        """Formateador especial para logs de auditoría con estructura JSON"""
        def format(self, record):
            log_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "message": record.getMessage(),
                "module": record.module,
                "line": record.lineno,
                "endpoint": getattr(record, 'endpoint', None),
                "method": getattr(record, 'method', None),
                "user_id": getattr(record, 'user_id', None),
                "entity_type": getattr(record, 'entity_type', None),
                "entity_id": getattr(record, 'entity_id', None),
                "status_code": getattr(record, 'status_code', None),
                "ip": getattr(record, 'ip', None),
                **getattr(record, "audit_data", {})
            }
            return json.dumps(log_entry, ensure_ascii=False)

    # Formateadores
    json_formatter = AuditLogFormatter()
    console_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s'
    )

    # --- Handlers ---
    # 1. Handler principal (INFO + WARNING)
    info_handler = RotatingFileHandler(
        'logs/flask_app.log',
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding='utf-8'
    )
    info_handler.setLevel(logging.INFO)
    info_handler.setFormatter(json_formatter)
    info_handler.addFilter(lambda record: record.levelno <= logging.WARNING)

    # 2. Handler de errores (ERROR + CRITICAL)
    error_handler = RotatingFileHandler(
        'logs/flask_errors.log',
        maxBytes=10 * 1024 * 1024,
        backupCount=2,
        encoding='utf-8'
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(json_formatter)

    # 3. Handler de consola (solo en desarrollo)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if app.debug else logging.INFO)
    console_handler.setFormatter(console_formatter)

    # --- Configuración de la aplicación ---
    # Eliminar handlers por defecto si existen
    for handler in list(app.logger.handlers):
        app.logger.removeHandler(handler)
    
    app.logger.setLevel(logging.DEBUG if app.debug else logging.INFO)
    app.logger.addHandler(info_handler)
    app.logger.addHandler(error_handler)
    app.logger.addHandler(console_handler)

    # Configuración de librerías externas
    if not app.debug:
        # Werkzeug (servidor)
        werkzeug_logger = logging.getLogger('werkzeug')
        werkzeug_logger.setLevel(logging.WARNING)
        werkzeug_handler = RotatingFileHandler('logs/flask_app.log')
        werkzeug_handler.setFormatter(json_formatter)
        werkzeug_logger.addHandler(werkzeug_handler)
        
        # SQLAlchemy
        logging.getLogger('sqlalchemy').setLevel(logging.WARNING)
        logging.getLogger('sqlalchemy.engine').setLevel(logging.ERROR)
        
        # Otras librerías
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('requests').setLevel(logging.WARNING)

    # Mensaje inicial
    app.logger.info("Configuración de logging inicializada correctamente", extra={
        "audit_data": {
            "app_name": app.name,
            "debug_mode": app.debug,
            "log_handlers": [h.__class__.__name__ for h in app.logger.handlers]
        }
    })


    
def create_app(config_class=None):
    """Factory principal de la aplicación Flask"""
    app = Flask(__name__)
    app.url_map.strict_slashes = False
    
    # Cargar configuración
    if config_class:
        app.config.from_object(config_class)
    else:
        from .config import Config  # ← Importar aquí
        app.config.from_object(Config)
    # app.config['SQLALCHEMY_ECHO'] = True


    # =============================================
    # Configuración Principal de JWT (Cookies)
    # =============================================
    

    # Configuración JWT - Modo híbrido (cookies y headers)
    app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']  # Aceptar ambos métodos
    app.config['JWT_SECRET_KEY'] = 'Admin781'  # Debe ser consistente

    # Configuración de cookies (mantén tu configuración actual)
    app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token'
    app.config['JWT_REFRESH_COOKIE_NAME'] = 'refresh_token'
    app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
    app.config['JWT_REFRESH_COOKIE_PATH'] = '/auth/refresh'
    app.config['JWT_COOKIE_SECURE'] = False
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False
    app.config['JWT_COOKIE_SAMESITE'] = 'Lax'

    # Configuración de headers
    app.config['JWT_HEADER_NAME'] = 'Authorization'
    app.config['JWT_HEADER_TYPE'] = 'Bearer'

    # Tiempos de expiración
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)

    # JUSTO DESPUÉS DE LAS OTRAS CONFIGURACIONES JWT
    app.config.update({
        'JWT_VALIDATE_CSRF': False,  # Desactiva validaciones CSRF
        'JWT_VALIDATE_SUBMITTED_JSON': False,  # Nueva en v4.4+
        'JWT_CSRF_IN_COOKIES': False  # Redundancia para seguridad
    })
    from marshmallow import EXCLUDE

    # Inicializar extensiones con la app
    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db)
    # ma = Marshmallow()
    ma.init_app(app)
    app.config["MARSHMALLOW_STRICT"] = False
    app.config["MARSHMALLOW_VALIDATE"] = False
    app.config["MARSHMALLOW_UNDEFINED"] = EXCLUDE 

    # Registrar blueprints
    from .auth import auth_bp
    from .routes import project_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(project_bp, url_prefix='/projects')

    #Configuración Swagger (sin importar nada de swagger_docs.py)
    from flask_restx import Api
    api = Api(
        app,
        version='1.0',
        title='API Proyectos',
        description='Documentación API',
        doc='/swagger-ui',  # Usa esta ruta
        # prefix='/api',
        validate=True,
        security='Bearer Auth',
        authorizations={
            'Bearer Auth': {
                'type': 'apiKey',
                'in': 'header',
                'name': 'Authorization',
                'description': 'Usar: Bearer <access_token>'
            }
        }
    )

    # Define los namespaces DIRECTAMENTE aquí para evitar importaciones circulares
    projects_ns = api.namespace('Projects', description='Operaciones con proyectos', path='/projects')
    tasks_ns = api.namespace('Tasks', description='Operaciones con tareas', path='/projects/<int:proyecto_id>/tasks')
    collab_ns = Namespace('Collaborators', description='Gestión de colaboradores', path='/<int:proyecto_id>/add_member')
    metrics_ns = Namespace('Metrics', description='Métricas del sistema', path='/metrics')
    auth_ns = api.namespace('Auth', description='Operaciones de autenticación')


    
    api.add_namespace(collab_ns)
    api.add_namespace(metrics_ns)



    # Modelo para la solicitud de registro
    registro_model = api.model('Registro', {
        'nombre': fields.String(required=True, description='Nombre completo'),
        'email': fields.String(required=True, description='Email válido'),
        'password': fields.String(required=True, description='Contraseña')
    })
    
    # registro_response_model = api.model('RegistroResponse', {
    #     'message': fields.String(description='Mensaje de estado'),
    #     'user': fields.Nested(api.model('User', {
    #         'id': fields.Integer,
    #         'nombre': fields.String,
    #         'email': fields.String,
    #         'rol': fields.String
    #     })),
    #     'code': fields.String(description='Código de estado')
    # })

    login_model = api.model('Login', {
    'email': fields.String(required=True),
    'password': fields.String(required=True)
    })

    # refresh_response_model = api.model('RefreshResponse', {
    # 'code': fields.String(example='TOKEN_REFRESHED'),
    # 'message': fields.String(example='Access token renovado exitosamente'),
    # 'http_status': fields.Integer(example=200)
    # })

    # Modelos (sin cambios)
    usuario_model = api.model('Usuario', {
        'id': fields.Integer,
        'nombre': fields.String,
        'email': fields.String
    })

    # login_response_model = api.model('LoginResponse', {
    #     'status': fields.String(example='success'),
    #     'code': fields.Integer(example=200),
    #     'data': fields.Nested(api.model('LoginData', {
    #         'user': fields.Nested(api.model('UserLogin', {
    #             'id': fields.Integer,
    #             'email': fields.String,
    #             'name': fields.String,
    #             'role': fields.String
    #         }))
    #     }))
    # })

    proyecto_model = api.model('Proyecto', {
        'id': fields.Integer,
        'nombre': fields.String(required=True),
        'descripcion': fields.String,
        # 'estado': fields.String,
        # 'propietario_id': fields.Integer
    })

    @auth_ns.route('/register')
    class Registro(Resource):
        @auth_ns.doc('registro')
        @auth_ns.expect(registro_model)
        @auth_ns.response(201, 'Registro exitoso')
        @auth_ns.response(400, 'Validación fallida')
        @auth_ns.response(409, 'Email ya existe')
        @auth_ns.response(500, 'Error del servidor')
        def post(self):
            """Registro de nuevo usuario"""
            pass 

    @auth_ns.route('/login')
    class Login(Resource):
        @auth_ns.doc('login')
        @auth_ns.expect(login_model)
        @auth_ns.response(200, 'Login exitoso')
        @auth_ns.response(400, 'Datos inválidos')
        @auth_ns.response(401, 'Credenciales inválidas')
        @auth_ns.response(500, 'Error del servidor')
        def post(self):
            """Inicio de sesión"""
            pass

    @auth_ns.route('/refresh')
    class Refresh(Resource):
        @auth_ns.doc('refresh', security='Bearer Auth')
        @auth_ns.response(200, 'Token refrescado')
        @auth_ns.response(401, 'Token inválido o faltante')
        @auth_ns.response(500, 'Error del servidor')
        def post(self):
            """Obtener nuevo access token usando refresh token"""
            pass

    from .models import EstadoTarea
    tarea_model = api.model('Tarea', {
        'id': fields.Integer,
        'titulo': fields.String(required=True),
        'descripcion': fields.String,
        'estado': fields.String(enum=[e.value for e in EstadoTarea]),
        'proyecto_id': fields.Integer,
        'asignado_a_id': fields.Integer
    })

    

    
    # Endpoints principales
    @projects_ns.route('/')
    class ProjectList(Resource):
        @projects_ns.doc(security='Bearer Auth')
        @projects_ns.expect(proyecto_model)
        @projects_ns.marshal_with(proyecto_model, code=201)
        def post(self):
            """Crear proyecto (POST /projects/)"""
            pass

        @projects_ns.doc(security='Bearer Auth')
        @projects_ns.marshal_list_with(proyecto_model)
        def get(self):
            """Listar proyectos (GET /projects/)"""
            pass

    @projects_ns.route('/<int:id>')
    class ProjectDetail(Resource):
        @projects_ns.doc(security='Bearer Auth')
        @projects_ns.marshal_with(proyecto_model)
        def get(self, id):
            """Ver proyecto (GET /projects/<id>)"""
            pass

        @projects_ns.doc(security='Bearer Auth')
        @projects_ns.expect(proyecto_model)
        def put(self, id):
            """Actualizar proyecto (PUT /projects/<id>)"""
            pass

        @projects_ns.doc(security='Bearer Auth')
        def delete(self, id):
            """Eliminar proyecto (DELETE /projects/<id>)"""
            pass

    # Tareas
    @tasks_ns.route('/')
    class TaskList(Resource):
        @tasks_ns.doc(security='Bearer Auth')
        @tasks_ns.expect(tarea_model)
        @tasks_ns.marshal_with(tarea_model, code=201)
        def post(self, proyecto_id):
            """Crear tarea (POST /projects/<proyecto_id>/tasks)"""
            pass

        @tasks_ns.doc(security='Bearer Auth')
        @tasks_ns.marshal_list_with(tarea_model)
        def get(self, proyecto_id):
            """Listar tareas (GET /projects/<proyecto_id>/tasks)"""
            pass

    @tasks_ns.route('/<int:tarea_id>')
    class TaskDetail(Resource):
        @tasks_ns.doc(security='Bearer Auth')
        @tasks_ns.marshal_with(tarea_model)
        def get(self, proyecto_id, tarea_id):
            """Ver tarea (GET /projects/<proyecto_id>/tasks/<tarea_id>)"""
            pass

        @tasks_ns.doc(security='Bearer Auth')
        @tasks_ns.expect(tarea_model, code=201)
        def put(self, proyecto_id, tarea_id):
            """Actualizar tarea (PUT /projects/<proyecto_id>/tasks/<tarea_id>)"""
            pass

        @tasks_ns.doc(security='Bearer Auth')
        def delete(self, proyecto_id, tarea_id):
            """Eliminar tarea (DELETE /projects/<proyecto_id>/tasks/<tarea_id>)"""
            pass

    @tasks_ns.route('/<int:tarea_id>/status')
    class TaskStatus(Resource):
        @tasks_ns.doc(security='Bearer Auth')
        @tasks_ns.expect(api.model('Estado', {'estado': fields.String(required=True)}))
        def put(self, proyecto_id, tarea_id):
            """Cambiar estado (PUT /projects/<proyecto_id>/tasks/<tarea_id>/status)"""
            pass

    # Colaboradores
    @collab_ns.route('/')
    class CollaboratorManager(Resource):
        @collab_ns.doc(security='Bearer Auth')
        def post(self, proyecto_id):
            """Agregar colaborador (POST /projects/<proyecto_id>/add_member)"""
            pass

    # Métricas
    @metrics_ns.route('/detailed-stats')
    class MetricsResource(Resource):
        @metrics_ns.doc(security='Bearer Auth')
        def get(self):
            """Obtener métricas (GET /projects/metrics/detailed-stats)"""
            pass


    # Configurar logging
    configure_logging(app)

    # Importar modelos DENTRO del contexto y después de init_app
    with app.app_context():
        from .models import Usuario, Proyecto, MiembroProyecto, Tarea, Log, EstadoTarea 
        # Importar todos los modelos
        # Crear tablas si no existen
        db.create_all()

    app.logger.info('=== Aplicación iniciada correctamente ===')
    return app