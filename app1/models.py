from datetime import datetime, timezone
from enum import Enum
from app1.extensions import db
from flask_sqlalchemy import SQLAlchemy
# from flask_bcrypt import generate_password_hash, check_password_hash
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import validates
from passlib.hash import scrypt

# Clase base para herencia
class ModelBase(db.Model):
    __abstract__ = True
    id = db.Column(db.Integer, primary_key=True)
    fecha_creacion = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    fecha_actualizacion = db.Column(db.DateTime, onupdate=datetime.utcnow)

# Enums
class EstadoTarea(str, Enum):
    PENDIENTE = "pendiente"
    EN_PROGRESO = "en_progreso"
    COMPLETADO = "completado"
    BLOQUEADA = "bloqueada"
    
    CANCELADA = "cancelada"

    @classmethod
    def has_value(cls, value):
        return value in cls._value2member_map_

# Modelo Usuario
class Usuario(ModelBase):
    __tablename__ = 'usuarios'
    
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    rol = db.Column(db.String(20), nullable=False, server_default='usuario')
    
    # Relaciones
    proyectos_creados = db.relationship('Proyecto', foreign_keys='Proyecto.propietario_id', backref='propietario')
    proyectos = db.relationship('MiembroProyecto', back_populates='usuario')
    tareas_asignadas = db.relationship('Tarea', foreign_keys='Tarea.asignado_a_id', backref='asignado_a')
    tareas_creadas = db.relationship('Tarea', foreign_keys='Tarea.creador_id', backref='creador')
    
    def __init__(self, **kwargs):
        # Validación de campos requeridos
        if 'nombre' not in kwargs or not kwargs['nombre']:
            raise ValueError("El nombre es requerido")
        if 'email' not in kwargs or not kwargs['email']:
            raise ValueError("El email es requerido")
        
        # Manejo especial para password
        password = kwargs.pop('password', None)
        password_hash = kwargs.pop('password_hash', None)
        
        super().__init__(**kwargs)
        
        # Establecer contraseña si se proporcionó
        if password:
            self.set_password(password)
        elif password_hash:
            self.password_hash = password_hash
        else:
            # Permitir creación sin contraseña temporalmente
            # La validación final se hará antes de commit
            pass
    
    def validate_password(self):
        """Valida que la contraseña esté establecida"""
        if not self.password_hash:
            raise ValueError("La contraseña es requerida")
    
    def set_password(self, password):
        if not password:
            raise ValueError("La contraseña es requerida")
        if len(password) < 8:
            raise ValueError("La contraseña debe tener al menos 8 caracteres")
        self.password_hash = generate_password_hash(password)

    
    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)
    
    # def generate_token(self):
    #     """Genera un token JWT para el usuario"""
    #     return create_access_token(
    #         identity=self.id,
    #         expires_delta=timedelta(minutes=30)

    
    @validates('nombre', 'email')
    def validate_required_fields(self, key, value):
        """Validación de campos requeridos"""
        if not value or (isinstance(value, str) and not value.strip()):
            raise ValueError(f"El campo {key} es requerido")
        return value
    

    def to_dict(self, include_relations=False):
            data = {
                "id": self.id,
                "nombre": self.nombre,
                "email": self.email,
                "rol": self.rol,
                "fecha_creacion": self.fecha_creacion.isoformat() if self.fecha_creacion else None
            }
            
            if include_relations:
                data["proyectos"] = [p.to_dict() for p in self.proyectos]
                # Añade otras relaciones si son necesarias
                
            return data


# Modelo Proyecto
class Proyecto(ModelBase):
    __tablename__ = 'proyectos'
    
    nombre = db.Column(db.String(255), nullable=False)
    descripcion = db.Column(db.Text)
    propietario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    estado = db.Column(db.String(20), default='pendiente')  # Nuevo campo
    fecha_completado = db.Column(db.DateTime)  # Nuevo campo
    completado_por_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'))  # Nuevo campo
    
    # Relaciones
    
    miembros = db.relationship('MiembroProyecto', back_populates='proyecto')
    tareas = db.relationship('Tarea', backref='proyecto')

    def to_dict(self, include_relations=False):
        data = {
            "id": self.id,
            "nombre": self.nombre,
            "descripcion": self.descripcion,
            "propietario_id": self.propietario_id,
            "estado": self.estado,  # Incluido
            "porcentaje_completado": self.porcentaje_completado,  # Nueva propiedad
            "fecha_creacion": self.fecha_creacion.isoformat() if self.fecha_creacion else None,
            "fecha_actualizacion": self.fecha_actualizacion.isoformat() if self.fecha_actualizacion else None,
            "fecha_completado": self.fecha_completado.isoformat() if self.fecha_completado else None
        }
        if include_relations:
            data['tareas'] = [t.to_dict() for t in self.tareas]
        return data

    @property
    def porcentaje_completado(self):
        if not self.tareas:
            return 0
        completadas = sum(1 for t in self.tareas if t.estado == EstadoTarea.COMPLETADO)
        return round((completadas / len(self.tareas)) * 100, 2)

# Modelo MiembroProyecto
class MiembroProyecto(db.Model):
    __tablename__ = 'miembros_proyecto'
    
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id', ondelete="CASCADE"), nullable=False)
    proyecto_id = db.Column(db.Integer, db.ForeignKey('proyectos.id', ondelete="CASCADE"), nullable=False)
    rol = db.Column(db.String(10), nullable=False)
    
    # Relaciones
    usuario = db.relationship('Usuario', back_populates='proyectos')
    proyecto = db.relationship('Proyecto', back_populates='miembros')

    # __table_args__ = (
    #     db.UniqueConstraint('usuario_id', 'proyecto_id', name='uq_usuario_proyecto'),
    # )

# Modelo Tarea
class Tarea(ModelBase):
    __tablename__ = 'tareas'
    
    titulo = db.Column(db.String(255), nullable=False)
    descripcion = db.Column(db.Text)
    estado = db.Column(db.Enum(EstadoTarea), default=EstadoTarea.PENDIENTE)
    fecha_completado = db.Column(db.DateTime)
    completado_por_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'))
    proyecto_id = db.Column(db.Integer, db.ForeignKey('proyectos.id'))
    asignado_a_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'))
    creador_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    subject = db.Column(db.String(100), nullable=False, default='default-subject')


    def to_dict(self):
        return {
            "id": self.id,
            "titulo": self.titulo,
            "estado": self.estado.value,
            "proyecto_id": self.proyecto_id,
            "fecha_completado": self.fecha_completado.isoformat() if self.fecha_completado else None
        }

# Modelo Log
class Log(db.Model):
    __tablename__ = 'logs_auditoria'
    
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    proyecto_id = db.Column(db.Integer, db.ForeignKey('proyectos.id', ondelete='SET NULL'), nullable=True)
    tarea_id = db.Column(db.Integer, db.ForeignKey('tareas.id', ondelete='SET NULL'), nullable=True)
    accion = db.Column(db.String(50), nullable=False)
    detalles = db.Column(db.JSON)
    ip_origen = db.Column(db.String(45))
    user_agent = db.Column(db.String(200))
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow)
    tipo_entidad = db.Column(db.String(20))  # <-- Añade esta línea
    
    # Relaciones
    usuario = db.relationship('Usuario')
    proyecto = db.relationship('Proyecto')
    tarea = db.relationship('Tarea')