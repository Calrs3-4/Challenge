from marshmallow import fields, validate
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from flask_marshmallow import Marshmallow
from app1.models import Proyecto, MiembroProyecto, Tarea

from app1 import ma, db
ma = Marshmallow()


class MiembroProyectoSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = MiembroProyecto
        sqla_session = db.session
        include_fk = True

class ProjectSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Proyecto
        sqla_session = db.session
        include_fk = True
    
    # Campos básicos que coinciden con tus tests
    id = fields.Int(dump_only=True)
    nombre = fields.Str(
        required=True,
        validate=validate.Length(min=3, max=100, error="El nombre debe tener entre 3 y 100 caracteres")
    )
    descripcion = fields.Str(validate=validate.Length(max=500))
    propietario_id = fields.Int(dump_only=True)
    
    # Campos de fecha formateados
    fecha_creacion = fields.DateTime(format='iso', dump_only=True)
    fecha_actualizacion = fields.DateTime(format='iso', dump_only=True)
    
    # Relación con miembros (opcional, pero útil)
    miembros = fields.Nested(MiembroProyectoSchema, many=True, dump_only=True)
    
    # Campo calculado para el total de miembros
    total_miembros = fields.Function(lambda obj: len(obj.miembros))


from marshmallow import EXCLUDE


class TareaSchema(ma.Schema):
    class Meta:
        unknown = EXCLUDE
    
    titulo = ma.String(
        required=True,
        validate=[
            validate.Length(min=1, max=255, error="Título debe tener entre 1 y 255 caracteres"),
            validate.Regexp(r'^[\w\sáéíóúñÁÉÍÓÚÑ.,-]+$', error="Título contiene caracteres inválidos")
        ]
    )
    descripcion = ma.String(
        required=True,
        validate=validate.Length(min=1, error="Descripción no puede estar vacía")
    )
    asignado_a_id = ma.Integer(allow_none=True)
    subject = ma.String(
        required=False,
        allow_none=True,
        validate=validate.Length(max=100)
    )
    # Solo incluye campos que realmente existen en tu modelo