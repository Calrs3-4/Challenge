# app1/extensions.py
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_marshmallow import Marshmallow

db = SQLAlchemy(session_options={"autoflush": False})
bcrypt = Bcrypt()
jwt = JWTManager()
migrate = Migrate()
ma = Marshmallow()