import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'Admin781')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///challenge.db')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'Admin781')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PROPAGATE_EXCEPTIONS = True

class ProductionConfig(Config):
    FLASK_ENV = 'production'
    DEBUG = False
    TESTING = False
    # Para PostgreSQL en producción (Heroku usa DATABASE_URL)
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', '').replace('postgres://', 'postgresql://')
    
    # Configuración de producción
    PREFERRED_URL_SCHEME = 'https'
    SERVER_NAME = os.getenv('SERVER_NAME', None)