import sys
from pathlib import Path
import os

# Configuración inicial
sys.path.append(str(Path(__file__).parent))
from app1 import create_app
from app1.config import Config, ProductionConfig

# Determinar entorno
if os.getenv('FLASK_ENV') == 'production':
    app = create_app(ProductionConfig)
else:
    app = create_app(Config)

if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_ENV') != 'production')