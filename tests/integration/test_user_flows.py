import pytest
import time  # Asegúrate de tener esta importación
from werkzeug.http import parse_cookie, dump_cookie
from app1.models import Usuario
from app1 import db

class TestUserFlows:
    """Pruebas de flujos completos de usuario"""

    def test_full_auth_flow(self, client, app):
        """Prueba registro -> login -> acceso"""
        with app.app_context():
            unique_email = f"flow_{int(time.time())}@example.com"

            # 1. Registro
            register_data = {
                "nombre": "Flow User",
                "email": unique_email,
                "password": "FlowPass123"
            }
            response = client.post('/auth', json=register_data)
            assert response.status_code == 201

            # 2. Login
            login_data = {"email": unique_email, "password": "FlowPass123"}
            response = client.post('/auth/login', json=login_data)

            # Verificaciones actualizadas
            assert response.status_code == 200
            assert response.json["status"] == "success"
            assert "user" in response.json["data"]
            assert response.json["data"]["user"]["email"] == unique_email

            # Verificar que los tokens están en las cookies (forma correcta)
            cookies = response.headers.get_all('Set-Cookie')
            assert any('access_token' in cookie for cookie in cookies)
            assert any('refresh_token' in cookie for cookie in cookies)