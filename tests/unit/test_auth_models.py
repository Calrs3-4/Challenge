import pytest
from app1.models import Usuario

class TestAuthModels:
    """Pruebas unitarias para modelos de autenticación"""

    def test_password_hashing(self, test_user):
        """Prueba hashing de contraseña"""
        assert test_user.check_password("TestPass123") is True
        assert test_user.check_password("WrongPassword") is False

    def test_set_password(self, db_session):
        """Prueba que set_password actualiza correctamente el hash"""
        user = Usuario(
            nombre="Test",
            email="test_setpwd@example.com",
            password="TempPass123"
        )
        db_session.add(user)
        original_hash = user.password_hash
        user.set_password("NewPassword123")
        assert user.password_hash != original_hash
        assert user.check_password("NewPassword123")

    def test_required_fields(self):
        """Prueba validación de campos requeridos"""
        with pytest.raises(ValueError):
            Usuario(email="test@example.com")  # Falta nombre
        
        with pytest.raises(ValueError):
            Usuario(nombre="Test")  # Falta email

    def test_to_dict_excludes_sensitive_data(self, test_user):
        """Prueba que to_dict no incluye información sensible"""
        user_dict = test_user.to_dict()
        assert 'password_hash' not in user_dict
        assert 'email' in user_dict  # Asumiendo que email no es sensible