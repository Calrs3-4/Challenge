import pytest
from app1.models import Proyecto, MiembroProyecto, Usuario
from http import HTTPStatus
from sqlalchemy.exc import SQLAlchemyError
from flask_jwt_extended import create_access_token
from flask import current_app



class TestProjectRoutes:
    
    def test_crear_proyecto(self, client, test_user):
        """Prueba corregida de creación de proyecto"""
        # Login
        login_resp = client.post('/auth/login', json={
            "email": test_user.email,
            "password": "TestPass123"
        })
        assert login_resp.status_code == 200

        # Obtener token
        access_token = next(
            cookie.split('access_token=')[1].split(';')[0]
            for cookie in login_resp.headers.get_all('Set-Cookie')
            if 'access_token' in cookie
        )

        # Datos del proyecto
        project_data = {
            "nombre": "Proyecto Test",
            "descripcion": "Descripción de prueba",
            "estado": "pendiente"  # Solo si es un campo válido en tu schema
        }

        # Enviar solicitud
        response = client.post(
            '/projects',
            json=project_data,
            headers={
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
        )

        # Verificación detallada
        if response.status_code != 201:
            print(f"ERROR: {response.json}")  # Esto te mostrará el mensaje de error real

        assert response.status_code == 201
        assert response.json["data"]["nombre"] == "Proyecto Test"  # Acceder a través de "data"


    def test_crear_proyecto_sin_autenticacion(self, client):
        """Prueba sin token de acceso"""
        response = client.post(
            '/projects',
            json={"nombre": "Proyecto No Auth"}
        )

        assert response.status_code == HTTPStatus.UNAUTHORIZED
            
    def test_crear_proyecto_error_db(self, client, auth_header, monkeypatch):
        """Prueba simulando error en base de datos"""
        def mock_begin_nested(*args, **kwargs):
            raise SQLAlchemyError("Error de base de datos simulada")

        monkeypatch.setattr('app1.routes.db.session.begin_nested', mock_begin_nested)

        response = client.post(
            '/projects/',
            json={"nombre": "Proyecto Fallido"},
            headers=auth_header
        )
        
        assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
        assert response.json['error_code'] == "INTERNAL_ERROR"
    
    
    def test_listar_proyectos_filtrados(self, client, auth_header, test_project_with_member):
        response = client.get(
            '/projects',  # Sin barra final
            query_string={'estado': 'pendiente'},
            headers=auth_header
        )
        assert response.status_code == HTTPStatus.OK


    def test_crear_proyecto_datos_invalidos(self, client, auth_header):
        """Prueba con datos inválidos"""
        invalid_data = {
            "nombre": "",  # Nombre vacío debería fallar
            "descripcion": "Descripción válida"
        }

        response = client.post(
            '/projects',
            json=invalid_data,
            headers=auth_header
        )

        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert 'errors' in response.json
        assert 'nombre' in response.json['errors']

    def test_crear_proyecto_sin_autenticacion(self, client):
        """Prueba sin token de acceso"""
        response = client.post(
            '/projects',
            json={"nombre": "Proyecto No Auth"}
        )

        assert response.status_code == HTTPStatus.UNAUTHORIZED


    def test_listar_proyectos(self, client, auth_header, db_session, test_user):
        response = client.get(
            '/projects/',  # Prefijo + ruta = /projects/
            headers=auth_header
        )
        assert response.status_code == HTTPStatus.OK




class TestProjectDetailRoutes:

    def test_ver_proyecto_exitoso(self, client, auth_header, test_project_with_member):
        """Test que verifica el acceso a un proyecto donde el usuario es miembro"""
        response = client.get(
            f'/projects/{test_project_with_member.id}',
            headers=auth_header
        )
        
        assert response.status_code == HTTPStatus.OK.value
        assert response.json['proyecto']['nombre'] == "Proyecto con Miembro"
        assert response.json['access_info']['tu_rol'] == "admin"
        assert len(response.json['proyecto']['miembros']) == 1

    def test_ver_proyecto_sin_acceso(self, client, auth_header, db_session):
        """Test que verifica el acceso denegado a un proyecto no autorizado"""
        # Crear proyecto con usuario diferente
        otro_usuario = Usuario(
            nombre="Otro Usuario",
            email="otro@test.com",
            password="TestPass123"
        )
        db_session.add(otro_usuario)
        db_session.commit()
        
        proyecto = Proyecto(
            nombre="Proyecto Privado",
            propietario_id=otro_usuario.id
        )
        db_session.add(proyecto)
        db_session.commit()

        response = client.get(
            f'projects/{proyecto.id}',
            headers=auth_header
        )

        assert response.status_code == HTTPStatus.FORBIDDEN.value
        assert response.json['error_code'] == 3001

    def test_ver_proyecto_no_existente(self, client, auth_header):
        """Test para un proyecto que no existe"""
        response = client.get(
            'projects/999999',
            headers=auth_header
        )

        assert response.status_code == HTTPStatus.FORBIDDEN.value
        assert response.json['error_code'] == 3001





import pytest
from http import HTTPStatus
from sqlalchemy.exc import SQLAlchemyError
from app1.models import Proyecto, MiembroProyecto, Usuario
from error_code import (
    SuccessCodes,
    ProjectErrorCodes,
    CollaboratorErrorCodes,
    SystemErrorCodes
)

class TestUpdateProject:

    @pytest.mark.parametrize("payload,expected_status,expected_code", [
    # Casos exitosos (valores numéricos directos)
    ({"nombre": "Nuevo nombre válido"}, HTTPStatus.OK, 2202),  # SuccessCodes.PROJECT_UPDATED.value
    ({"descripcion": "Nueva descripción"}, HTTPStatus.OK, 2202),
    ({}, HTTPStatus.OK, 2000),  # SuccessCodes.SUCCESS.value
    
    # Casos de error (valores numéricos directos)
    ({"nombre": "AB"}, HTTPStatus.BAD_REQUEST, 7990),  # ProjectErrorCodes.INVALID_PROJECT_NAME_LENGTH.value
    ({"nombre": "A"*101}, HTTPStatus.BAD_REQUEST, 7990),
    ({"campo_invalido": "valor"}, HTTPStatus.BAD_REQUEST, 2010),  # ProjectErrorCodes.INVALID_PROJECT_NAME.value
    ({"nombre": "Válido", "extra": "valor"}, HTTPStatus.BAD_REQUEST, 2010),
    ])


    def test_actualizar_proyecto(self, client, auth_header, test_project_with_member,
                            payload, expected_status, expected_code):
        """Test parametrizado para diferentes casos de actualización"""
        response = client.put(
            f'/projects/{test_project_with_member.id}',
            json=payload,
            headers=auth_header
        )

        assert response.status_code == expected_status.value
        
        response_data = response.json
        if expected_status == HTTPStatus.OK:
            assert response_data['code'] == expected_code  # Sin .value
            if expected_code == 2202:  # PROJECT_UPDATED
                assert 'cambios' in response_data
                assert 'proyecto_id' in response_data
        else:
            assert response_data['error_code'] == expected_code  # Sin .value
            assert 'message' in response_data
            assert 'http_status' in response_data

    def test_actualizar_proyecto_sin_permisos(self, client, auth_header, db_session, test_user):
        """Test para usuario sin permisos de administración"""
        # Crear proyecto con miembro no admin
        proyecto = Proyecto(
            nombre="Proyecto Solo Lectura",
            propietario_id=test_user.id
        )
        
        db_session.add(proyecto)
        db_session.flush()
        
        miembro = MiembroProyecto(
            usuario_id=test_user.id,
            proyecto_id=proyecto.id,
            rol='miembro'
        )
        db_session.add(miembro)
        db_session.commit()

        response = client.put(
            f'/projects/{proyecto.id}',
            json={"nombre": "Intento de cambio"},
            headers=auth_header
        )

        assert response.status_code == HTTPStatus.FORBIDDEN.value
        assert response.json['error_code'] == 3002

    def test_actualizar_proyecto_no_existente(self, client, auth_header):
        """Test para proyecto que no existe"""
        response = client.put(
            '/projects/999999',
            json={"nombre": "No existe"},
            headers=auth_header
        )

        assert response.status_code == HTTPStatus.FORBIDDEN.value
        assert response.json['error_code'] == 3002

    def test_actualizar_proyecto_error_db(self, client, auth_header, test_project_with_member, mocker):
        """Test para error de base de datos"""
        # Mock para simular error en commit
        mock_commit = mocker.patch('sqlalchemy.orm.Session.commit')
        mock_commit.side_effect = SQLAlchemyError("DB Error")
        
        response = client.put(
            f'/projects/{test_project_with_member.id}',
            json={"nombre": "Error DB"},
            headers=auth_header
        )

        assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR.value
        assert response.json['error_code'] == 9002





class TestDeleteProject:

    def test_eliminar_proyecto_como_propietario(self, client, auth_header, db_session):
        # 1. Crear usuario propietario
        propietario = Usuario(
            nombre="Propietario Test",
            email="propietario@test.com",
            password="password123"
        )
        db_session.add(propietario)
        db_session.commit()

        # 2. Crear proyecto de prueba
        proyecto = Proyecto(
            nombre="Test Delete",
            propietario_id=propietario.id,  # Asegúrate que sea el mismo ID
            descripcion="Descripción de prueba",
            estado="pendiente"
        )
        db_session.add(proyecto)
        db_session.commit()

        # 3. Verificar relación propietario-proyecto
        print(f"Proyecto propietario_id: {proyecto.propietario_id}")
        print(f"Usuario ID: {propietario.id}")

        # 4. Crear token JWT con identidad correcta
        from flask_jwt_extended import create_access_token
        auth_header = {
            'Authorization': f'Bearer {create_access_token(identity=str(propietario.id))}'
        }

        # 5. Hacer petición DELETE
        response = client.delete(
            f'/projects/{proyecto.id}',
            headers=auth_header
        )

         # 5. Depuración
        print(f"Response status: {response.status_code}")
        print(f"Response JSON: {response.json}")

        # 6. Verificaciones
        assert response.status_code == 200
        assert response.json["code"] == SuccessCodes.PROJECT_DELETED

    def test_eliminar_proyecto_como_admin(self, client, auth_header, db_session, test_user):
        """Test que verifica eliminación por admin (no propietario)"""
        otro_usuario = Usuario(
            email="owner@test.com",
            nombre="Propietario",
            password="TestPass123"
        )
        db_session.add(otro_usuario)
        db_session.commit()
        
        proyecto = Proyecto(
            nombre="Proyecto Admin",
            propietario_id=otro_usuario.id,
            estado="activo"
        )
        db_session.add(proyecto)
        db_session.commit()
        
        miembro = MiembroProyecto(
            usuario_id=test_user.id,
            proyecto_id=proyecto.id,
            rol="admin"
        )
        db_session.add(miembro)
        db_session.commit()

        response = client.delete(
            f'/projects/{proyecto.id}',
            headers=auth_header
        )

        assert response.status_code == HTTPStatus.OK.value
        assert Proyecto.query.get(proyecto.id) is None

    def test_eliminar_proyecto_completado(self, client, auth_header, test_user, db_session):
        """Test que verifica que no se puede eliminar proyecto completado"""
        proyecto = Proyecto(
            nombre="Proyecto Completado",
            propietario_id=test_user.id,
            estado="completado"
        )
        db_session.add(proyecto)
        db_session.commit()

        response = client.delete(
            f'/projects/{proyecto.id}',
            headers=auth_header
        )

        assert response.status_code == HTTPStatus.BAD_REQUEST.value
        assert response.json['code'] == SuccessCodes.PROJECT_ALREADY_COMPLETED
        assert Proyecto.query.get(proyecto.id) is not None