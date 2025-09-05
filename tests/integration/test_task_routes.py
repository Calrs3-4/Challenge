import json
from http import HTTPStatus
from datetime import datetime
import pytest
from error_code import CollaboratorErrorCodes, ProjectErrorCodes,SystemErrorCodes,TaskErrorCodes, SuccessCodes
from app1.models import Usuario, MiembroProyecto, Proyecto, Tarea, EstadoTarea
from unittest.mock import patch
from flask_jwt_extended import create_access_token
from app1 import db
from flask_jwt_extended import get_jwt_identity
import time
from app1.models import db as _db
from sqlalchemy.exc import SQLAlchemyError

class TestAgregarColaborador:
    """Pruebas para el endpoint POST /projects/<int:proyecto_id>/add_member"""

    def test_agregar_colaborador_exitoso(self, client, auth_header, test_project, test_user, db_session):
      """Test para agregar un nuevo miembro al proyecto exitosamente"""
      # 1. Asegurar que test_user sea admin del proyecto
      miembro_admin = MiembroProyecto(
          usuario_id=test_user.id,
          proyecto_id=test_project.id,
          rol="admin"  # ¡Este rol es obligatorio según el endpoint!
      )
      db_session.add(miembro_admin)
      db_session.commit()

      # 2. Crear un nuevo usuario para agregar como colaborador
      nuevo_usuario = Usuario(nombre="Nuevo Miembro", email="nuevo@example.com")
      nuevo_usuario.set_password("password123")
      db_session.add(nuevo_usuario)
      db_session.commit()

      # 3. Datos para la solicitud POST
      data = {
          "usuario_id": nuevo_usuario.id,
          "rol": "colaborador"
      }

      # 4. Hacer la solicitud al endpoint
      response = client.post(
          f"/projects/{test_project.id}/add_member",
          headers=auth_header,
          data=json.dumps(data),
          content_type="application/json"
      )

      # 5. Verificaciones
      assert response.status_code == HTTPStatus.CREATED
      assert response.json["status"] == "success"
      assert response.json["data"]["miembro"]["id"] == nuevo_usuario.id
      assert response.json["data"]["miembro"]["rol"] == "colaborador"

      # 6. Verificar en la base de datos
      miembro = MiembroProyecto.query.filter_by(
          usuario_id=nuevo_usuario.id,
          proyecto_id=test_project.id
      ).first()
      assert miembro is not None
      assert miembro.rol == "colaborador"

    def test_agregar_colaborador_sin_permisos(self, client, auth_header, test_project, test_user, db_session):
      """Test para intentar agregar miembro sin ser admin"""
      # Crear un usuario normal (no admin)
      usuario_normal = Usuario(nombre="Usuario Normal", email="normal@example.com")
      usuario_normal.set_password("password123")
      db_session.add(usuario_normal)
      db_session.commit()

      # Crear token para usuario normal (no admin)
      from flask_jwt_extended import create_access_token
      token = create_access_token(identity=str(usuario_normal.id))
      headers = {'Authorization': f'Bearer {token}'}

      data = {
          "usuario_id": test_user.id,  # Intentar agregar a otro usuario
          "rol": "colaborador"
      }

      response = client.post(
          f"/projects/{test_project.id}/add_member",
          headers=headers,
          data=json.dumps(data),
          content_type="application/json"
      )

      assert response.status_code == HTTPStatus.FORBIDDEN
      assert response.json["status"] == "error"
      assert response.json["code"] == 3002  # Usa el valor numérico del código de error

    def test_agregar_colaborador_ya_existente(self, client, auth_header, test_project, test_user, db_session):
      """Test para agregar un miembro que ya pertenece al proyecto"""
      # 1. Asegurar que test_user es admin del proyecto
      miembro_admin = MiembroProyecto(
          usuario_id=test_user.id,
          proyecto_id=test_project.id,
          rol="admin"
      )
      db_session.add(miembro_admin)
      
      # 2. Crear y guardar el usuario existente
      usuario_existente = Usuario(nombre="Miembro Existente", email="existente@example.com")
      usuario_existente.set_password("password123")
      db_session.add(usuario_existente)
      db_session.commit()

      # 3. Agregarlo como miembro (para probar duplicado)
      miembro_existente = MiembroProyecto(
          usuario_id=usuario_existente.id,
          proyecto_id=test_project.id,
          rol="colaborador"
      )
      db_session.add(miembro_existente)
      db_session.commit()

      # 4. Datos para intentar agregarlo de nuevo
      data = {
          "usuario_id": usuario_existente.id,
          "rol": "colaborador"
      }

      # 5. Hacer la solicitud (como admin)
      response = client.post(
          f"/projects/{test_project.id}/add_member",
          headers=auth_header,
          data=json.dumps(data),
          content_type="application/json"
      )

      # 6. Verificaciones
      assert response.status_code == HTTPStatus.BAD_REQUEST
      assert response.json["status"] == "error"
      assert response.json["code"] == CollaboratorErrorCodes.USER_ALREADY_ADDED

    def test_agregar_colaborador_usuario_no_existente(self, client, auth_header, test_project, test_user, db_session):
      """Test para agregar un usuario que no existe"""
      # 1. Asegurar que test_user es admin del proyecto
      miembro_admin = MiembroProyecto(
          usuario_id=test_user.id,
          proyecto_id=test_project.id,
          rol="admin"
      )
      db_session.add(miembro_admin)
      db_session.commit()

      # 2. Datos con ID de usuario que no existe
      data = {
          "usuario_id": 99999,  # ID que no existe
          "rol": "colaborador"
      }

      # 3. Hacer la solicitud (como admin)
      response = client.post(
          f"/projects/{test_project.id}/add_member",
          headers=auth_header,
          data=json.dumps(data),
          content_type="application/json"
      )

      # 4. Verificaciones
      assert response.status_code == HTTPStatus.NOT_FOUND
      assert response.json["status"] == "error"
      assert response.json["code"] == CollaboratorErrorCodes.USER_NOT_FOUND

    def test_agregar_colaborador_rol_invalido(self, client, auth_header, test_project, test_user, db_session):
      """Test para agregar con un rol no válido"""
      # 1. Asegurar que test_user es admin del proyecto
      miembro_admin = MiembroProyecto(
          usuario_id=test_user.id,
          proyecto_id=test_project.id,
          rol="admin"
      )
      db_session.add(miembro_admin)
      db_session.commit()

      # 2. Crear un usuario con email único
      # Usar un email que no exista (puedes usar un timestamp o random)
      import time
      email_unico = f"nuevo_{int(time.time())}@example.com"
      
      nuevo_usuario = Usuario(nombre="Nuevo Miembro", email=email_unico)
      nuevo_usuario.set_password("password123")
      db_session.add(nuevo_usuario)
      db_session.commit()

      # 3. Datos con rol inválido
      data = {
          "usuario_id": nuevo_usuario.id,
          "rol": "rol_invalido"  # Rol que no existe
      }

      # 4. Hacer la solicitud
      response = client.post(
          f"/projects/{test_project.id}/add_member",
          headers=auth_header,
          data=json.dumps(data),
          content_type="application/json"
      )

      # 5. Verificaciones
      assert response.status_code == HTTPStatus.BAD_REQUEST
      assert response.json["status"] == "error"
      assert response.json["code"] == CollaboratorErrorCodes.INVALID_ROLE

    def test_agregar_colaborador_sin_campo_usuario_id(self, client, auth_header, test_project):
        """Test para agregar miembro sin el campo usuario_id requerido"""
        data = {
            "rol": "colaborador"  # Falta usuario_id
        }

        response = client.post(
            f"/projects/{test_project.id}/add_member",
            headers=auth_header,
            data=json.dumps(data),
            content_type="application/json"
        )

        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json["status"] == "error"
        assert response.json["code"] == ProjectErrorCodes.MISSING_REQUIRED_FIELDS

    def test_agregar_colaborador_formato_invalido(self, client, auth_header, test_project):
        """Test para enviar datos en formato no JSON"""
        response = client.post(
            f"/projects/{test_project.id}/add_member",
            headers=auth_header,
            data="esto no es json",
            content_type="text/plain"
        )

        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json["status"] == "error"
        assert response.json["code"] == SystemErrorCodes.INVALID_REQUEST_FORMAT


# import pytest
# from http import HTTPStatus
# from app1.models import Tarea, MiembroProyecto
# from unittest.mock import patch

class TestCrearTarea:
    """Test suite para el endpoint de creación de tareas"""

    def test_crear_tarea_exitoso(self, client, auth_header, test_project):
        
        """Test para creación exitosa de tarea"""
        task_data = {
            "titulo": "Nueva tarea",
            "descripcion": "Descripción de prueba",
            "asignado_a_id": None,
            "subject": "test-subject"
        }

        # URL con doble projects (intencional)
        response = client.post(
            f"/projects/{test_project.id}/tasks",
            data=json.dumps(task_data),  # Usamos data= en lugar de json=
            headers={
                **auth_header,
                'Content-Type': 'application/json'
            }
        )

        # Debug completo
        print("\n=== TEST DEBUG ===")
        print(f"Request URL: /projects/projects/{test_project.id}/tasks")
        print(f"Request data: {task_data}")
        print(f"Response status: {response.status_code}")
        print(f"Response data: {response.json}")
        
        assert response.status_code == HTTPStatus.CREATED.value


    def test_crear_tarea_sin_permisos(self, client, auth_header, test_project, test_user):
        """Test que verifica el acceso sin permisos"""
        # Eliminamos al usuario de los miembros del proyecto
        MiembroProyecto.query.filter_by(
            usuario_id=test_user.id,
            proyecto_id=test_project.id
        ).delete()
        db.session.commit()

        task_data = {
            "titulo": "Tarea sin permisos",
            "descripcion": "No debería funcionar"
        }

        response = client.post(
            f"/projects/{test_project.id}/tasks",
            json=task_data,
            headers=auth_header
        )

        assert response.status_code == HTTPStatus.FORBIDDEN.value
        assert "error" in response.json
        assert "No tienes acceso a este proyecto" in response.json["error"]

    def test_crear_tarea_duplicada(self, client, auth_header, test_project):
        """Test que verifica la prevención de tareas duplicadas"""
        # Primero creamos una tarea
        task_data = {
            "titulo": "Tarea duplicada",
            "descripcion": "Primera tarea"
        }

        response1 = client.post(
            f"/projects/{test_project.id}/tasks",
            json=task_data,
            headers=auth_header
        )
        assert response1.status_code == HTTPStatus.CREATED.value

        # Intentamos crear la misma tarea otra vez
        response2 = client.post(
            f"/projects/{test_project.id}/tasks",
            json=task_data,
            headers=auth_header
        )

        assert response2.status_code == HTTPStatus.BAD_REQUEST.value
        assert "error" in response2.json
        assert "Ya existe una tarea con este título" in response2.json["error"]

    def test_crear_tarea_datos_invalidos(self, client, auth_header, test_project):
        """Test para validación de datos inválidos"""
        # Caso 1: Falta título (requerido)
        invalid_data1 = {
            "descripcion": "Falta el título"
        }

        response1 = client.post(
            f"/projects/{test_project.id}/tasks",
            json=invalid_data1,
            headers=auth_header
        )

        assert response1.status_code == HTTPStatus.BAD_REQUEST.value
        assert "error" in response1.json
        assert "Datos de tarea inválidos" in response1.json["error"]
        assert "titulo" in response1.json["detalles"]

        # Caso 2: Falta descripción (requerido)
        invalid_data2 = {
            "titulo": "Falta descripción"
        }

        response2 = client.post(
            f"/projects/{test_project.id}/tasks",
            json=invalid_data2,
            headers=auth_header
        )

        assert response2.status_code == HTTPStatus.BAD_REQUEST.value
        assert "descripcion" in response2.json["detalles"]

    def test_crear_tarea_sin_json(self, client, auth_header, test_project):
        """Test para request sin contenido JSON"""
        response = client.post(
            f"/projects/{test_project.id}/tasks",
            data="Esto no es JSON",
            headers={
                **auth_header,
                "Content-Type": "text/plain"  # Forzamos tipo incorrecto
            }
        )

        assert response.status_code == HTTPStatus.BAD_REQUEST.value
        assert "error" in response.json
        # Actualizado para coincidir con tus códigos de error
        assert response.json["error"] == "Datos de tarea inválidos"
        assert response.json["codigo_error"] == TaskErrorCodes.INVALID_TASK_DATA
 

    def test_crear_tarea_error_interno(self, client, auth_header, test_project, mocker):
        """Test para manejo de errores internos"""
        # Mockeamos un error en la base de datos
        mocker.patch(
            'app1.models.db.session.commit',
            side_effect=Exception("Error simulado")
        )

        task_data = {
            "titulo": "Tarea que fallará",
            "descripcion": "Esta tarea causará un error"
        }

        response = client.post(
            f"/projects/{test_project.id}/tasks",
            json=task_data,
            headers=auth_header
        )

        assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR.value
        assert "error" in response.json
        assert "Error interno al crear la tarea" in response.json["error"]

    def test_crear_tarea_campos_opcionales(self, client, auth_header, test_project, test_user):
        """Test que verifica que los campos opcionales funcionen correctamente"""
        # Caso 1: Sin asignado_a_id ni subject
        minimal_data = {
            "titulo": "Tarea mínima",
            "descripcion": "Solo campos requeridos"
        }

        response1 = client.post(
            f"/projects/{test_project.id}/tasks",
            json=minimal_data,
            headers=auth_header
        )

        assert response1.status_code == HTTPStatus.CREATED.value
        assert response1.json["data"]["asignado_a_id"] is None
        assert response1.json["data"]["subject"] == "default-subject"

        # Caso 2: Con todos los campos opcionales
        full_data = {
            "titulo": "Tarea completa",
            "descripcion": "Todos los campos",
            "asignado_a_id": test_user.id,
            "subject": "custom-subject"
        }

        response2 = client.post(
            f"/projects/{test_project.id}/tasks",
            json=full_data,
            headers=auth_header
        )


        assert response2.status_code == HTTPStatus.CREATED.value
        assert response2.json["data"]["asignado_a_id"] == test_user.id
        assert response2.json["data"]["subject"] == "custom-subject"



# import pytest
# from http import HTTPStatus
# from app1.models import Tarea, MiembroProyecto

class TestListarTareas:
    """Test suite para el endpoint de listado de tareas"""

    def test_listar_tareas_exitoso(self, client, auth_header, test_project, test_user):
        """Test para listado exitoso de tareas"""
        # Crear algunas tareas de prueba
        tarea1 = Tarea(
            titulo="Tarea 1",
            descripcion="Descripción 1",
            proyecto_id=test_project.id,
            creador_id=test_user.id
        )
        tarea2 = Tarea(
            titulo="Tarea 2", 
            descripcion="Descripción 2",
            proyecto_id=test_project.id,
            creador_id=test_user.id
        )
        db.session.add_all([tarea1, tarea2])
        db.session.commit()

        response = client.get(
            f"/projects/{test_project.id}/tasks",
            headers=auth_header
        )

        assert response.status_code == HTTPStatus.OK
        assert "data" in response.json
        assert len(response.json["data"]) == 2
        assert {t["titulo"] for t in response.json["data"]} == {"Tarea 1", "Tarea 2"}

    def test_listar_tareas_vacio(self, client, auth_header, test_project):
        """Test para proyecto sin tareas"""
        response = client.get(
            f"/projects/{test_project.id}/tasks",
            headers=auth_header
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json["data"] == []

    def test_listar_tareas_sin_permisos(self, client, auth_header, test_project, test_user):
        """Test que verifica el acceso sin permisos"""
        # Eliminar al usuario de los miembros del proyecto
        MiembroProyecto.query.filter_by(
            usuario_id=test_user.id,
            proyecto_id=test_project.id
        ).delete()
        db.session.commit()

        response = client.get(
            f"/projects/{test_project.id}/tasks",
            headers=auth_header
        )

        assert response.status_code == HTTPStatus.FORBIDDEN
        assert response.json["error"] == "No tienes acceso a este proyecto"
        assert response.json["proyecto_id"] == test_project.id

    def test_listar_tareas_no_autenticado(self, client, test_project):
        """Test para acceso no autenticado"""
        response = client.get(
            f"/projects/{test_project.id}/tasks"
        )

        assert response.status_code == 401  # Unauthorized

    def test_estructura_respuesta(self, client, auth_header, test_project, test_user):
        """Test que verifica la estructura completa de la respuesta"""
        tarea = Tarea(
            titulo="Tarea test",
            descripcion="Descripción test",
            proyecto_id=test_project.id,
            creador_id=test_user.id,
            asignado_a_id=test_user.id
        )
        db.session.add(tarea)
        db.session.commit()

        response = client.get(
            f"/projects/{test_project.id}/tasks",
            headers=auth_header
        )

        assert response.status_code == HTTPStatus.OK
        data = response.json
        
        # Verificar estructura general
        assert set(data.keys()) == {"data", "proyecto_id"}
        assert isinstance(data["data"], list)
        assert data["proyecto_id"] == test_project.id
        
        # Verificar estructura de cada tarea
        tarea_data = data["data"][0]
        assert set(tarea_data.keys()) == {
            "titulo", "descripcion", "asignado_a", "tarea_id", "proyecto_id"
        }
        assert tarea_data["tarea_id"] == tarea.id
        assert tarea_data["proyecto_id"] == test_project.id

    def test_listar_tareas_proyecto_inexistente(self, client, auth_header):
        """Test para proyecto que no existe"""
        non_existent_id = 9999
        response = client.get(
            f"/projects/{non_existent_id}/tasks",
            headers=auth_header
        )

        assert response.status_code == HTTPStatus.FORBIDDEN
        assert response.json["proyecto_id"] == non_existent_id



class TestActualizarTarea:
    """Grupo de pruebas para el endpoint de actualización de tareas."""

    def test_actualizar_titulo_tarea(self, client, db_session, test_user, auth_header, test_project):
        """
        Prueba que un usuario puede actualizar el título de una tarea.
        """
        # 1. Preparación - Crear una tarea de prueba
        tarea = Tarea(
            titulo="Tarea original",
            descripcion="Descripción original",
            proyecto_id=test_project.id,
            creador_id=test_user.id,
            asignado_a_id=test_user.id
        )
        db_session.add(tarea)
        db_session.commit()

        # 2. Ejecución - Hacer la petición PUT
        nuevo_titulo = "Nuevo título de tarea"
        response = client.put(
            f'/projects/{test_project.id}/tasks/{tarea.id}',
            json={'titulo': nuevo_titulo},
            headers=auth_header
        )

        # 3. Verificación
        assert response.status_code == HTTPStatus.OK
        assert response.json['tarea']['titulo'] == nuevo_titulo
        assert 'changes' in response.json
        assert response.json['changes']['titulo']['anterior'] == "Tarea original"
        assert response.json['changes']['titulo']['nuevo'] == nuevo_titulo

    def test_actualizar_descripcion_tarea(self, client, db_session, test_user, auth_header, test_project):
        """
        Prueba que un usuario puede actualizar la descripción de una tarea.
        """
        # 1. Preparación
        tarea = Tarea(
            titulo="Tarea para actualizar",
            descripcion="Descripción vieja",
            proyecto_id=test_project.id,
            creador_id=test_user.id
        )
        db_session.add(tarea)
        db_session.commit()

        # 2. Ejecución
        nueva_desc = "Nueva descripción detallada"
        response = client.put(
            f'/projects/{test_project.id}/tasks/{tarea.id}',
            json={'descripcion': nueva_desc},
            headers=auth_header
        )

        # 3. Verificación
        assert response.status_code == HTTPStatus.OK
        assert response.json['tarea']['descripcion'] == nueva_desc
        assert response.json['changes']['descripcion']['anterior'] == "Descripción vieja"
        assert response.json['changes']['descripcion']['nuevo'] == nueva_desc

    def test_reasignar_tarea_como_admin(self, client, db_session, test_user, auth_header, test_project):
        """
        Prueba que un admin puede reasignar una tarea a otro usuario.
        """
        # 1. Crear un segundo usuario con email único
        timestamp = int(time.time())
        otro_usuario = Usuario(
            nombre=f"Otro Usuario {timestamp}",
            email=f"otro_{timestamp}@test.com",
            password="test1234"
        )
        db_session.add(otro_usuario)
        db_session.commit()

        # Resto del test permanece igual...
        miembro = MiembroProyecto(
            usuario_id=otro_usuario.id,
            proyecto_id=test_project.id,
            rol='miembro'
        )
        db_session.add(miembro)
        
        tarea = Tarea(
            titulo="Tarea para reasignar",
            proyecto_id=test_project.id,
            creador_id=test_user.id,
            asignado_a_id=test_user.id,
            estado='en_progreso'
        )
        db_session.add(tarea)
        db_session.commit()

        response = client.put(
            f'/projects/{test_project.id}/tasks/{tarea.id}',
            json={'asignado_a_id': otro_usuario.id},
            headers=auth_header
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json['tarea']['asignado_a_id'] == otro_usuario.id


    def test_no_actualizar_estado_directamente(self, client, db_session, test_user, auth_header, test_project):
        """
        Prueba que no se puede cambiar el estado directamente desde este endpoint.
        """
        # 1. Crear tarea
        tarea = Tarea(
            titulo="Tarea con estado",
            proyecto_id=test_project.id,
            creador_id=test_user.id,
            estado='pendiente'
        )
        db_session.add(tarea)
        db_session.commit()

        # 2. Intentar cambiar estado
        response = client.put(
            f'/projects/{test_project.id}/tasks/{tarea.id}',
            json={'estado': 'completado'},
            headers=auth_header
        )

        # 3. Verificar error
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert "Para cambiar el estado use el endpoint específico" in response.json['error']
        assert "endpoint_correcto" in response.json['metadata']

    def test_usuario_no_miembro_no_puede_actualizar(self, client, db_session, test_user, test_project):
        """
        Prueba que un usuario que no es miembro del proyecto no puede actualizar tareas.
        """
        # 1. Crear otro usuario (no miembro del proyecto)
        otro_usuario = Usuario(nombre="Extraño", email="extraño@test.com", password="test1234")
        db_session.add(otro_usuario)
        db_session.commit()

        # 2. Obtener token para el otro usuario
        with client.application.app_context():
            from flask_jwt_extended import create_access_token
            otro_token = create_access_token(identity=str(otro_usuario.id))
            otro_auth_header = {'Authorization': f'Bearer {otro_token}'}

        # 3. Crear tarea en el proyecto
        tarea = Tarea(
            titulo="Tarea protegida",
            proyecto_id=test_project.id,
            creador_id=test_user.id
        )
        db_session.add(tarea)
        db_session.commit()

        # 4. Intentar actualizar como usuario no autorizado
        response = client.put(
            f'/projects/{test_project.id}/tasks/{tarea.id}',
            json={'titulo': "Intento de hackeo"},
            headers=otro_auth_header
        )

        # 5. Verificar que fue rechazado
        assert response.status_code == HTTPStatus.FORBIDDEN
        assert "Acceso denegado" in response.json['error']

    def test_actualizacion_invalida_sin_datos(self, client, auth_header, test_project, test_user, db_session):
        """
        Prueba que enviar un JSON vacío devuelve un error.
        """
        # 1. Crear tarea
        tarea = Tarea(
            titulo="Tarea para actualizar",
            proyecto_id=test_project.id,
            creador_id=test_user.id
        )
        db_session.add(tarea)
        db_session.commit()

        # 2. Hacer petición sin datos útiles
        response = client.put(
            f'/projects/{test_project.id}/tasks/{tarea.id}',
            json={},  # JSON vacío
            headers=auth_header
        )

        # 3. Verificar error
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert "Datos no proporcionados" in response.json['error']

    def test_formato_no_json(self, client, test_project, test_user, db_session, auth_header):
        """
        Prueba que enviar datos que no son JSON devuelve un error.
        """
        # 1. Crear tarea
        tarea = Tarea(
            titulo="Tarea para probar formato",
            proyecto_id=test_project.id,
            creador_id=test_user.id
        )
        db_session.add(tarea)
        db_session.commit()

        # 2. Hacer petición con texto plano (no JSON)
        # Usamos el auth_header pero sobrescribimos el Content-Type
        headers = {**auth_header, 'Content-Type': 'text/plain'}
        
        response = client.put(
            f'/projects/{test_project.id}/tasks/{tarea.id}',  # URL corregida
            data="Esto no es JSON",
            headers=headers
        )

        # 3. Verificar error
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert "Se requiere formato JSON" in response.json['error']

    def test_tarea_no_existente(self, client, auth_header, test_project):
        """
        Prueba que intentar actualizar una tarea que no existe devuelve 404.
        """
        # Usar un ID que no existe (99999)
        response = client.put(
            f'/projects/{test_project.id}/tasks/99999',
            json={'titulo': "Título nuevo"},
            headers=auth_header
        )

        assert response.status_code == HTTPStatus.NOT_FOUND
        assert "Tarea no encontrada" in response.json['error']

    def test_reasignacion_no_admin(self, client, db_session, test_user, auth_header, test_project):
        """
        Prueba que un usuario no-admin no puede reasignar tareas de otros.
        """
        # 1. Crear otro usuario y agregarlo al proyecto como miembro normal
        otro_usuario = Usuario(nombre="Miembro Normal", email="normal@test.com", password="test1234")
        db_session.add(otro_usuario)
        db_session.commit()

        miembro = MiembroProyecto(
            usuario_id=otro_usuario.id,
            proyecto_id=test_project.id,
            rol='miembro'
        )
        db_session.add(miembro)

        # 2. Cambiar el rol del usuario principal a miembro (no admin)
        miembro_admin = MiembroProyecto.query.filter_by(
            usuario_id=test_user.id,
            proyecto_id=test_project.id
        ).first()
        miembro_admin.rol = 'miembro'
        db_session.commit()

        # 3. Crear tarea asignada al otro usuario
        tarea = Tarea(
            titulo="Tarea de otro",
            proyecto_id=test_project.id,
            creador_id=test_user.id,
            asignado_a_id=otro_usuario.id
        )
        db_session.add(tarea)
        db_session.commit()

        # 4. Intentar reasignar como usuario no-admin
        response = client.put(
            f'/projects/{test_project.id}/tasks/{tarea.id}',
            json={'asignado_a_id': test_user.id},  # Intentar asignarse a sí mismo
            headers=auth_header
        )

        # 5. Verificar que fue rechazado
        assert response.status_code == HTTPStatus.FORBIDDEN
        assert "Solo el administrador puede reasignar" in response.json['error']



# import pytest
# from http import HTTPStatus
# from datetime import datetime
# from sqlalchemy.exc import SQLAlchemyError
# from app1.models import Proyecto, Tarea, MiembroProyecto, EstadoTarea
# from error_code import (
#     SuccessCodes,
#     ProjectErrorCodes,
#     TaskErrorCodes,
#     CollaboratorErrorCodes,
#     SystemErrorCodes
# )

class TestChangeTaskStatus:


    def test_cambiar_estado_exitoso(self, client, auth_header, test_project_with_tasks):
        """Test para cambio de estado exitoso"""
        proyecto, tarea = test_project_with_tasks

        # Debug: Verifica los IDs a través de los objetos
        print(f"ID Proyecto: {proyecto.id}")
        print(f"ID Tarea: {tarea.id}")
        print(f"ID Usuario del header: {auth_header['Authorization'].split()[1]}")  # Solo para debug

        response = client.put(
            f'/projects/{proyecto.id}/tasks/{tarea.id}/status',
            json={'estado': EstadoTarea.EN_PROGRESO.value},
            headers=auth_header  # El JWT ya está incluido aquí
        )
        
        assert response.status_code == HTTPStatus.OK



    def test_completar_tarea(self, client, auth_header, test_project_with_tasks, db_session):
        """Test para marcar tarea como completada"""
        proyecto, tarea = test_project_with_tasks
        tarea.asignado_a_id = 1  # Asignar al usuario de test
        db_session.commit()
        
        response = client.put(
            f'/projects/{proyecto.id}/tasks/{tarea.id}/status',
            json={'estado': EstadoTarea.COMPLETADO.value},
            headers=auth_header
        )
        
        assert response.status_code == HTTPStatus.OK
        assert response.json['code'] == SuccessCodes.TASK_COMPLETED
        assert response.json['data']['tarea']['estado_actual'] == EstadoTarea.COMPLETADO.value
        assert response.json['data']['tarea']['fecha_completado'] is not None

    def test_cambiar_estado_sin_json(self, client, auth_header, test_project_with_tasks):
        """Test para request sin JSON"""
        proyecto, tarea = test_project_with_tasks
        
        response = client.put(
            f'/projects/{proyecto.id}/tasks/{tarea.id}/status',
            data="esto no es json",
            headers=auth_header
        )
        
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json['code'] == SystemErrorCodes.INVALID_REQUEST_FORMAT

    def test_cambiar_estado_sin_campo_estado(self, client, auth_header, test_project_with_tasks):
        """Test para request sin campo 'estado'"""
        proyecto, tarea = test_project_with_tasks
        
        response = client.put(
            f'/projects/{proyecto.id}/tasks/{tarea.id}/status',
            json={'otro_campo': 'valor'},
            headers=auth_header
        )
        
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json['code'] == ProjectErrorCodes.MISSING_REQUIRED_FIELDS

    def test_estado_no_valido(self, client, auth_header, test_project_with_tasks):
        """Test para estado no válido"""
        proyecto, tarea = test_project_with_tasks
        
        response = client.put(
            f'/projects/{proyecto.id}/tasks/{tarea.id}/status',
            json={'estado': 'estado_invalido'},
            headers=auth_header
        )
        
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json['code'] == TaskErrorCodes.INVALID_STATUS_TRANSITION

    def test_usuario_no_miembro(self, client, auth_header, db_session, test_user):
        """Test para usuario que no es miembro del proyecto"""
        # Crear proyecto con otro usuario
        otro_usuario = Usuario(nombre="Otro", email="otro@test.com", password="pass1234")
        db_session.add(otro_usuario)
        db_session.flush()

        proyecto = Proyecto(nombre="Proyecto Privado", propietario_id=otro_usuario.id)
        db_session.add(proyecto)
        db_session.flush()

        # Crear tarea con creador_id válido (usando el otro_usuario como creador)
        tarea = Tarea(
            titulo="Tarea Privada",
            proyecto_id=proyecto.id,
            estado=EstadoTarea.PENDIENTE,
            creador_id=otro_usuario.id,  # Campo obligatorio
            asignado_a_id=otro_usuario.id  # Si es requerido
        )
        db_session.add(tarea)
        db_session.commit()

        response = client.put(
            f'/projects/{proyecto.id}/tasks/{tarea.id}/status',
            json={'estado': EstadoTarea.EN_PROGRESO.value},
            headers=auth_header
        )
        
        error_data = response.json
        assert response.status_code == HTTPStatus.FORBIDDEN
        assert (error_data.get('error_code') == CollaboratorErrorCodes.USER_NOT_COLLABORATOR or 
        error_data.get('code') == CollaboratorErrorCodes.USER_NOT_COLLABORATOR or
        "No tienes acceso" in error_data.get('error', ''))

    def test_tarea_no_existente(self, client, auth_header, test_project_with_tasks):
        """Test para tarea que no existe"""
        proyecto, _ = test_project_with_tasks
        
        response = client.put(
            f'/projects/{proyecto.id}/tasks/999999/status',
            json={'estado': EstadoTarea.EN_PROGRESO.value},
            headers=auth_header
        )
        
        assert response.status_code == HTTPStatus.NOT_FOUND
        assert response.json['code'] == TaskErrorCodes.TASK_NOT_FOUND

    def test_completar_tarea_no_asignada(self, client, auth_header, test_project_with_tasks, db_session):
        """Test para completar tarea no asignada"""
        proyecto, tarea = test_project_with_tasks
        tarea.asignado_a_id = None  # Asegurar que no está asignada
        db_session.commit()
        
        response = client.put(
            f'/projects/{proyecto.id}/tasks/{tarea.id}/status',
            json={'estado': EstadoTarea.COMPLETADO.value},
            headers=auth_header
        )
        
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json['code'] == TaskErrorCodes.CANNOT_COMPLETE_UNASSIGNED

    def test_completar_tarea_por_no_asignado(self, client, auth_header, test_project_with_tasks, db_session):
        """Test para usuario no asignado intentando completar tarea"""
        proyecto, tarea = test_project_with_tasks
        tarea.asignado_a_id = 999  # Asignar a otro usuario
        db_session.commit()
        
        # Cambiar rol a miembro (no admin)
        miembro = MiembroProyecto.query.filter_by(proyecto_id=proyecto.id).first()
        miembro.rol = "miembro"
        db_session.commit()
        
        response = client.put(
            f'/projects/{proyecto.id}/tasks/{tarea.id}/status',
            json={'estado': EstadoTarea.COMPLETADO.value},
            headers=auth_header
        )
        
        assert response.status_code == HTTPStatus.FORBIDDEN
        assert response.json['code'] == CollaboratorErrorCodes.INSUFFICIENT_PERMISSIONS

    def test_error_base_datos(self, client, auth_header, test_project_with_tasks, mocker):
        """Test para error de base de datos"""
        proyecto, tarea = test_project_with_tasks
        
        # Mock para simular error en commit
        mocker.patch('sqlalchemy.orm.Session.commit', side_effect=SQLAlchemyError("DB Error"))
        
        response = client.put(
            f'/projects/{proyecto.id}/tasks/{tarea.id}/status',
            json={'estado': EstadoTarea.EN_PROGRESO.value},
            headers=auth_header
        )
        
        assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
        assert response.json['code'] == SystemErrorCodes.INTERNAL_SERVER_ERROR