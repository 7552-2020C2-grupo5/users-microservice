"""Sample test suite."""

import json
import logging
import tempfile

# pylint:disable=redefined-outer-name,protected-access
import pytest

from users_microservice.app import create_app
from users_microservice.models import db

logger = logging.getLogger(__name__)


@pytest.fixture
def client():
    with tempfile.NamedTemporaryFile() as dbf:
        app = create_app(test_db=f"sqlite:///{dbf.name}")
        with app.app_context():
            from flask_migrate import upgrade as _upgrade

            _upgrade()
        with app.test_client() as test_client:
            yield test_client
        with app.app_context():
            db.drop_all()


@pytest.fixture
def invalid_email_admin():
    return {
        "first_name": "string",
        "last_name": "string",
        "email": "string",
        "password": "string",
    }


@pytest.fixture
def admin():
    return {
        "first_name": "Máximo",
        "last_name": "Cozzetti",
        "email": "ravenna@gmail.com",
        "password": "DebilitadorSocial",
    }


@pytest.fixture
def admin2():
    return {
        "first_name": "Brian",
        "last_name": "Kernighan",
        "email": "bk@gmail.com",
        "password": "Princeton",
    }


@pytest.fixture
def user():
    return {
        "first_name": "Franco",
        "last_name": "Milazzo",
        "email": "stallone@gmail.com",
        "password": "Schwarzenegger",
        "wallet_address": "1287912123012912309",
        "wallet_mnemonic": "valentia y fuerza contra cualquier amenaza",
    }


@pytest.fixture
def user2():
    return {
        "first_name": "Dennis",
        "last_name": "Ritchie",
        "email": "dritchie@gmail.com",
        "password": "Harvard",
        "wallet_address": "1287912123012912309",
        "wallet_mnemonic": "The C programming language",
    }


def test_root(client):
    response = client.get("/")
    assert response._status_code == 200


def test_create_admin_invalid_email(client, invalid_email_admin):
    response = client.post("/v1/admins", json=invalid_email_admin)
    assert response._status_code == 400


def test_create_admin_invalid_email_2(client):
    response = client.post(
        "/v1/admins",
        json={
            "first_name": "prueba",
            "last_name": "prueba",
            "email": "a@a.com",
            "password": "1234",
        },
    )
    assert response._status_code == 400


def test_login_root_admin(client):
    print(client.get("/v1/admins").data)
    admin_login = {"email": "admin@bookbnb.com", "password": "admin_bookbnb"}
    response = client.post("/v1/admins/login", json=admin_login)
    assert response._status_code == 201


def test_login_admin(client, admin):
    response = client.post("/v1/admins", json=admin)
    assert response._status_code == 201
    admin_login = {"email": admin["email"], "password": admin["password"]}
    response = client.post("/v1/admins/login", json=admin_login)
    assert response._status_code == 201


def test_block_user(client, user):
    response = client.post("/v1/users", json=user)
    assert response._status_code == 201
    user_data = json.loads(response.data)
    response = client.delete(f"/v1/users/{user_data['id']}")
    assert response._status_code == 200
    response = client.delete(f"/v1/users/{user_data['id']}")
    assert response._status_code == 403
    user_login = {"email": user["email"], "password": user["password"]}
    response = client.post("/v1/admins/login", json=user_login)
    assert response._status_code == 401


def test_login_user_does_not_exist(client):
    user_login = {"email": "dulcedeleche@gmail.com", "password": "TeHacesElHosco"}
    response = client.post("/v1/admins/login", json=user_login)
    assert response._status_code == 401


def test_filter_admin_first_name(client, admin, admin2):
    _ = client.post("/v1/admins", json=admin)
    _ = client.post("/v1/admins", json=admin2)
    filtered = client.get(f"/v1/admins?first_name={admin['first_name']}")
    assert filtered._status_code == 200
    filtered_data = json.loads(filtered.data)
    assert len(filtered_data) == 1
    assert filtered_data[0]["first_name"] == admin['first_name']


def test_filter_admin_first_name_partial(client, admin, admin2):
    _ = client.post("/v1/admins", json=admin)
    _ = client.post("/v1/admins", json=admin2)
    filtered = client.get(f"/v1/admins?first_name={admin['first_name'][:3]}")
    assert filtered._status_code == 200
    filtered_data = json.loads(filtered.data)
    assert len(filtered_data) == 1
    assert filtered_data[0]["first_name"] == admin['first_name']


def test_filter_admin_first_name_not_exists(client, admin, admin2):
    _ = client.post("/v1/admins", json=admin)
    _ = client.post("/v1/admins", json=admin2)
    filtered = client.get("/v1/admins?first_name=asdfdsafasfas")
    assert filtered._status_code == 200
    filtered_data = json.loads(filtered.data)
    assert len(filtered_data) == 0


def test_filter_admin_last_name(client, admin, admin2):
    _ = client.post("/v1/admins", json=admin)
    _ = client.post("/v1/admins", json=admin2)
    filtered = client.get(f"/v1/admins?last_name={admin['last_name']}")
    assert filtered._status_code == 200
    filtered_data = json.loads(filtered.data)
    assert len(filtered_data) == 1
    assert filtered_data[0]["last_name"] == admin['last_name']


def test_filter_admin_last_name_partial(client, admin, admin2):
    _ = client.post("/v1/admins", json=admin)
    _ = client.post("/v1/admins", json=admin2)
    filtered = client.get(f"/v1/admins?last_name={admin['last_name'][:4]}")
    assert filtered._status_code == 200
    filtered_data = json.loads(filtered.data)
    assert len(filtered_data) == 1
    assert filtered_data[0]["last_name"] == admin['last_name']


def test_filter_admin_last_name_not_exists(client, admin, admin2):
    _ = client.post("/v1/admins", json=admin)
    _ = client.post("/v1/admins", json=admin2)
    filtered = client.get("/v1/admins?last_name=asdfdsafasfas")
    assert filtered._status_code == 200
    filtered_data = json.loads(filtered.data)
    assert len(filtered_data) == 0


def test_filter_user_first_name(client, user, user2):
    _ = client.post("/v1/users", json=user)
    _ = client.post("/v1/users", json=user2)
    filtered = client.get(f"/v1/users?first_name={user['first_name']}")
    assert filtered._status_code == 200
    filtered_data = json.loads(filtered.data)
    assert len(filtered_data) == 1
    assert filtered_data[0]["first_name"] == user['first_name']


def test_filter_user_first_name_partial(client, user, user2):
    _ = client.post("/v1/users", json=user)
    _ = client.post("/v1/users", json=user2)
    filtered = client.get(f"/v1/users?first_name={user['first_name'][:3]}")
    assert filtered._status_code == 200
    filtered_data = json.loads(filtered.data)
    assert len(filtered_data) == 1
    assert filtered_data[0]["first_name"] == user['first_name']


def test_filter_user_first_name_not_exists(client, user, user2):
    _ = client.post("/v1/users", json=user)
    _ = client.post("/v1/users", json=user2)
    filtered = client.get("/v1/users?first_name=asdfdsafasfas")
    assert filtered._status_code == 200
    filtered_data = json.loads(filtered.data)
    assert len(filtered_data) == 0


def test_filter_user_last_name(client, user, user2):
    _ = client.post("/v1/users", json=user)
    _ = client.post("/v1/users", json=user2)
    filtered = client.get(f"/v1/users?last_name={user['last_name']}")
    assert filtered._status_code == 200
    filtered_data = json.loads(filtered.data)
    assert len(filtered_data) == 1
    assert filtered_data[0]["last_name"] == user['last_name']


def test_filter_user_last_name_partial(client, user, user2):
    _ = client.post("/v1/users", json=user)
    _ = client.post("/v1/users", json=user2)
    filtered = client.get(f"/v1/users?last_name={user['last_name'][:4]}")
    assert filtered._status_code == 200
    filtered_data = json.loads(filtered.data)
    assert len(filtered_data) == 1
    assert filtered_data[0]["last_name"] == user['last_name']


def test_filter_user_last_name_not_exists(client, user, user2):
    _ = client.post("/v1/users", json=user)
    _ = client.post("/v1/users", json=user2)
    filtered = client.get("/v1/users?last_name=asdfdsafasfas")
    assert filtered._status_code == 200
    filtered_data = json.loads(filtered.data)
    assert len(filtered_data) == 0
