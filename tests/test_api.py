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
    app = create_app()
    with tempfile.NamedTemporaryFile() as dbf:
        app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{dbf.name}"
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
def user():
    return {
        "first_name": "Franco",
        "last_name": "Milazzo",
        "email": "stallone@gmail.com",
        "password": "Schwarzenegger",
        "wallet_address": "1287912123012912309",
        "wallet_mnemonic": "valentia y fuerza contra cualquier amenaza",
    }


def test_root(client):
    response = client.get("/")
    assert response._status_code == 200


def test_create_admin_invalid_email(client, invalid_email_admin):
    response = client.post("/v1/admins", json=invalid_email_admin)
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
