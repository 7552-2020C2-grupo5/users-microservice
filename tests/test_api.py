"""Sample test suite."""

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
            db.create_all()
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


def test_root(client):
    response = client.get("/")
    assert response._status_code == 200


def test_create_admin_invalid_email(client, invalid_email_admin):
    response = client.post("/v1/admins", json=invalid_email_admin)
    assert response._status_code == 400


def test_login_admin(client, admin):
    response = client.post("/v1/admins", json=admin)
    assert response._status_code == 201
    admin_login = {"email": admin["email"], "password": admin["password"]}
    response = client.post("/v1/admins/login", json=admin_login)
    assert response._status_code == 201
