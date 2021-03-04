"""Metrics test suite."""

import json
import logging
import tempfile
from datetime import datetime as dt
from datetime import timedelta as td

# pylint:disable=redefined-outer-name,protected-access
import pytest

from users_microservice.app import create_app
from users_microservice.models import db

logger = logging.getLogger(__name__)


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


def test_new_users_per_day(client, user):
    r = client.post("/v1/users", json=user)
    r = client.get(
        "/v1/metrics",
        data={
            "start_date": dt.utcnow().date().isoformat(),
            "end_date": dt.utcnow().date().isoformat(),
        },
    )
    assert r._status_code == 200
    assert json.loads(r.data) == [
        {
            "name": "new_users_per_day",
            "data": [{"date": dt.utcnow().date().isoformat(), "value": 1.0}],
        }
    ]


def test_new_users_per_day_2(client, user):
    r = client.post("/v1/users", json=user)
    r = client.get(
        "/v1/metrics",
        data={
            "start_date": dt.utcnow().date().isoformat(),
            "end_date": (dt.utcnow() + td(days=1)).date().isoformat(),
        },
    )
    assert r._status_code == 200
    assert json.loads(r.data) == [
        {
            "name": "new_users_per_day",
            "data": [
                {"date": dt.utcnow().date().isoformat(), "value": 1.0},
                {"date": (dt.utcnow() + td(days=1)).date().isoformat(), "value": 0.0},
            ],
        }
    ]


def test_new_users_per_day_3(client, user):
    r = client.post("/v1/users", json=user)
    r = client.get(
        "/v1/metrics",
        data={
            "start_date": (dt.utcnow() - td(days=1)).date().isoformat(),
            "end_date": dt.utcnow().date().isoformat(),
        },
    )
    assert r._status_code == 200
    assert json.loads(r.data) == [
        {
            "name": "new_users_per_day",
            "data": [
                {"date": (dt.utcnow() - td(days=1)).date().isoformat(), "value": 0.0},
                {"date": dt.utcnow().date().isoformat(), "value": 1.0},
            ],
        }
    ]


def test_new_users_per_day_4(client, user):
    r = client.post("/v1/users", json=user)
    r = client.get(
        "/v1/metrics",
        data={
            "start_date": (dt.utcnow() - td(days=1)).date().isoformat(),
            "end_date": (dt.utcnow() + td(days=1)).date().isoformat(),
        },
    )
    assert r._status_code == 200
    assert json.loads(r.data) == [
        {
            "name": "new_users_per_day",
            "data": [
                {"date": (dt.utcnow() - td(days=1)).date().isoformat(), "value": 0.0},
                {"date": dt.utcnow().date().isoformat(), "value": 1.0},
                {"date": (dt.utcnow() + td(days=1)).date().isoformat(), "value": 0.0},
            ],
        }
    ]
