"""Flask api."""
import logging
from pathlib import Path

import requests
from flask import Flask, request
from flask_cors import CORS
from flask_migrate import Migrate
from werkzeug.middleware.proxy_fix import ProxyFix

from users_microservice.api import api
from users_microservice.cfg import config
from users_microservice.constants import DEFAULT_VERIFICATION_URL
from users_microservice.models import bcrypt, db

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def fix_dialect(s):
    if s.startswith("postgres://"):
        s = s.replace("postgres://", "postgresql://")
    s = s.replace("postgresql://", "postgresql+psycopg2://")
    return s


def before_request():
    excluded_paths = [
        # swagger
        "/",
        "/swaggerui/favicon-32x32.png",
        "/swagger.json",
        "/swaggerui/swagger-ui-standalone-preset.js",
        "/swaggerui/swagger-ui-standalone-preset.js",
        "/swaggerui/swagger-ui-bundle.js",
        "/swaggerui/swagger-ui.css",
        "/swaggerui/droid-sans.css",
        # swagger v1
        "/v1/swagger.json",
        # login
        "/v1/admins/login",
    ]
    if (
        config.env(default="DEV") == "DEV"
        or request.path in excluded_paths
        or request.method == "OPTIONS"
    ):
        return

    gunicorn_error_logger = logging.getLogger('gunicorn.error')
    gunicorn_error_logger.setLevel(logging.DEBUG)

    bookbnb_token = request.headers.get("BookBNBAuthorization")

    gunicorn_error_logger.info(
        f"Caught token {bookbnb_token}, validating with tokens service"
    )

    if bookbnb_token is None:
        return {"message": "BookBNB token is missing"}, 401

    r = requests.post(
        config.token_verification_url(default=DEFAULT_VERIFICATION_URL),
        json={"token": bookbnb_token},
        headers={"BookBNBAuthorization": config.bookbnb_token(default="_")},
    )

    gunicorn_error_logger.info(f"Response was: {r.json()} and is ok: {r.ok}")

    if not r.ok:
        return {"message": "Invalid BookBNB token"}, 401


def create_app(test_db=None):
    """creates a new app instance"""
    new_app = Flask(__name__)
    new_app.config["SQLALCHEMY_DATABASE_URI"] = config.database.url(
        default=test_db or "sqlite:///publications_microservice.db", cast=fix_dialect
    )
    new_app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    new_app.config["ERROR_404_HELP"] = False
    db.init_app(new_app)
    api.init_app(new_app)
    bcrypt.init_app(new_app)
    Migrate(new_app, db, directory=Path(__file__).parent / "migrations")
    new_app.wsgi_app = ProxyFix(
        new_app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1
    )  # remove after flask-restx > 0.2.0 is released
    # https://github.com/python-restx/flask-restx/issues/230
    CORS(new_app)
    new_app.before_request(before_request)
    gunicorn_error_logger = logging.getLogger('gunicorn.error')
    if gunicorn_error_logger is not None:
        new_app.logger.handlers.extend(  # pylint: disable=no-member
            gunicorn_error_logger.handlers
        )
        new_app.logger.setLevel(logging.DEBUG)  # pylint: disable=no-member
    return new_app
