"""Token namespace controller module."""


import logging

import requests

from users_microservice.cfg import config
from users_microservice.exceptions import ServerTokenError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def get_env_vars():
    heroku_app = config.heroku_app_name()
    heroku_api_key = config.heroku_api_key()
    result = requests.get(
        f"https://api.heroku.com/apps/{heroku_app}/config-vars",
        headers={
            "Accept": "application/vnd.heroku+json; version=3",
            "Authorization": f"Bearer {heroku_api_key}",
        },
    )
    result.raise_for_status()
    return result.json()


def _patch_env_vars(env_vars):
    heroku_app = config.heroku_app_name()
    heroku_api_key = config.heroku_api_key()
    result = requests.patch(
        f"https://api.heroku.com/apps/{heroku_app}/config-vars",
        json=env_vars,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/vnd.heroku+json; version=3",
            "Authorization": f"Bearer {heroku_api_key}",
        },
    )
    result.raise_for_status()


def add_end_var(key, val):
    try:
        _patch_env_vars({key.upper(): val})
    except Exception as e:
        raise ServerTokenError from e


def remove_env_var(key):
    try:
        _patch_env_vars({key.upper(): "_"})
    except Exception as e:
        raise ServerTokenError from e
