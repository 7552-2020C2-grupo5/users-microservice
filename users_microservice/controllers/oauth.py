"""Federated identity controller."""
import logging

import jwt
import requests
from jwt import PyJWKClient

from users_microservice.cfg import config
from users_microservice.constants import (
    DEFAULT_AUDIENCE,
    DEFAULT_GOOGLE_OPENID_CFG_JWKS_KEY,
    DEFAULT_GOOGLE_OPENID_CFG_URI,
)
from users_microservice.exceptions import EmailAlreadyRegistered
from users_microservice.models import User, db

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def validated_token(token, verify=True):
    """Validate a token and return decoded token."""
    url = (
        requests.get(
            config.oauth.google_openid_config_uri(default=DEFAULT_GOOGLE_OPENID_CFG_URI)
        )
        .json()
        .get(
            config.oauth.google_openid_jkws_key(
                default=DEFAULT_GOOGLE_OPENID_CFG_JWKS_KEY
            )
        )
    )
    logger.info("JWK url is %s", url)
    jwks_client = PyJWKClient(url)
    signing_key = jwks_client.get_signing_key_from_jwt(token)

    data = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=config.oauth.audience(default=DEFAULT_AUDIENCE),
        options={"verify_signature": verify},
    )

    return data


def oauth_user(token):
    """Get user from token."""
    decoded_token = validated_token(token, False)
    return User.query.filter(User.email == decoded_token["email"]).first()


def create_oauth_user(token, wallet_address, wallet_mnemonic):
    """Create a new user from OAuth token."""
    if oauth_user(token) is not None:
        raise EmailAlreadyRegistered

    data = validated_token(token)

    new_user_data = {
        "first_name": data["given_name"],
        "last_name": data["family_name"],
        "password": data["sub"],
        "profile_picture": data["picture"],
        "wallet_address": wallet_address,
        "wallet_mnemonic": wallet_mnemonic,
        "email": data["email"],
    }
    new_user = User(**new_user_data)
    db.session.add(new_user)
    db.session.commit()
    return new_user
