"""SQLAlchemy models."""
import datetime

import jwt
from email_validator import validate_email as ev_validate_email
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import validates
from sqlalchemy.sql import func
from sqlalchemy_utils.types.email import EmailType

from users_microservice.cfg import config
from users_microservice.constants import (
    DEFAULT_JWT_ALGORITHM,
    DEFAULT_JWT_EXPIRATION,
    DEFAULT_SECRET_KEY,
)
from users_microservice.exceptions import (
    BlockedUser,
    EmailAlreadyRegistered,
    PasswordDoesNotMatch,
    UserDoesNotExist,
)

db = SQLAlchemy()
bcrypt = Bcrypt()


class BaseUser(db.Model):  # type:ignore
    """Base User model."""

    __abstract__ = True

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String, nullable=False)
    last_name = db.Column(db.String, nullable=False)
    _password = db.Column(db.String, nullable=False)
    email = db.Column(EmailType, unique=True, nullable=False)
    register_date = db.Column(db.DateTime, nullable=False, default=func.now())

    @hybrid_property
    def password(self):
        return self.jwt

    @classmethod
    def _hash_pasword(cls, plaintext):
        return bcrypt.generate_password_hash(plaintext).decode()

    @password.setter  # type: ignore
    def password(self, plaintext):
        self._password = self._hash_pasword(plaintext)

    @validates("email")
    def validate_email(self, _key, email_address):
        user = type(self).query.filter(type(self).email == email_address).first()
        ev_validate_email(email_address)
        if user is not None and user.id != self.id:
            raise EmailAlreadyRegistered
        return email_address

    def verify_password(self, plaintext):
        return bcrypt.check_password_hash(self._password.encode(), plaintext)

    @classmethod
    def check_password(cls, email, password):
        user = cls.query.filter_by(email=email).first()
        if user is None:
            raise UserDoesNotExist
        if not user.verify_password(password):
            raise PasswordDoesNotMatch
        return user.jwt

    @property
    def jwt(self):
        payload = {
            'exp': datetime.datetime.utcnow()
            + datetime.timedelta(
                seconds=config.jwt_expiration(cast=int, default=DEFAULT_JWT_EXPIRATION)
            ),
            'iat': datetime.datetime.utcnow(),
            'sub': self.id,
        }
        return jwt.encode(
            payload,
            config.secret_key(default=DEFAULT_SECRET_KEY),
            algorithm=config.jwt_algorithm(default=DEFAULT_JWT_ALGORITHM),
        )

    @staticmethod
    def decode_auth_token(auth_token) -> int:
        """Decodes the auth token.

        Parameters
        ----------
        auth_token: The token to decode.

        Returns
        -------
        The id of the user the token belongs to.

        Raises
        ------
        jwt.ExpiredSignatureError
        jwt.InvalidTokenError
        jwt.DecodeError
        """
        if BlacklistToken.check_blacklist(auth_token):
            raise jwt.InvalidTokenError
        return jwt.decode(
            auth_token,
            key=config.secret_key(default=DEFAULT_SECRET_KEY),
            algorithms=[config.jwt_algorithm(default=DEFAULT_JWT_ALGORITHM)],
        )['sub']

    @staticmethod
    def decode_auth_token_role(auth_token) -> str:
        if BlacklistToken.check_blacklist(auth_token):
            raise jwt.InvalidTokenError
        return jwt.decode(
            auth_token,
            key=config.secret_key(default=DEFAULT_SECRET_KEY),
            algorithms=[config.jwt_algorithm(default=DEFAULT_JWT_ALGORITHM)],
        )['role']

    def update_from_dict(self, **kwargs):
        for field, value in kwargs.items():
            setattr(self, field, value)


class User(BaseUser):  # type:ignore
    """User model."""

    # TODO: validate URLs
    profile_picture = db.Column(db.String, nullable=True)
    blocked = db.Column(db.Boolean, default=False)
    wallet_address = db.Column(db.String(256))
    wallet_mnemonic = db.Column(db.String(256))

    @property
    def jwt(self):
        payload = {
            'exp': datetime.datetime.utcnow()
            + datetime.timedelta(
                seconds=config.jwt_expiration(cast=int, default=DEFAULT_JWT_EXPIRATION)
            ),
            'iat': datetime.datetime.utcnow(),
            'sub': self.id,
            'wallet_address': self.wallet_address,
            'wallet_mnemonic': self.wallet_mnemonic,
            'role': 'user',
        }
        return jwt.encode(
            payload, config.secret_key(default=DEFAULT_SECRET_KEY), algorithm='HS256'
        )

    @classmethod
    def check_password(cls, email, password):
        user = cls.query.filter_by(email=email).first()
        if user is None:
            raise UserDoesNotExist
        if user.blocked:
            raise BlockedUser
        if not user.verify_password(password):
            raise PasswordDoesNotMatch
        return user.jwt


class AdminUser(BaseUser):  # type:ignore
    """Admin user model."""

    @property
    def jwt(self):
        payload = {'iat': datetime.datetime.utcnow(), 'sub': self.id, 'role': 'admin'}
        return jwt.encode(
            payload, config.secret_key(default=DEFAULT_SECRET_KEY), algorithm='HS256'
        )


class BlacklistToken(db.Model):  # type:ignore
    """Token Model for storing JWT tokens."""

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False, default=func.now())

    @staticmethod
    def check_blacklist(auth_token):
        if BlacklistToken.query.filter_by(token=str(auth_token)).first() is None:
            return False
        return True
