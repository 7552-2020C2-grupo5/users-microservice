"""SQLAlchemy models."""
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy_utils.types.email import EmailType
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import validates
from users_microservice.cfg import config
from users_microservice.constants import DEFAULT_SECRET_KEY
from users_microservice.exceptions import (
    UserDoesNotExist,
    PasswordDoesNotMatch,
    EmailAlreadyRegistered,
)
from flask_bcrypt import Bcrypt
import datetime
import jwt
from sqlalchemy.sql import func

db = SQLAlchemy()
bcrypt = Bcrypt()


class User(db.Model):  # type:ignore
    """User model."""

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String, nullable=False)
    last_name = db.Column(db.String, nullable=False)
    _password = db.Column(db.String, nullable=False)
    email = db.Column(EmailType, unique=True, nullable=False)

    @hybrid_property
    def password(self):
        return self.jwt

    @password.setter  # type: ignore
    def password(self, plaintext):
        self._password = bcrypt.generate_password_hash(plaintext).decode()

    @validates("email")
    def validate_email(self, _key, email_address):
        if User.query.filter(User.email == email_address).first() is not None:
            raise EmailAlreadyRegistered
        return email_address

    def verify_password(self, plaintext):
        return bcrypt.check_password_hash(self.password, plaintext)

    @staticmethod
    def check_password(email, plaintext):
        user = User.query.filter_by(email=email).first()
        if user is None:
            raise UserDoesNotExist
        if not user.verify_password(plaintext):
            raise PasswordDoesNotMatch
        return user.jwt

    @property
    def jwt(self):
        payload = {
            'exp': datetime.datetime.utcnow()
            + datetime.timedelta(seconds=config.jwt_expiration(cast=int)),
            'iat': datetime.datetime.utcnow(),
            'sub': self.id,
        }
        return jwt.encode(
            payload, config.secret_key(default=DEFAULT_SECRET_KEY), algorithm='HS256'
        ).decode()

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
        """
        if BlacklistToken.check_blacklist(auth_token):
            raise jwt.InvalidTokenError
        return jwt.decode(auth_token, config.secret_key(default=DEFAULT_SECRET_KEY))[
            'sub'
        ]


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
