"""SQLAlchemy models."""
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy_utils.types.email import EmailType
from users_microservice.cfg import SECRET_KEY
from flask_bcrypt import Bcrypt
import datetime
import jwt

db = SQLAlchemy()
bcrypt = Bcrypt()


class User(db.Model):  # type:ignore
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String, nullable=False)
    last_name = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    email = db.Column(EmailType, unique=True, nullable=False)

    def __init__(self, first_name, last_name, email, password):
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.password = bcrypt.generate_password_hash(password).decode()

    @staticmethod
    def encode_auth_token(user_id):
        """
        Generates the Auth Token
        :return: string
        """
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=5),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id,
        }
        return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    @staticmethod
    def decode_auth_token(auth_token):
        """
        Decodes the auth token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, SECRET_KEY)
            return payload['sub']
        except jwt.ExpiredSignatureError:
            return "Signature expired. Please log in again."
        except jwt.InvalidTokenError:
            return "Invalid token. Please log in again."
