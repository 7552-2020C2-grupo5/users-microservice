"""SQLAlchemy models."""
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy_utils.types.email import EmailType

db = SQLAlchemy()


class User(db.Model):  # type:ignore
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String)
    last_name = db.Column(db.String)
    email = db.Column(EmailType)
