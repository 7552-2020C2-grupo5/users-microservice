"""API module."""
from flask_restx import Api, Resource, fields
from flask import request, Response
from users_microservice.models import db, User, bcrypt
from users_microservice import __version__
import logging
import json

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

MIMETYPE = "application/json"


api = Api(
    prefix="/v1",
    version=__version__,
    title="Users API",
    description="Users microservice for bookbnb",
    default="Users",
    default_label="Users operations",
    validate=True,
)


@api.errorhandler
def handle_exception(error: Exception):
    """When an unhandled exception is raised"""
    message = "Error: " + getattr(error, 'message', str(error))
    return {'message': message}, getattr(error, 'code', 500)


register_model = api.model(
    "User register model",
    {
        "id": fields.Integer(readonly=True, description="The user unique identifier"),
        "first_name": fields.String(required=True, description='The user first name'),
        "last_name": fields.String(required=True, description='The user last name'),
        "email": fields.String(required=True, description='The user email'),
        "password": fields.String(required=True, description='The user password'),
    },
)

login_model = api.model(
    "User login model",
    {
        "email": fields.String(required=True, description='The user email'),
        "password": fields.String(required=True, description='The user password'),
    },
)

profile_model = api.model(
    "User profile model",
    {
        "id": fields.Integer(readonly=True, description="The user unique identifier"),
        "first_name": fields.String(required=True, description='The user first name'),
        "last_name": fields.String(required=True, description='The user last name'),
        "email": fields.String(required=True, description='The user email'),
    },
)


@api.route('/validate_token')
class UserTokenValidatorResource(Resource):
    """
    User Token Validator
    """

    @api.doc('validate_user_token')
    def get(self):
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''

        fail_msg = {'status': 'fail'}
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if isinstance(resp, int):
                msg = {'status': 'success'}
                return Response(json.dumps(msg), status=200, mimetype=MIMETYPE)
            return Response(json.dumps(fail_msg), status=401, mimetype=MIMETYPE)
        else:
            return Response(json.dumps(fail_msg), status=401, mimetype=MIMETYPE)


@api.route('/user')
class UserListResource(Resource):
    @api.doc('list_user')
    @api.marshal_list_with(profile_model)
    def get(self):
        """Get all users."""
        return User.query.all()


@api.route('/user/<int:user_id>')
@api.param('user_id', 'The user unique identifier')
@api.response(404, 'User not found')
class UserResource(Resource):
    @api.doc('get_user')
    @api.marshal_with(profile_model)
    def get(self, user_id):
        """Get a user by id."""
        user = User.query.filter(User.id == user_id).first()
        if not user:
            return None, 404
        return user


@api.route('/register')
class RegisterResource(Resource):
    """
    User Registration Resource
    """

    @api.expect(register_model, validate=True)
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(email=data.get('email')).first()
        if not user:
            user = User(**api.payload)
            db.session.add(user)
            db.session.commit()

            auth_token = user.encode_auth_token(user.id)
            resp = {
                'status': 'success',
                'message': 'Successfully registered.',
                'auth_token': auth_token.decode(),
            }
            msg = json.dumps(resp)
            return Response(msg, status=201, mimetype='application/json')
        else:
            resp = {
                'status': 'fail',
                'message': 'User already exists. Please Log in.',
            }
            msg = json.dumps(resp)
            return Response(msg, status=202, mimetype='application/json')


@api.route('/login')
class LoginResource(Resource):
    """
    User Login Resource
    """

    @api.expect(login_model, validate=True)
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(email=data.get('email')).first()

        if user and bcrypt.check_password_hash(user.password, data.get('password')):
            auth_token = user.encode_auth_token(user.id)
            resp = {
                'status': 'success',
                'message': 'Successfully logged in.',
                'auth_token': auth_token.decode(),
            }
            msg = json.dumps(resp)
            return Response(msg, status=200, mimetype='application/json')

        elif user and not bcrypt.check_password_hash(
            user.password, data.get('password')
        ):
            resp = {'status': 'fail', 'message': 'Password does not match.'}
            msg = json.dumps(resp)
            return Response(msg, status=202, mimetype='application/json')

        else:
            resp = {'status': 'fail', 'message': 'User does not exist.'}
            msg = json.dumps(resp)
            return Response(msg, status=202, mimetype='application/json')
