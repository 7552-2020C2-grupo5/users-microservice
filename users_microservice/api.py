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

parser = api.parser()
parser.add_argument('Authorization', type=str, location='headers')


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
    @api.expect(parser, validate=True)
    @api.response(200, "Success")
    @api.response(401, "Invalid token")
    def get(self):
        auth_token = request.headers.get('Authorization')
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if isinstance(resp, int):
                msg = {'status': 'success'}
                return Response(json.dumps(msg), status=200, mimetype=MIMETYPE)
        msg = {'status': 'fail'}
        return Response(json.dumps(msg), status=401, mimetype=MIMETYPE)


@api.route('/profile')
class UserListResource(Resource):
    @api.doc('list_users_profiles')
    @api.marshal_list_with(profile_model)
    def get(self):
        """Get all users."""
        return User.query.all()


@api.route('/profile/<int:user_id>')
@api.param('user_id', 'The user unique identifier')
@api.response(404, 'User not found')
class UserResource(Resource):
    @api.doc('get_user_profile_by_id')
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

    @api.doc('user_register')
    @api.expect(register_model, validate=True)
    @api.response(201, 'Successfully registered')
    @api.response(401, 'User already registered')
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
            return Response(json.dumps(resp), status=201, mimetype=MIMETYPE)
        else:
            resp = {
                'status': 'fail',
                'message': 'User already exists. Please Log in.',
            }
            return Response(json.dumps(resp), status=401, mimetype=MIMETYPE)


@api.route('/login')
class LoginResource(Resource):
    """
    User Login Resource
    """

    @api.expect(login_model, validate=True)
    @api.doc('user_login')
    @api.response(201, "Success")
    @api.response(401, "Password does not match")
    @api.response(404, "User does not exist")
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
            return Response(msg, status=201, mimetype=MIMETYPE)

        elif user and not bcrypt.check_password_hash(
            user.password, data.get('password')
        ):
            resp = {'status': 'fail', 'message': 'Password does not match.'}
            return Response(json.dumps(resp), status=401, mimetype=MIMETYPE)

        else:
            resp = {'status': 'fail', 'message': 'User does not exist.'}
            return Response(json.dumps(resp), status=404, mimetype=MIMETYPE)


@api.route('/logout')
class LogoutAPI(Resource):
    """
    User Logout Resource
    """

    @api.doc('user_logout')
    @api.expect(parser, validate=True)
    @api.response(201, "Success")
    @api.response(401, "Invalid token")
    def post(self):
        auth_token = request.headers.get('Authorization')
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if isinstance(resp, int):
                # blacklist_token = BlacklistToken(token=auth_token)
                # db.session.add(blacklist_token)
                # db.session.commit()
                resp = {'status': 'success', 'message': 'Successfully logged out.'}
                return Response(json.dumps(resp), status=201, mimetype=MIMETYPE)
            else:  # token is not valid
                resp = {'status': 'fail', 'message': resp}
                return Response(json.dumps(resp), status=401, mimetype=MIMETYPE)
        else:
            resp = {'status': 'fail', 'message': 'Provide a valid auth token.'}
            return Response(json.dumps(resp), status=401, mimetype=MIMETYPE)
