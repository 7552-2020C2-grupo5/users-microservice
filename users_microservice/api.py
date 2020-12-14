"""API module."""
from flask_restx import Api, Resource, fields, marshal, Model
from users_microservice.models import db, User, BlacklistToken
from users_microservice import __version__
import logging
import jwt
from users_microservice.exceptions import (
    UserDoesNotExist,
    PasswordDoesNotMatch,
    EmailAlreadyRegistered,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

api = Api(
    prefix="/v1",
    version=__version__,
    title="Users API",
    description="Users microservice for bookbnb",
    default="Users",
    default_label="Users operations",
    validate=True,
)

auth_parser = api.parser()
auth_parser.add_argument('Authorization', type=str, location='headers', required=True)


@api.errorhandler(UserDoesNotExist)
def handle_user_does_not_exist(_error: UserDoesNotExist):
    """Handle missing user errors."""
    return {"message": "User does not exist"}, 404


@api.errorhandler
def handle_exception(error: Exception):
    """When an unhandled exception is raised"""
    message = f"Error: {getattr(error, 'message', str(error))}"
    return {"message": message}, getattr(error, 'code', 500)


base_user_model = Model(
    "User base model",
    {
        "id": fields.Integer(readonly=True, description="The user unique identifier"),
        "first_name": fields.String(required=True, description='The user first name'),
        "last_name": fields.String(required=True, description='The user last name'),
        "profile_picture": fields.String(
            required=False, description="URL pointing to the user's profile picture"
        ),
        "email": fields.String(required=True, description='The user email'),
    },
)

edit_model = api.model(
    "User edit model",
    {
        "first_name": fields.String(required=False, description='The user first name'),
        "last_name": fields.String(required=False, description='The user last name'),
        "profile_picture": fields.String(
            required=False, description="URL pointing to the user's profile picture"
        ),
        "email": fields.String(required=False, description='The user email'),
    },
)

profile_model = base_user_model.clone(
    "User profile model",
    {"register_date": fields.DateTime(description='The date the user joined bookbnb')},
)
api.models[profile_model.name] = profile_model


register_model = base_user_model.clone(
    "User register model",
    {
        "password": fields.String(
            required=True, description='The password for the new user'
        ),
    },
)
api.models[register_model.name] = register_model


registered_model = profile_model.clone(
    "New user model",
    {
        "token": fields.String(
            required=True, attribute='password', description='The jwt'
        )
    },
)
api.models[registered_model.name] = registered_model


login_model = api.model(
    "User login model",
    {
        "email": fields.String(required=True, description='The user email'),
        "password": fields.String(required=True, description='The user password'),
    },
)

decoded_token_model = api.model("Logged in User model", {"token": fields.String})


@api.route('/users')
class UserListResource(Resource):
    @api.doc('list_users_profiles')
    @api.marshal_list_with(profile_model)
    def get(self):
        """Get all users."""
        return User.query.all()

    @api.doc('user_register')
    @api.expect(register_model)
    @api.response(201, 'Successfully registered', model=registered_model)
    @api.response(409, 'User already registered')
    def post(self):
        try:
            new_user = User(**api.payload)
            db.session.add(new_user)
            db.session.commit()

            return api.marshal(new_user, registered_model), 201
        except EmailAlreadyRegistered:
            return {"message": "The email has already been registered."}, 409


@api.route('/users/<int:user_id>')
@api.param('user_id', 'The user unique identifier')
@api.response(404, 'User not found')
class UserResource(Resource):
    @api.doc('get_user_profile_by_id')
    @api.marshal_with(profile_model)
    def get(self, user_id):
        """Get a user by id."""
        user = User.query.filter(User.id == user_id).first()
        if user is None:
            raise UserDoesNotExist
        return user

    @api.expect(edit_model)
    @api.marshal_with(registered_model)
    def put(self, user_id):
        """Replace a user by id."""
        user = User.query.filter(User.id == user_id).first()
        if user is None:
            raise UserDoesNotExist
        user.update_from_dict(**api.payload)
        db.session.merge(user)
        db.session.commit()
        return user


@api.route('/validate_token')
class UserTokenValidatorResource(Resource):
    """User Token Validator"""

    @api.doc('validate_user_token')
    @api.expect(auth_parser)
    @api.response(200, "Success")
    @api.response(401, "Invalid token")
    @api.response(400, "Malformed token")
    def get(self):
        parser_args = auth_parser.parse_args()
        auth_token = parser_args.Authorization
        try:
            User.decode_auth_token(auth_token)
            return {"status": "success"}, 200
        except jwt.DecodeError:
            return {"message": "The token sent was malformed."}, 400
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError,) as e:
            return {"message": str(e)}, 401


@api.route('/login')
class LoginResource(Resource):
    """User Login Resource"""

    @api.expect(login_model)
    @api.doc('user_login')
    @api.response(201, "Success")
    @api.response(401, "Invalid credentials")
    def post(self):
        try:
            return (
                marshal(
                    {"token": User.check_password(**api.payload)}, decoded_token_model
                ),
                201,
            )
        except PasswordDoesNotMatch:
            return {"message": "Password does not match."}, 402


@api.route('/logout')
class LogoutAPI(Resource):
    """User Logout Resource."""

    @api.doc('user_logout')
    @api.expect(auth_parser)
    @api.response(201, "Success")
    @api.response(401, "Invalid token")
    def post(self):
        parser_args = auth_parser.parse_args()
        auth_token = parser_args.Authorization
        try:
            User.decode_auth_token(auth_token)
            blacklist_token = BlacklistToken(token=auth_token)
            db.session.add(blacklist_token)
            db.session.commit()
            return {'status': 'success', 'message': 'Successfully logged out.'}, 201
        except jwt.ExpiredSignatureError:
            return {"message": "Signature expired. Please log in again."}, 401
        except jwt.InvalidTokenError:
            return {"message": "Invalid token. Please log in again."}, 401
