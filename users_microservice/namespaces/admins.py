"""Admin users namespace module."""
import operator as ops

import jwt
from email_validator import EmailNotValidError
from flask_restx import Model, Namespace, Resource, fields, marshal, reqparse

from users_microservice import __version__
from users_microservice.exceptions import (
    EmailAlreadyRegistered,
    PasswordDoesNotMatch,
    UserDoesNotExist,
)
from users_microservice.models import AdminUser, BlacklistToken, db
from users_microservice.utils import FilterParam

api = Namespace("Admin Users", description="Admin Users operations",)

auth_parser = api.parser()
auth_parser.add_argument('Authorization', type=str, location='headers', required=True)


@api.errorhandler(UserDoesNotExist)
def handle_user_does_not_exist(_error: UserDoesNotExist):
    """Handle missing user errors."""
    return {"message": "User does not exist"}, 404


base_user_model = Model(
    "Admin User base model",
    {
        "id": fields.Integer(readonly=True, description="The user unique identifier"),
        "first_name": fields.String(required=True, description='The user first name'),
        "last_name": fields.String(required=True, description='The user last name'),
        "email": fields.String(required=True, description='The user email'),
    },
)

edit_model = api.model(
    "Admin user edit model",
    {
        "first_name": fields.String(required=False, description='The user first name'),
        "last_name": fields.String(required=False, description='The user last name'),
        "email": fields.String(required=False, description='The user email'),
    },
)

profile_model = base_user_model.clone(
    "Admin user profile model",
    {"register_date": fields.DateTime(description='The date the user joined bookbnb')},
)
api.models[profile_model.name] = profile_model


register_model = base_user_model.clone(
    "Admin user register model",
    {
        "password": fields.String(
            required=True, description='The password for the new user'
        ),
    },
)
api.models[register_model.name] = register_model


registered_model = profile_model.clone(
    "New admin user model",
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


admin_user_parser = reqparse.RequestParser()
admin_user_parser.add_argument(
    "first_name",
    type=FilterParam("first_name", ops.contains, schema=str),
    help="First name to filter on",
    store_missing=False,
)
admin_user_parser.add_argument(
    "last_name",
    type=FilterParam("last_name", ops.contains, schema=str),
    help="Last name to filter on",
    store_missing=False,
)
admin_user_parser.add_argument(
    "email",
    type=FilterParam("email", ops.contains, schema=str),
    help="Email to filter on",
    store_missing=False,
)


@api.route('')
class AdminUserListResource(Resource):
    @api.doc('list_admin_users_profiles')
    @api.marshal_list_with(profile_model)
    @api.expect(admin_user_parser)
    def get(self):
        """Get all admin users."""
        params = admin_user_parser.parse_args()

        query = AdminUser.query
        for _, filter_op in params.items():
            if not isinstance(filter_op, FilterParam):
                continue
            query = filter_op.apply(query, AdminUser)

        return query.all()

    @api.doc('admin_user_register')
    @api.expect(register_model)
    @api.response(201, 'Successfully registered', model=registered_model)
    @api.response(409, 'Admin user already registered')
    @api.response(400, 'Bad request')
    def post(self):
        try:
            new_user = AdminUser(**api.payload)
            db.session.add(new_user)
            db.session.commit()

            return api.marshal(new_user, registered_model), 201
        except EmailAlreadyRegistered:
            return {"message": "The email has already been registered."}, 409
        except EmailNotValidError as e:
            return {"message": str(e)}, 400


@api.route('/<int:user_id>')
@api.param('user_id', 'The admin user unique identifier')
@api.response(404, 'Admin user not found')
class AdminUserResource(Resource):
    @api.doc('get_admin_user_profile')
    @api.marshal_with(profile_model)
    def get(self, user_id):
        """Get an admin user by id."""
        user = AdminUser.query.filter(AdminUser.id == user_id).first()
        if user is None:
            raise UserDoesNotExist
        return user

    @api.expect(edit_model)
    @api.marshal_with(profile_model)
    def put(self, user_id):
        """Replace an admin user by id."""
        user = AdminUser.query.filter(AdminUser.id == user_id).first()
        if user is None:
            raise UserDoesNotExist
        user.update_from_dict(**api.payload)
        db.session.merge(user)
        db.session.commit()
        return user


@api.route('/validate_token')
class UserTokenValidatorResource(Resource):
    """Admin user token validation"""

    @api.doc('validate_admin_user_token')
    @api.expect(auth_parser)
    @api.response(200, "Success")
    @api.response(401, "Invalid token")
    @api.response(400, "Malformed token")
    def get(self):
        parser_args = auth_parser.parse_args()
        auth_token = parser_args.Authorization
        try:
            AdminUser.decode_auth_token(auth_token)
            return {"status": "success"}, 200
        except jwt.DecodeError:
            return {"message": "The token sent was malformed."}, 400
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError,) as e:
            return {"message": str(e)}, 401


@api.route('/login')
class AdminLoginResource(Resource):
    """Admin user login"""

    @api.expect(login_model)
    @api.doc('admin_user_login')
    @api.response(201, "Success")
    @api.response(401, "Invalid credentials")
    def post(self):
        try:
            return (
                marshal(
                    {"token": AdminUser.check_password(**api.payload)},
                    decoded_token_model,
                ),
                201,
            )
        except (PasswordDoesNotMatch, UserDoesNotExist):
            return {"message": "Invalid credentials"}, 401


@api.route('/logout')
class AdminLogout(Resource):
    """Admin user logout"""

    @api.doc('admin_user_logout')
    @api.expect(auth_parser)
    @api.response(201, "Success")
    @api.response(401, "Invalid token")
    def post(self):
        parser_args = auth_parser.parse_args()
        auth_token = parser_args.Authorization
        try:
            AdminUser.decode_auth_token(auth_token)
            blacklist_token = BlacklistToken(token=auth_token)
            db.session.add(blacklist_token)
            db.session.commit()
            return {'status': 'success', 'message': 'Successfully logged out.'}, 201
        except jwt.ExpiredSignatureError:
            return {"message": "Signature expired. Please log in again."}, 401
        except jwt.InvalidTokenError:
            return {"message": "Invalid token. Please log in again."}, 401
