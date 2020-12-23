"""Users namespace module."""
import jwt
import sendgrid
from email_validator import EmailNotValidError
from flask_restx import Model, Namespace, Resource, fields, marshal
from sendgrid.helpers.mail import Content, Email, Mail, To

from users_microservice import __version__
from users_microservice.cfg import config
from users_microservice.constants import DEFAULT_RESET_PWD_EMAIL, DEFAULT_RESET_PWD_LEN
from users_microservice.exceptions import (
    BlockedUser,
    EmailAlreadyRegistered,
    PasswordDoesNotMatch,
    UserDoesNotExist,
)
from users_microservice.models import BlacklistToken, User, db
from users_microservice.utils import generate_random_password

api = Namespace("Users", description="Users operations",)

auth_parser = api.parser()
auth_parser.add_argument('Authorization', type=str, location='headers', required=True)


@api.errorhandler(UserDoesNotExist)
def handle_user_does_not_exist(_error: UserDoesNotExist):
    """Handle missing user errors."""
    return {"message": "User does not exist"}, 404


@api.errorhandler(BlockedUser)
def handle_blocked_user(_error: BlockedUser):
    """Handle blocked users."""
    return {"message": "User has been blocked"}, 403


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


@api.route('')
class UserListResource(Resource):
    @api.doc('list_users_profiles')
    @api.marshal_list_with(profile_model)
    def get(self):
        """Get all users."""
        return User.query.filter(User.blocked == False).all()  # noqa: E712

    @api.doc('user_register')
    @api.expect(register_model)
    @api.response(201, 'Successfully registered', model=registered_model)
    @api.response(409, 'User already registered')
    @api.response(400, 'Invalid email')
    def post(self):
        try:
            new_user = User(**api.payload)
            db.session.add(new_user)
            db.session.commit()
            return api.marshal(new_user, registered_model), 201
        except EmailAlreadyRegistered:
            return {"message": "The email has already been registered."}, 409
        except EmailNotValidError:
            return {"message": "The email is not valid"}, 400


@api.route('/<int:user_id>')
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
        if user.blocked:
            raise BlockedUser
        return user

    @api.expect(edit_model)
    @api.marshal_with(profile_model)
    def put(self, user_id):
        """Replace a user by id."""
        user = User.query.filter(User.id == user_id).first()
        if user is None:
            raise UserDoesNotExist
        if user.blocked:
            raise BlockedUser
        user.update_from_dict(**api.payload)
        db.session.merge(user)
        db.session.commit()
        return user

    def delete(self, user_id):
        """Block a user by id."""
        user = User.query.filter(User.id == user_id).first()
        if user is None:
            raise UserDoesNotExist
        if user.blocked:
            raise BlockedUser
        user.blocked = True
        db.session.merge(user)
        db.session.commit()
        return {"message": "The user has been blocked"}, 200


@api.route('/<int:user_id>/reset_password')
@api.param('user_id', 'The user unique identifier')
@api.response(201, 'Success')
@api.response(404, 'User not found')
class ResetPasswordResource(Resource):
    def post(self, user_id):
        """Reset user password"""
        user = User.query.filter(User.id == user_id).first()
        if user is None:
            raise UserDoesNotExist
        if user.blocked:
            raise BlockedUser

        new_pass = generate_random_password(DEFAULT_RESET_PWD_LEN)
        user.password = new_pass
        db.session.merge(user)
        db.session.commit()

        sg = sendgrid.SendGridAPIClient(api_key=config.sendgrid.api_key())

        email = config.reset_pwd_email(default=DEFAULT_RESET_PWD_EMAIL)

        from_email = Email(email)
        to_email = To(user.email)

        subject = "BookBNB - Password Reset"
        content_body = f"Your password has been reset. Your new password is: {new_pass}"
        content = Content("text/plain", content_body)

        mail = Mail(from_email, to_email, subject, content)
        mail_json = mail.get()
        sg.client.mail.send.post(request_body=mail_json)
        return {"status": "success"}, 201


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
            return {"message": "Password does not match."}, 401


@api.route('/logout')
class LogoutResource(Resource):
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
