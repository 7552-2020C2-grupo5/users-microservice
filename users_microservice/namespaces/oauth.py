"""OAuth namespace module."""

import jwt
from flask_restx import Namespace, Resource, fields, reqparse

from users_microservice import __version__
from users_microservice.controllers.oauth import create_oauth_user, oauth_user
from users_microservice.exceptions import BlockedUser, UserDoesNotExist

api = Namespace("OAuth", description="OAuth login operations",)

logged_model = api.model(
    "OAuth logged user", {"token": fields.String(description="BookBNB token")}
)

oauth_parser = api.parser()
oauth_parser.add_argument('Authorization', type=str, location='headers', required=True)

oauth_token_parser = reqparse.RequestParser()
oauth_token_parser.add_argument(
    'token', type=str, required=True, help="The OAuth token"
)

oauth_register_model = api.model(
    "OAuth user register",
    {
        "token": fields.String(required=True, description="The OAuth token"),
        "wallet_address": fields.String(
            required=True, description='The wallet address for the new user'
        ),
        "wallet_mnemonic": fields.String(
            required=True, description='The wallet mnemonic for the new user'
        ),
    },
)

oauth_user_model = api.model(
    "OAuth user model",
    {
        "id": fields.Integer(readonly=True, description="The user unique identifier"),
        "first_name": fields.String(required=True, description='The user first name'),
        "last_name": fields.String(required=True, description='The user last name'),
        "profile_picture": fields.String(
            required=False, description="URL pointing to the user's profile picture"
        ),
        "email": fields.String(required=True, description='The user email'),
        "register_date": fields.DateTime(
            description='The date the user joined bookbnb'
        ),
    },
)


@api.route('/user')
class OAuthUserResource(Resource):
    @api.doc('oauth_user')
    @api.response(200, 'User found')
    @api.response(404, 'User not found')
    @api.expect(oauth_token_parser)
    def get(self):
        """Get all admin users."""
        args = oauth_token_parser.parse_args()
        user = oauth_user(args.token)

        if user is None:
            return {"message": "User does not exist"}, 404
        return api.marshal(user, oauth_user_model), 200

    @api.doc('oauth_register')
    @api.expect(oauth_register_model)
    @api.response(200, "OAuth register successful", oauth_user_model)
    @api.response(400, "Malformed token")
    @api.response(401, "Unable to authenticate")
    def post(self):
        try:
            user = create_oauth_user(**api.payload)
            return api.marshal(user, oauth_user_model)
        except jwt.DecodeError:
            return {"message": "The token sent was malformed."}, 400
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError,) as e:
            api.logger.error("Error: ", exc_info=e)
            return {"message": f"{e}"}, 401


@api.route('/login')
class OAuthLogin(Resource):
    """OAuth login resource."""

    @api.doc('oauth_login')
    @api.expect(oauth_token_parser)
    @api.response(201, "Success")
    @api.response(401, "Invalid token")
    @api.response(403, "User is blocked")
    def post(self):
        token = oauth_token_parser.parse_args().token
        user = oauth_user(token)
        if user is None:
            raise UserDoesNotExist
        if user.blocked:
            raise BlockedUser
        try:
            return api.marshal({"token": user.jwt}, logged_model), 201
        except Exception as e:  # noqa: E722 pylint: disable=bare-except,broad-except
            return {"message": f"Error on OAuth login: {e}"}, 401
