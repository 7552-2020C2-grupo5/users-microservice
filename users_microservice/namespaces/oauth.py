"""OAuth namespace module."""

import jwt
from flask_restx import Namespace, Resource, fields, reqparse

from users_microservice import __version__
from users_microservice.controllers.oauth import create_oauth_user, oauth_user
from users_microservice.models import BlacklistToken, db

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
    @api.marshal_with(oauth_user_model)
    def post(self):
        user = create_oauth_user(**api.payload)
        return user


@api.route('/login')
class OAuthLogin(Resource):
    """OAuth login resource."""

    @api.doc('oauth_login')
    @api.expect(oauth_token_parser)
    @api.response(201, "Success")
    @api.response(401, "Invalid token")
    def post(self):
        try:
            token = oauth_token_parser.parse_args().token
            return api.marshal({"token": oauth_user(token).jwt}, logged_model), 201
        except:  # noqa: E722 pylint: disable=bare-except
            return {"message": "Error on OAuth login"}, 401


@api.route('/logout')
class OAuthLogout(Resource):
    """OAuth user logout resource."""

    @api.doc('oauth_logout')
    @api.expect(oauth_parser)
    @api.response(201, "Success")
    @api.response(401, "Invalid token")
    def post(self):
        parser_args = oauth_parser.parse_args()
        auth_token = parser_args.Authorization
        try:
            auth_token = api.payload.get("token")
            blacklist_token = BlacklistToken(token=auth_token)
            db.session.add(blacklist_token)
            db.session.commit()
            return {'status': 'success', 'message': 'Successfully logged out.'}, 201
        except jwt.ExpiredSignatureError:
            return {"message": "Signature expired. Please log in again."}, 401
        except jwt.InvalidTokenError:
            return {"message": "Invalid token. Please log in again."}, 401
