"""API module."""
from flask_restx import Api, Resource, fields
from users_microservice.models import db, User
from users_microservice import __version__
import logging

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


@api.errorhandler
def handle_exception(error: Exception):
    """When an unhandled exception is raised"""
    message = "Error: " + getattr(error, 'message', str(error))
    return {'message': message}, getattr(error, 'code', 500)


user_model = api.model(
    "User",
    {
        "id": fields.Integer(readonly=True, description="The user unique identifier"),
        "first_name": fields.String(required=True, description='The name'),
        "last_name": fields.String(required=True, description='The last name'),
        "email": fields.String(required=True, description='The email'),
    },
)


@api.route('/user')
class UserListResource(Resource):
    @api.doc('list_user')
    @api.marshal_list_with(user_model)
    def get(self):
        """Get all users."""
        return User.query.all()

    @api.doc('create_user')
    @api.expect(user_model)
    @api.marshal_with(user_model, envelope='resource')
    def post(self):
        """Create a new user."""
        new_user = User(**api.payload)
        db.session.add(new_user)
        db.session.commit()
        return new_user


@api.route('/user/<int:user_id>')
@api.param('user_id', 'The user unique identifier')
@api.response(404, 'User not found')
class UserResource(Resource):
    @api.doc('get_user')
    @api.marshal_with(user_model, envelope='resource')
    def get(self, user_id):
        """Get a user by id."""
        user = User.query.filter(User.id == user_id).first()
        return user
