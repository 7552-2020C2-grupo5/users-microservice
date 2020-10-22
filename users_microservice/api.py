"""API module."""
from flask_restx import Api, Resource, fields
from users_microservice.models import db, User

api = Api(prefix="/v1")

user_model = api.model(
    "User",
    {
        "first_name": fields.String(description='The name'),
        "last_name": fields.String(description='The last name'),
        "email": fields.String(description='The email'),
    },
)


@api.route('/user')
class UserListResource(Resource):
    @api.doc('list_user')
    @api.marshal_list_with(user_model)
    def get(self):
        """Get all users."""
        return User.query.all()


@api.route('/user/<int:user_id>')
@api.param('user', 'The user unique identifier')
@api.response(404, 'User not found')
class UserResource(Resource):
    @api.doc('get_user')
    @api.marshal_with(user_model, envelope='resource')
    def get(self, user_id):
        """Get a user by id."""
        user = User.query.filter(User.id == user_id).first()
        return user

    @api.doc('create_user', body=user_model, validate=True)
    @api.marshal_with(user_model, envelope='resource')
    def post(self, user_id):
        """Create a new user."""
        new_user = User(
            id=user_id,
            first_name=api.payload.first_name,
            last_name=api.payload.last_name,
            email=api.payload.email,
        )
        db.session.add(new_user)
        db.session.commit()
        return new_user
