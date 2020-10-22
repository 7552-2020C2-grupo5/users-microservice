"""API module."""
from flask_restx import Api, Resource, reqparse, fields
from users_microservice.models import db, User

api = Api(prefix="/v1")

user_model = api.model(
    "User", {"nombre": fields.String, "apellido": fields.String, "email": fields.String}
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

    @api.doc('create_user')
    @api.marshal_with(user_model, envelope='resource')
    def put(self, user_id):
        """Create a new user."""
        parser = reqparse.RequestParser()
        parser.add_argument('nombre', type=str, help='The name of the user')
        parser.add_argument('apellido', type=str, help='The lastname of the user')
        parser.add_argument('email', type=str, help='The email of the user')
        args = parser.parse_args(strict=True)
        new_user = User(
            id=user_id, nombre=args.nombre, apellido=args.apellido, email=args.email,
        )
        db.session.add(new_user)
        db.session.commit()
        return new_user
