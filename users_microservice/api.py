"""API module."""

from flask_restx import Api

from users_microservice import __version__
from users_microservice.namespaces.admins import api as admins_namespace
from users_microservice.namespaces.metrics import api as metrics_namespace
from users_microservice.namespaces.users import api as users_namespace

api = Api(
    prefix="/v1",
    version=__version__,
    title="Users API",
    description="Users microservice for bookbnb",
    default="Users",
    default_label="Users operations",
    validate=True,
)
api.add_namespace(users_namespace, path='/users')
api.add_namespace(admins_namespace, path='/admins')
api.add_namespace(metrics_namespace, path='/metrics')


@api.errorhandler
def handle_exception(error: Exception):
    """When an unhandled exception is raised"""
    message = "Error: " + getattr(error, 'message', str(error))
    return {'message': message}, getattr(error, 'code', 500)
