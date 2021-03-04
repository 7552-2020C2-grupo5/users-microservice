"""Token namespace module."""

from flask_restx import Namespace, Resource, fields

from users_microservice.constants import BOOKBNB_TOKEN
from users_microservice.exceptions import ServerTokenError

from .controller import add_end_var, remove_env_var

ns = Namespace("Server tokens", description="Register server tokens")

server_token_model = ns.model("Server token", {"token": fields.String(required=True)})


@ns.route('')
class ServerTokenResource(Resource):
    @ns.doc('add_server_token')
    @ns.expect(server_token_model)
    @ns.response(200, "Server token removed")
    @ns.response(500, "Error processing request")
    def post(self):
        """Register server token."""
        try:
            data = ns.payload
            add_end_var(BOOKBNB_TOKEN, data.get("token"))
            return {"message": "success"}, 200
        except ServerTokenError as e:
            ns.logger.error("Error setting server token", exc_info=e)
            return {"message": f"{e}"}, 500

    @ns.response(200, "Server token removed")
    @ns.response(500, "Error processing request")
    @ns.doc('remove_server_token')
    def delete(self):
        """Remove set server token."""
        try:
            remove_env_var(BOOKBNB_TOKEN)
            return {"message": "success"}, 200
        except ServerTokenError as e:
            ns.logger.error("Error deleting server token", exc_info=e)
            return {"message": "Internal error"}, 500
