"""Metrics namespace module."""

from flask_restx import Namespace, Resource, fields, inputs, reqparse

from users_microservice import __version__
from users_microservice.controllers.metrics import all_metrics as all_metrics

api = Namespace("Metrics", description="Metrics operations",)

metrics_parser = reqparse.RequestParser()
metrics_parser.add_argument(
    "start_date", type=inputs.date_from_iso8601, help="initial date", required=True
)
metrics_parser.add_argument(
    "end_date", type=inputs.date_from_iso8601, help="final date", required=True
)

metric_datum_model = api.model(
    "Metric datum",
    {
        "date": fields.Date(required=True, description="The date of the datum"),
        "value": fields.Float(required=True, description="The value of the datum"),
    },
)

metric_model = api.model(
    "Metric",
    {
        "name": fields.String(),
        "data": fields.List(fields.Nested(metric_datum_model, description="The data")),
    },
)


@api.route('')
class MetricsListResource(Resource):
    @api.doc('list_metrics')
    @api.marshal_list_with(metric_model)
    @api.expect(metrics_parser)
    def get(self):
        """Get all metrics."""
        params = metrics_parser.parse_args()
        return [m(params.start_date, params.end_date) for m in all_metrics]
