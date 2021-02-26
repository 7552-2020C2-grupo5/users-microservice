"""Metrics controller."""
from datetime import timedelta as td

from sqlalchemy import func

from users_microservice.models import User


def prepare(name, query, cols):
    return {"name": name, "data": [dict(zip(cols, r)) for r in query]}


def pad(metric, start_date, end_date):
    dates = [d.get("date") for d in metric.get("data")]

    current_date = start_date

    while current_date <= end_date:
        if current_date.isoformat() not in dates:
            metric["data"].append({"date": current_date.isoformat(), "value": 0})
        current_date += td(days=1)

    metric["data"] = sorted(metric["data"], key=lambda x: x.get("date"))

    return metric


def new_users_per_day(start_date, end_date):
    count = (
        User.query.filter(func.date(User.register_date).between(start_date, end_date))
        .with_entities(func.date(User.register_date), func.count(User.id))
        .group_by(func.date(User.register_date))
        .order_by(func.date(User.register_date))
        .all()
    )
    metric = prepare("new_users_per_day", count, ["date", "value"])
    metric = pad(metric, start_date, end_date)
    return metric


all_metrics = [new_users_per_day]
