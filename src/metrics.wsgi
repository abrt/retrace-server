import contextlib
import sqlite3
from typing import Dict

from prometheus_client.core import (
    CounterMetricFamily,
    GaugeMetricFamily,
    REGISTRY,
)
from prometheus_client.exposition import generate_latest
from webob import Request

from retrace.config import Config
from retrace.retrace import get_running_tasks, STATUS_SUCCESS, STATUS_FAIL
from retrace.stats import init_crashstats_db
from retrace.util import free_space, parse_http_gettext, response

CONFIG = Config()

StatsDict = Dict[str, int]


class RetraceCollector:
    def __init__(self, db: sqlite3.Connection) -> None:
        self._db = db

    def collect(self):
        # Calculate free space left on volume where crashes and tasks are stored.
        savedir_free_bytes = free_space(CONFIG["SaveDir"])

        # Number of tasks (worker processes) currently running.
        tasks_running = len(get_running_tasks())

        tasks_successful = get_num_tasks_successful(self._db)
        tasks_failed = get_num_tasks_failed(self._db)

        # Number of tasks denied because of server capacity overload, also called
        # denied tasks. See also 'MaxParallelTasks' option in retrace-server.conf.
        tasks_overload = get_num_tasks_overload(self._db)

        yield GaugeMetricFamily(
            "retrace_savedir_free_bytes",
            "Free disk space on volume with tasks",
            value=savedir_free_bytes,
            unit="bytes"
        )
        yield GaugeMetricFamily(
            "retrace_tasks_running",
            "Number of retrace workers currently running",
            value=tasks_running
        )
        yield CounterMetricFamily(
            "retrace_tasks_overload",
            "Number of retrace jobs denied because of exceeded capacity",
            value=tasks_overload)

        finished = CounterMetricFamily(
            "retrace_tasks_finished",
            "Total number of retrace tasks finished",
            labels=["result"]
        )
        finished.add_metric(["fail"], tasks_failed)
        finished.add_metric(["success"], tasks_successful)
        yield finished


def get_num_tasks_failed(db: sqlite3.Connection) -> int:
    cursor = db.cursor()

    result = cursor.execute("SELECT COUNT(*) FROM tasks WHERE status = ?",
                            (STATUS_FAIL,)).fetchone()

    return result[0]


def get_num_tasks_successful(db: sqlite3.Connection) -> int:
    cursor = db.cursor()

    result = cursor.execute("SELECT COUNT(*) FROM tasks WHERE status = ?",
                            (STATUS_SUCCESS,)).fetchone()

    return result[0]


def get_num_tasks_overload(db: sqlite3.Connection) -> int:
    cursor = db.cursor()

    result = cursor.execute("SELECT COUNT(*) FROM reportfull").fetchone()

    return result[0]


def application(environ, start_response):
    request = Request(environ)

    _ = parse_http_gettext("%s" % request.accept_language,
                           "%s" % request.accept_charset)

    if CONFIG["RequireHTTPS"] and request.scheme != "https":
        return response(start_response, "403 Forbidden",
                        _("You must use HTTPS"))

    if not CONFIG["AllowMetrics"]:
        return response(start_response, "403 Forbidden",
                        _("Metrics are not enabled for this server"))

    with contextlib.closing(init_crashstats_db()) as db:
        # Pull together all the required data.
        REGISTRY.register(RetraceCollector(db))

        # Format the data into format readable by Prometheus.
        body = generate_latest(REGISTRY)

    return response(start_response, "200 OK", body)
