import sqlite3
from typing import Dict

from webob import Request

from retrace.config import Config
from retrace.retrace import get_running_tasks, STATUS_SUCCESS, STATUS_FAIL
from retrace.stats import init_crashstats_db
from retrace.util import free_space, parse_http_gettext, response

CONFIG = Config()

StatsDict = Dict[str, int]

RESPONSE_TEMPLATE = """
# HELP retrace_savedir_free_bytes Free disk space on volume with tasks
# TYPE retrace_savedir_free_bytes gauge
retrace_savedir_free_bytes {savedir_free_bytes}
# HELP retrace_tasks_running Number of retrace workers currently running
# TYPE retrace_tasks_running gauge
retrace_tasks_running {tasks_running}
# HELP retrace_tasks_overload Number of retrace jobs denied because of exceeded capacity
# TYPE retrace_tasks_overload counter
retrace_tasks_overload {tasks_overload}
# HELP Total number of retrace tasks finished
# TYPE retrace_tasks_finished counter
retrace_tasks_finished{{result="fail"}} {tasks_failed}
retrace_tasks_finished{{result="success"}} {tasks_successful}
"""


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


def get_stats(db: sqlite3.Connection) -> StatsDict:
    cursor = db.cursor()

    # Calculate free space left on volume where crashes and tasks are stored.
    savedir_free_bytes = free_space(CONFIG["SaveDir"])

    # Number of tasks (worker processes) currently running.
    tasks_running = len(get_running_tasks())

    tasks_successful = get_num_tasks_successful(db)
    tasks_failed = get_num_tasks_failed(db)

    # Number of tasks denied because of server capacity overload, also called
    # denied tasks. See also 'MaxParallelTasks' option in retrace-server.conf.
    tasks_overload = get_num_tasks_overload(db)

    stats = {
        "savedir_free_bytes": savedir_free_bytes,
        "tasks_failed": tasks_failed,
        "tasks_overload": tasks_overload,
        "tasks_running": tasks_running,
        "tasks_successful": tasks_successful,
    }

    return stats


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

    # Pull together all the required data.
    db = init_crashstats_db()
    stats = get_stats(db)
    db.close()

    # Format the data into format readable by Prometheus.
    body = RESPONSE_TEMPLATE.strip().format(**stats)

    return response(start_response, "200 OK", body)
