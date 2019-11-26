#!/usr/bin/python3

import itertools
import multiprocessing as mp
import os
import shlex

from subprocess import PIPE, CalledProcessError, run, TimeoutExpired

from retrace.retrace import log_info, log_error, log_debug
from .config import HOOK_PATH, HOOK_TIMEOUT, hooks_config

"""
    Hooks description:
    pre_start -- When self.start() is called
    start -- When task type is determined and the main task starts
    pre_prepare_debuginfo -- Before the preparation of debuginfo packages
    post_prepare_debuginfo -- After the preparation of debuginfo packages
    pre_prepare_mock -- Before the preparation of mock environment
    post_prepare_mock -- After the preparation of mock environment
    pre_retrace -- Before starting of the retracing itself
    post_retrace -- After retracing is done
    success -- After retracing success
    fail -- After retracing fails
    pre_remove_task -- Before removing task
    post_remove_task -- After removing task
    pre_clean_task -- Before cleaning task
    post_clean_task -- After cleaning task
"""


def get_executables(path):
    """ Scan `path` and return list of found executable scripts.
    """
    def _getname(entry):
        return entry.name

    script_list = []

    if not os.path.isdir(path):
        return script_list

    with os.scandir(path) as dirls:
        for entry in sorted(dirls, key=_getname):
            if entry.is_file() and os.access(entry.path, os.X_OK):
                script_list.append(entry.path)

    return script_list


class RetraceHook:

    def __init__(self, task):
        self.taskid = task.get_taskid()
        self.task_results_dir = task.get_results_dir()

    def _get_cmdline(self, hook, exc=None):
        if exc:
            cmdline = hooks_config.get(f"{hook}.{exc}.cmdline", None)

        if not cmdline:
            cmdline = hooks_config.get(f"{hook}.cmdline", None)

        if cmdline:
            cmdline = cmdline.format(hook_name=hook,
                                     taskid=self.taskid,
                                     task_results_dir=self.task_results_dir)

        return cmdline

    def _get_hookdir(self):
        hooks_path = hooks_config.get("main.hookdir", HOOK_PATH)

        return hooks_path

    def _get_timeout(self, hook):
        timeout = hooks_config.get("main.timeout", HOOK_TIMEOUT)

        if f"{hook}.timeout" in hooks_config:
            timeout = hooks_config.get(f"{hook}.timeout", timeout)

        return int(timeout)

    def _process_script(self, hook, hook_path, timeout, exc_path):
        exc = os.path.basename(exc_path)
        script = exc_path

        log_debug(f"Running '{hook}' hook - script '{exc}'")
        hook_cmdline = self._get_cmdline(hook, exc)

        if hook_cmdline:
            script = shlex.quote(f"{script} {hook_cmdline}")

        script = shlex.split(script)

        try:
            child = run(script, shell=True, timeout=timeout, cwd=hook_path,
                        stdout=PIPE, stderr=PIPE, encoding='utf-8')
            child.check_returncode()
        except TimeoutExpired as ex:
            if ex.stdout:
                log_info(ex.stdout)
            if ex.stderr:
                log_error(ex.stderr)
            log_error(f"Hook script '{exc}' timed out in {ex.timeout} seconds.")
        except CalledProcessError as ex:
            if ex.stdout:
                log_info(ex.stdout)
            if ex.stderr:
                log_error(ex.stderr)
            log_error(f"Hook script '{exc}' failed with exit status {ex.returncode}.")
        else:
            if child.stdout:
                log_info(child.stdout)
            if child.stderr:
                log_error(child.stderr)

    def run(self, hook):
        """Called by the default hook implementations"""
        hook_path = os.path.join(self._get_hookdir(), hook)
        executables = get_executables(hook_path)
        timeout = self._get_timeout(hook)

        params = itertools.product([hook], [hook_path], [timeout], executables)

        with mp.Pool() as hook_pool:
            hook_pool.starmap(self._process_script, params)
