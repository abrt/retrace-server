# Singleton class for providing plugins

# heavily inspired by
#   http://python-3-patterns-idioms-test.readthedocs.io/en/latest/Singleton.html
# Each module that needs working with plugins, needs reference on Plugins
#    instance. To obtain all existing plugins, calling method all() should be
#    sufficient enough. List of imported modules is returned.
# If different path to plugins then default is needed, there are 2 options:
#    1) Calling method load() with parameter before any calling of method all()
#    2) Setting environment variable "RETRACE_SERVER_PLUGIN_DIR"
#    Note: No.2 has bigger priority the No.1
# Note: Loading, if not forced by calling load(), is done in first calling of
#    all(). Another calls of all() return the same list. To change this list
#    method load() must be called explicitly.

import os
import sys
from importlib import import_module
from pathlib import Path
from types import ModuleType
from typing import Any, List, Optional


class Plugins:
    _instance: Optional[ModuleType] = None

    class _Plugins:
        plugins_read: bool
        plugin_list: List[ModuleType]

        def __init__(self) -> None:
            self.plugin_list = []
            self.plugins_read = False

        def load(self, plugin_dir: Path = Path("/usr/share/retrace-server/plugins")) -> None:
            self.plugin_list = []
            self.plugins_read = True
            # if environment variable set, use rather that
            env_plugin_dir = os.environ.get("RETRACE_SERVER_PLUGIN_DIR")
            if env_plugin_dir:
                plugin_dir = Path(env_plugin_dir)
            sys.path.insert(0, str(plugin_dir))

            try:
                files = list(plugin_dir.iterdir())
            except Exception as ex:
                print("Unable to list directory '%s': %s" % (plugin_dir, ex))
                raise ImportError(ex) from ex

            for filepath in files:
                if not filepath.name.startswith("_") and filepath.suffix == ".py":
                    pluginname = filepath.stem
                    try:
                        this = import_module(pluginname)
                    except Exception: # pylint: disable=broad-except
                        continue
                    if "distribution" in this.__dict__ and "repos" in this.__dict__:
                        self.plugin_list.append(this)

        def all(self) -> List[ModuleType]:
            if not self.plugins_read:
                self.load()
            return self.plugin_list

    def __new__(cls,):
        if not Plugins._instance:
            Plugins._instance = Plugins._Plugins()
        return Plugins._instance

    def __getattr__(self, name: str) -> Any:
        return getattr(self._instance, name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self._instance, name, value)
