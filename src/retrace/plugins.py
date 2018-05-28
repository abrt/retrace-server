#Singleton class for providing plugins

#heavily inspired by
#  http://python-3-patterns-idioms-test.readthedocs.io/en/latest/Singleton.html
#Each module that needs working with plugins, needs reference on Plugins
#   instance. To obtain all existing plugins, calling method all() should be
#   sufficient enough. List of imported modules is returned.
#If different path to plugins then default is needed, there are 2 options:
#   1) Calling method load() with parameter before any calling of method all()
#   2) Setting environment variable "RETRACE_SERVER_PLUGIN_DIR"
#   Note: No.2 has bigger priority the No.1
#Note: Loading, if not forced by calling load(), is done in first calling of
#   all(). Another calls of all() return the same list. To change this list
#   method load() must be called explicitly.

import os
import sys

class Plugins(object):
    class __plugins:
        def __init__(self):
            self.plugins_read = False
            self.PLUGINS = []

        def load(self, plugin_dir="/usr/share/retrace-server/plugins"):
            self.PLUGINS = []
            self.plugins_read = True
            #if environment variable set, use rather that
            env_plugin_dir = os.environ.get('RETRACE_SERVER_PLUGIN_DIR')
            if env_plugin_dir:
                plugin_dir = env_plugin_dir
            sys.path.insert(0, plugin_dir)

            try:
                files = os.listdir(plugin_dir)
            except Exception as ex:
                print("Unable to list directory '%s': %s" % (plugin_dir, ex))
                raise ImportError, ex

            for filename in files:
                if not filename.startswith("_") and filename.endswith(".py"):
                    pluginname = filename.replace(".py", "")
                    try:
                        this = __import__(pluginname)
                    except:
                        continue
                    if this.__dict__.has_key("distribution") and this.__dict__.has_key("repos"):
                        self.PLUGINS.append(this)

        def all(self):
            if not self.plugins_read:
                self.load()
            return self.PLUGINS

    instance = None
    def __new__(cls,):
        if not Plugins.instance:
            Plugins.instance = Plugins.__plugins()
        return Plugins.instance

    def __getattr__(self, name):
        return getattr(self.instance, name)

    def __setattr__(self, name):
        return setattr(self.instance, name)
