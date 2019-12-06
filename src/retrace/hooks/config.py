#!/bin/python3
import os
import configparser
from pathlib import Path

MAIN_CONFIG_PATH = "/etc/retrace-server/"
MAIN_HOOK_CONFIG_FILE = "retrace-server-hooks.conf"
MAIN_HOOK_CONFIGS_PATH = "/etc/retrace-server/hooks"
USER_CONFIG_PATH = Path.home() / ".config/retrace-server/"
USER_HOOK_CONFIGS_PATH = Path.home() / ".config/retrace-server/hooks"
HOOK_PATH = "/usr/libexec/retrace-server/hooks/"
HOOK_TIMEOUT = 300


def get_config_files(directory):
    return [fname for fname in [os.path.abspath(os.path.join(directory, filename.name))
                                for filename in os.scandir(directory) if filename.name.endswith(".conf")]]


def load_config_files(config_files):
    result = {}
    cfg_parser = configparser.ConfigParser()
    cfg_parser.read(config_files)

    for section in cfg_parser.sections():
        for option in cfg_parser.options(section):
            key = f"{section.lower()}.{option.lower()}"
            result[key] = cfg_parser.get(section, option)

    return result


def load_hook_config():
    hook_configs = []
    hook_configs += get_config_files(MAIN_HOOK_CONFIGS_PATH)

    main_hook_config_file = Path(MAIN_CONFIG_PATH, MAIN_HOOK_CONFIG_FILE)
    hook_configs.append(str(main_hook_config_file))

    if USER_HOOK_CONFIGS_PATH.exists():
        hook_configs += get_config_files(USER_HOOK_CONFIGS_PATH)

    if USER_CONFIG_PATH.exists():
        hook_configs.append(str(USER_CONFIG_PATH))

    cfgs = load_config_files(hook_configs)

    return cfgs


hooks_config = load_hook_config()
