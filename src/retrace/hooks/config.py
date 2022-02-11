import configparser
from pathlib import Path
from typing import Dict, List

from retrace.retrace import log_warn

MAIN_CONFIG_PATH = Path("/etc/retrace-server/")
MAIN_HOOK_CONFIG_FILE = Path("retrace-server-hooks.conf")
MAIN_HOOK_CONFIGS_PATH = Path("/etc/retrace-server/hooks")
USER_CONFIG_PATH = Path.home() / ".config/retrace-server/"
USER_HOOK_CONFIGS_PATH = Path.home() / ".config/retrace-server/hooks"
HOOK_PATH = Path("/usr/libexec/retrace-server/hooks/")
HOOK_TIMEOUT = 300


def get_config_files(directory: Path) -> List[Path]:
    if not directory.is_dir():
        log_warn(f"Configuration directory {directory} does not exist")
        return []

    return [fname for fname in directory.iterdir()
            if fname.suffix == ".conf"]


def load_config_files(config_files: List[Path]) -> Dict[str, str]:
    result = {}
    cfg_parser = configparser.ConfigParser()
    cfg_parser.read(config_files)

    for section in cfg_parser.sections():
        for option in cfg_parser.options(section):
            key = f"{section.lower()}.{option.lower()}"
            result[key] = cfg_parser.get(section, option)

    return result


def load_hook_config() -> Dict[str, str]:
    hook_configs: List[Path] = []
    hook_configs += get_config_files(MAIN_HOOK_CONFIGS_PATH)

    main_hook_config_file = Path(MAIN_CONFIG_PATH, MAIN_HOOK_CONFIG_FILE)
    hook_configs.append(main_hook_config_file)

    if USER_HOOK_CONFIGS_PATH.exists():
        hook_configs += get_config_files(USER_HOOK_CONFIGS_PATH)

    if USER_CONFIG_PATH.exists():
        hook_configs.append(USER_CONFIG_PATH)

    cfgs = load_config_files(hook_configs)

    return cfgs


hooks_config = load_hook_config()
