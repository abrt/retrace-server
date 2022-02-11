import logging


logger = logging.getLogger(__name__)


def log_debug(msg: str):
    logger.debug(msg)


def log_error(msg: str):
    logger.error(msg)


def log_exception(msg: str):
    logger.debug(msg, exc_info=True)


def log_info(msg: str):
    logger.info(msg)


def log_warn(msg: str):
    logger.warning(msg)
