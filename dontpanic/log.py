import logging
import logging.handlers
import os


logger = logging.getLogger(__name__)
# Don't log (in python 2.7 we could set a NullHandler)
logger.setLevel('CRITICAL')


def get_logger(logdir=None, debug=False):
    """Return a logger for the dontpanic script."""
    logname = 'dontpanic.log'

    logdir = logdir or '.'
    debug = debug or False

    logger = logging.getLogger(__name__)

    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    logfile_handler = logging.handlers.RotatingFileHandler(
        os.path.join(logdir, logname)
    )
    stream_handler = logging.StreamHandler()

    logger.addHandler(logfile_handler)
    logger.addHandler(stream_handler)

    logger.debug("Dontpanic script started ...")

    return logger
