import logging

import pytest


@pytest.fixture(autouse=True)
def reset_loggers():
    root_handlers = logging.getLogger().handlers[:]
    altsrc_handlers = logging.getLogger("altsrc").handlers[:]
    yield
    logging.getLogger().handlers = root_handlers
    logging.getLogger("altsrc").handlers = altsrc_handlers
