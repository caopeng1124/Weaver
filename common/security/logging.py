"""Scrub the fully formatted record, including args and traceback text."""

import logging

from common.security.content import redact_text


class RedactingFormatter(logging.Formatter):
    def __init__(self, original: logging.Formatter):
        super().__init__()
        self.original = original

    def format(self, record):
        return redact_text(self.original.format(record))
