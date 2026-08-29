"""Context-local options used while parsing a PDF."""

import contextvars
from contextlib import contextmanager
from dataclasses import dataclass


@dataclass(frozen=True)
class ParserContext:
    force_mode: bool = False
    manual_analysis: bool = False


_parser_context = contextvars.ContextVar(
    "parser_context", default=ParserContext()
)


def get_parser_context():
    return _parser_context.get()


@contextmanager
def set_parser_context(force_mode=False, manual_analysis=False):
    token = _parser_context.set(ParserContext(force_mode, manual_analysis))
    try:
        yield
    finally:
        _parser_context.reset(token)
