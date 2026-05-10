from .semantics import Semantics, Successor, semantic

# Load all the semantics
from . import x86  # noqa: F401

__all__ = ["Semantics", "Successor", "semantic"]
