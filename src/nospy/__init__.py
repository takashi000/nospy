__version__ = "0.0.6"

from typing import Tuple
from .nospy import (
    Nostr
)
__all__: Tuple[str, ...] = (
    "Nostr",
)

def __dir__() -> Tuple[str, ...]:
    return __all__ + ("__doc__",)