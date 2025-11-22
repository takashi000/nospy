__version__ = "0.0.8"

from typing import Tuple
from .nospy import (
    Nostr
)
__all__: Tuple[str, ...] = (
    "Nostr",
)

def __dir__() -> Tuple[str, ...]:
    return __all__ + ("__doc__",)