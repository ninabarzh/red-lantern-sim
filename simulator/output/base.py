# simulator/output/base.py
from __future__ import annotations
from typing import Iterable


class Adapter:
    """Base adapter for transforming simulator events into log lines."""

    def transform(self, event: dict) -> Iterable[str]:
        """Override in subclasses."""
        return []
