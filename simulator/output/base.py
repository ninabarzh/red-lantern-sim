# simulator/output/base.py
from __future__ import annotations

from collections.abc import Iterable


class Adapter:
    """Base adapter for transforming simulator events into log lines."""

    def transform(self, event: dict) -> Iterable[str]:
        """Override in subclasses."""
        return []
