"""The collector interface.

A collector is any object with ``collect() -> CollectionResult``. Built-in
collectors are registered as ``certclock.collectors`` entry points. A caller
can also pass its own object to ``Inventory.ingest``; nothing has to be
registered for that to work.
"""

from __future__ import annotations

from typing import Protocol

from certclock.models import CollectionResult


class Collector(Protocol):
    name: str
    replaced_sources: tuple[str, ...]

    def collect(self) -> CollectionResult:
        """Read one source. Must not modify the source and must not return keys."""
