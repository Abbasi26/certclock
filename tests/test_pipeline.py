from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from certclock.config import Config
from certclock.inventory import Inventory
from certclock.mint import Minted
from certclock.models import CollectionResult, Gap, Observation
from certclock.pipeline import scan


def test_scan_invalid_hosts_preserves_inventory(
    tmp_path: Path, now: dt.datetime, leaf: Minted
):
    database = tmp_path / "certclock.db"
    with Inventory(database) as inventory:
        inventory.ingest(
            CollectionResult(
                observations=[
                    Observation(source="file", detail="existing.pem", der=leaf.der)
                ],
                warnings=["existing warning"],
                gaps=[Gap("file", "unreadable.pem", "existing gap")],
                replaced_sources=("file",),
            ),
            now,
        )
    previous = database.read_bytes()
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("example.test:0\n", encoding="utf-8")
    output = tmp_path / "out"
    config = Config(
        database=str(database),
        output_dir=str(output),
        hosts_file=str(hosts),
    )

    with pytest.raises(ValueError, match=r"hosts line 1: port 0 is out of range"):
        scan(config, now=now)

    assert database.read_bytes() == previous
    assert not output.exists()


# Not checked: tests were not run in this read-only review.
# Risk: failures after collector construction can still leave a replaced snapshot.
