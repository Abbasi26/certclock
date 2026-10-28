"""Shared fixtures. Certificates are generated in process; tests do not use the network."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from certclock.dates import utcnow
from certclock.mint import Minted, mint


@pytest.fixture
def now() -> dt.datetime:
    return dt.datetime(2026, 10, 21, 12, 0, tzinfo=dt.timezone.utc)


@pytest.fixture
def leaf(now: dt.datetime) -> Minted:
    issuer = mint(
        "Example Laboratory Issuing CA",
        is_ca=True,
        key="ec",
        path_length=0,
        sans=[],
        not_before=now - dt.timedelta(days=10),
        not_after=now + dt.timedelta(days=80),
    )
    return mint(
        "app.example.test",
        issuer=issuer,
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=40),
    )


def write_pem(directory: Path, name: str, minted: Minted) -> Path:
    path = directory / name
    path.write_bytes(minted.pem)
    return path


@pytest.fixture
def clock() -> dt.datetime:
    return utcnow()
