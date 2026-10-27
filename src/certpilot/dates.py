"""UTC datetime parsing and formatting."""

from __future__ import annotations

import datetime as dt

_FORMATS = (
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%m/%d/%Y %I:%M:%S %p",
    "%m/%d/%Y %I:%M %p",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M",
    "%m/%d/%Y",
    "%d.%m.%Y %H:%M:%S",
    "%d.%m.%Y %H:%M",
    "%d.%m.%Y",
    "%b %d %H:%M:%S %Y GMT",
    "%b %d %H:%M:%S %Y",
)


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def ensure_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)


def format_datetime(value: dt.datetime) -> str:
    return ensure_utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def format_date(value: dt.datetime) -> str:
    return ensure_utc(value).strftime("%d %b %Y")


def parse_datetime(value: str) -> dt.datetime:
    """Parse ISO-8601, certutil US dates, and OpenSSL GMT dates as UTC."""

    text = " ".join(value.strip().strip('"').split())
    if not text:
        raise ValueError("empty datetime")
    if text.endswith("Z"):
        try:
            return ensure_utc(dt.datetime.fromisoformat(text[:-1] + "+00:00"))
        except ValueError:
            pass
    try:
        return ensure_utc(dt.datetime.fromisoformat(text))
    except ValueError:
        pass
    for fmt in _FORMATS:
        try:
            return dt.datetime.strptime(text, fmt).replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
    raise ValueError(f"unrecognized datetime: {value!r}")


def days_remaining(not_after: dt.datetime, now: dt.datetime) -> int:
    """Whole days until expiry. Negative when the certificate is already expired."""

    seconds = (ensure_utc(not_after) - ensure_utc(now)).total_seconds()
    return int(seconds // 86400)


def bucket_for(days: int) -> str:
    """Timeline bucket. The 7/30/90 windows are fixed product buckets."""

    if days < 0:
        return "expired"
    if days <= 7:
        return "within_7"
    if days <= 30:
        return "within_30"
    if days <= 90:
        return "within_90"
    return "later"


def relative_expiry(not_after: dt.datetime, now: dt.datetime) -> str:
    days = days_remaining(not_after, now)
    date = format_date(not_after)
    if days < 0:
        n = abs(days)
        unit = "day" if n == 1 else "days"
        return f"expired on {date} ({n} {unit} ago)"
    if days == 0:
        return f"expires on {date} (in less than 1 day)"
    unit = "day" if days == 1 else "days"
    return f"expires on {date} (in {days} {unit})"
