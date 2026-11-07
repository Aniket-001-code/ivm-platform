"""Timezone helpers: SQLite returns naive datetimes, PostgreSQL returns aware ones."""

from datetime import datetime, timezone
from typing import overload


@overload
def as_utc(value: datetime) -> datetime: ...
@overload
def as_utc(value: None) -> None: ...
def as_utc(value: datetime | None) -> datetime | None:
    """Treat naive datetimes as UTC so they can be compared with aware ones."""
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
