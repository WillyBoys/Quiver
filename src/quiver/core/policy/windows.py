"""Testing windows: is testing allowed right now, and if not, when next? (Blueprint §5.1)

A window is a set of ISO weekdays plus a start and end time in an IANA time zone.
- end < start crosses midnight; the window belongs to the day it starts on.
- end == start is the whole day (24 hours of wall-clock time, so 23 or 25 across DST).
Wall-clock times that do not exist (spring forward) resolve to the moment after the gap;
times that occur twice (fall back) resolve to the first occurrence.
"""

import zoneinfo
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta


@dataclass(frozen=True)
class WindowSpec:
    timezone: str
    days: frozenset[int]  # ISO weekdays, 1 = Monday .. 7 = Sunday
    start_time: time
    end_time: time

    @classmethod
    def from_row(cls, row) -> "WindowSpec":
        return cls(row.timezone, frozenset(row.days), row.start_time, row.end_time)


@dataclass(frozen=True)
class WindowState:
    open: bool
    next_open: datetime | None  # UTC; None when no window will ever open


def _at(day: date, t: time, tz: zoneinfo.ZoneInfo) -> datetime:
    # fold=0: a skipped time maps past the gap, a repeated time to its first occurrence.
    return datetime.combine(day, t, tzinfo=tz).astimezone(UTC)


def _occurrences(window: WindowSpec, around: datetime):
    """(start, end) in UTC for each occurrence starting from the day before `around`
    through a week after it."""
    tz = zoneinfo.ZoneInfo(window.timezone)
    today = around.astimezone(tz).date()
    for offset in range(-1, 9):
        day = today + timedelta(days=offset)
        if day.isoweekday() not in window.days:
            continue
        start = _at(day, window.start_time, tz)
        if window.end_time > window.start_time:
            end = _at(day, window.end_time, tz)
        else:  # crosses midnight, or the whole day when equal
            end = _at(day + timedelta(days=1), window.end_time, tz)
        yield start, end


def window_state(windows: Iterable[WindowSpec], now: datetime) -> WindowState:
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    next_open = None
    for window in windows:
        for start, end in _occurrences(window, now):
            if start <= now < end:
                return WindowState(True, None)
            if start > now and (next_open is None or start < next_open):
                next_open = start
    return WindowState(False, next_open)
