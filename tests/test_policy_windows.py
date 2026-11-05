"""Testing windows: open/closed and next opening, including overnight windows and DST."""

from datetime import UTC, datetime, time

import pytest

from quiver.core.policy import WindowSpec, WindowState, window_state

WEEKDAYS = frozenset({1, 2, 3, 4, 5})


def win(tz="America/Chicago", days=WEEKDAYS, start=time(9), end=time(17)):
    return WindowSpec(tz, frozenset(days), start, end)


def utc(*args):
    return datetime(*args, tzinfo=UTC)


def test_no_windows_is_closed_forever():
    assert window_state([], utc(2026, 11, 4, 15)) == WindowState(False, None)


def test_naive_now_is_rejected():
    with pytest.raises(ValueError):
        window_state([win()], datetime(2026, 11, 4, 15))


@pytest.mark.parametrize(
    ("now", "is_open"),
    [
        (utc(2026, 11, 4, 14, 59), False),  # Wed 08:59 CST
        (utc(2026, 11, 4, 15, 0), True),  # 09:00, start is inclusive
        (utc(2026, 11, 4, 22, 59), True),  # 16:59
        (utc(2026, 11, 4, 23, 0), False),  # 17:00, end is exclusive
    ],
)
def test_daytime_boundaries(now, is_open):
    assert window_state([win()], now).open is is_open


def test_next_open_skips_the_weekend():
    friday_evening = utc(2026, 11, 7, 0, 0)  # Fri 18:00 CST
    state = window_state([win()], friday_evening)
    assert not state.open
    assert state.next_open == utc(2026, 11, 9, 15, 0)  # Mon 09:00 CST


def test_overnight_window_belongs_to_its_start_day():
    nights = win(days={5}, start=time(22), end=time(6))  # Friday night only
    assert window_state([nights], utc(2026, 11, 7, 10, 0)).open  # Sat 04:00 CST
    assert not window_state([nights], utc(2026, 11, 8, 10, 0)).open  # Sun 04:00 CST
    assert not window_state([nights], utc(2026, 11, 6, 10, 0)).open  # Fri 04:00 (Thu night)


def test_equal_start_and_end_is_the_whole_day():
    sunday = win(days={7}, start=time(0), end=time(0))
    assert window_state([sunday], utc(2026, 11, 8, 6, 0)).open  # Sun 00:00 CST
    assert window_state([sunday], utc(2026, 11, 9, 5, 59)).open  # Sun 23:59 CST
    assert not window_state([sunday], utc(2026, 11, 9, 6, 0)).open  # Mon 00:00


def test_multiple_windows_earliest_next_open():
    a = win(days={3}, start=time(20), end=time(21))
    b = win(tz="Europe/London", days={3}, start=time(23), end=time(23, 30))  # 17:00 CST
    state = window_state([a, b], utc(2026, 11, 4, 15))
    assert state.next_open == utc(2026, 11, 4, 23, 0)


def test_window_in_its_own_timezone():
    london = win(tz="Europe/London")
    assert window_state([london], utc(2026, 11, 4, 9, 0)).open  # 09:00 GMT
    assert not window_state([london], utc(2026, 11, 4, 17, 0)).open


def test_spring_forward_gap_start_moves_past_the_gap():
    # 2026-03-08: Chicago skips 02:00-03:00. A 02:30 start is read with the pre-gap offset,
    # i.e. 08:30 UTC = 03:30 CDT.
    gap = win(days={7}, start=time(2, 30), end=time(5))
    state = window_state([gap], utc(2026, 3, 8, 6, 0))
    assert state.next_open == utc(2026, 3, 8, 8, 30)
    assert not window_state([gap], utc(2026, 3, 8, 8, 29)).open
    assert window_state([gap], utc(2026, 3, 8, 9, 0)).open  # 04:00 CDT


def test_fall_back_ambiguous_time_uses_first_occurrence():
    # 2026-11-01: Chicago repeats 01:00-02:00. A 01:30 start is the first (CDT) 01:30.
    repeat = win(days={7}, start=time(1, 30), end=time(3))
    state = window_state([repeat], utc(2026, 11, 1, 5, 0))
    assert state.next_open == utc(2026, 11, 1, 6, 30)


def test_full_day_across_dst_is_25_hours_of_wall_clock():
    sunday = win(days={7}, start=time(0), end=time(0))
    assert window_state([sunday], utc(2026, 11, 2, 5, 30)).open  # Sun 23:30 CST
    assert not window_state([sunday], utc(2026, 11, 2, 6, 0)).open
