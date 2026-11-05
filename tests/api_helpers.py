"""Shared values and helpers for API tests (fixtures live in conftest.py)."""

PASSWORD = "a-long-test-password"

AUTH = {
    "authorized_by": "Jane Client",
    "authorizer_title": "CISO",
    "authorizer_organization": "Example Corp",
    "authorized_on": "2026-10-01",
}
WINDOW = {
    "timezone": "America/Chicago",
    "days": [1, 2, 3, 4, 5],
    "start_time": "09:00",
    "end_time": "17:00",
}
# Every day, all day: for tests that must not depend on the wall clock.
ALWAYS = {
    "timezone": "UTC",
    "days": [1, 2, 3, 4, 5, 6, 7],
    "start_time": "00:00",
    "end_time": "00:00",
}


def add_scope(client, eng, value, mode="include", reason="per SOW section 2"):
    return client.post(
        f"/engagements/{eng['id']}/scope", json={"value": value, "mode": mode, "reason": reason}
    )


def activate(client, eng, *scope, window=ALWAYS):
    """Give the engagement authorization, scope, and a window, then make it active."""
    url = f"/engagements/{eng['id']}"
    assert client.put(f"{url}/authorization", json=AUTH).status_code == 200
    for value in scope:
        mode = "exclude" if value.startswith("!") else "include"
        assert add_scope(client, eng, value.lstrip("!"), mode=mode).status_code == 201
    assert client.post(f"{url}/windows", json=window).status_code == 201
    resp = client.patch(url, json={"status": "active"})
    assert resp.status_code == 200, resp.text
