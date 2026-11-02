"""Submission status and outcome, bounty currencies, paid tracking and the earnings page."""

import re
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.web import format_money, format_money_input


def token(page: str) -> str:
    match = re.search(r'name="csrf" value="([^"]+)"', page)
    assert match
    return match.group(1)


def settings_for(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        admin_password="bounty-status-password",
        session_secret="test-session-secret-that-is-long-enough",
        max_upload_bytes=1024 * 1024,
        secure_cookies=False,
    )


def signed_in(settings: Settings):
    client = TestClient(create_app(settings), follow_redirects=False)
    client.__enter__()
    login = client.get("/login")
    client.post("/login", data={"username": "admin", "password": settings.admin_password, "csrf": token(login.text)})
    return client, token(client.get("/").text)


@pytest.fixture
def ws(tmp_path: Path):
    client, csrf = signed_in(settings_for(tmp_path))
    yield client, csrf, tmp_path
    client.__exit__(None, None, None)


def program(client: TestClient, csrf: str, name: str) -> str:
    response = client.post("/programs/new", data={"csrf": csrf, "name": name})
    assert response.status_code == 303
    return response.headers["location"].rsplit("/", 1)[-1]


def entry(client: TestClient, csrf: str, title: str) -> str:
    response = client.post(
        "/knowledge/new",
        data={"csrf": csrf, "title": title, "bug_type": "XSS", "default_severity": "high", "markdown": "# R"},
    )
    assert response.status_code == 303
    return response.headers["location"].rsplit("/", 1)[-1]


def finding(client: TestClient, csrf: str, program_id: str, knowledge_id: str, **extra) -> str:
    data = {
        "csrf": csrf,
        "program_id": program_id,
        "knowledge_id": knowledge_id,
        "status": "submitted",
        "severity": "high",
        "submitted_at": "2026-03-01",
    }
    data.update(extra)
    response = client.post("/findings/new", data=data)
    assert response.status_code == 303, response.text
    return re.search(r"finding_id=([0-9a-f-]{36})", response.headers["location"]).group(1)


def test_money_never_uses_scientific_notation():
    assert format_money(15_000_000, "VND") == "15,000,000"
    assert format_money(1250.5, "USD") == "1,250.50"
    assert format_money(300.0, "EUR") == "300"
    assert format_money(None, "USD") == ""
    assert format_money_input(15_000_000.0) == "15000000"
    assert format_money_input(12.5) == "12.5"


def test_legacy_statuses_migrate_to_status_outcome_and_paid(tmp_path: Path):
    settings = settings_for(tmp_path)
    client, csrf = signed_in(settings)
    program_id = program(client, csrf, "Legacy Co")
    legacy = ["draft", "triaged", "accepted", "resolved", "paid", "duplicate", "out_of_scope", "archived", "weird"]
    ids = {status: finding(client, csrf, program_id, entry(client, csrf, status)) for status in legacy}
    client.__exit__(None, None, None)

    with sqlite3.connect(tmp_path / "test.db") as connection:
        for status, finding_id in ids.items():
            connection.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
        # An outcome recorded before the migration is kept.
        connection.execute("UPDATE findings SET outcome = 'informative' WHERE id = ?", (ids["archived"],))

    for _restart in range(2):  # the migration is idempotent
        client, _csrf = signed_in(settings)
        client.__exit__(None, None, None)

    expected = {
        "draft": ("submitted", "", 0),
        "triaged": ("processing", "", 0),
        "accepted": ("processing", "accepted", 0),
        "resolved": ("done", "accepted", 0),
        "paid": ("done", "accepted", 1),
        "duplicate": ("done", "duplicate", 0),
        "out_of_scope": ("done", "out_of_scope", 0),
        "archived": ("done", "informative", 0),
        "weird": ("submitted", "", 0),
    }
    with sqlite3.connect(tmp_path / "test.db") as connection:
        for status, finding_id in ids.items():
            row = connection.execute(
                "SELECT status, outcome, is_paid FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
            assert row == expected[status], status


def test_status_and_outcome_are_validated(ws):
    client, csrf, _ = ws
    program_id = program(client, csrf, "Strict Co")
    knowledge_id = entry(client, csrf, "Validated")
    for overrides in ({"status": "triaged"}, {"outcome": "paid"}):
        data = {
            "csrf": csrf,
            "program_id": program_id,
            "knowledge_id": knowledge_id,
            "status": "submitted",
            "severity": "high",
            **overrides,
        }
        assert client.post("/findings/new", data=data).status_code == 422


def test_only_vnd_eur_usd_are_offered_but_legacy_rows_keep_theirs(ws):
    client, csrf, data_dir = ws
    program_id = program(client, csrf, "Currency Co")
    knowledge_id = entry(client, csrf, "Pounds")
    assert (
        client.post(
            "/findings/new",
            data={
                "csrf": csrf,
                "program_id": program_id,
                "knowledge_id": knowledge_id,
                "status": "submitted",
                "severity": "high",
                "payout": "10",
                "currency": "GBP",
            },
        ).status_code
        == 422
    )

    finding_id = finding(client, csrf, program_id, knowledge_id, payout="10", currency="USD")
    with sqlite3.connect(data_dir / "test.db") as connection:
        connection.execute("UPDATE findings SET currency = 'GBP' WHERE id = ?", (finding_id,))

    form = client.get(f"/findings/{finding_id}/edit").text
    options = re.findall(r'<option value="([A-Z]{3})" data-symbol', form)
    assert options == ["GBP", "VND", "EUR", "USD"]
    assert '<option value="VND" data-symbol="₫"' in form and '<option value="EUR" data-symbol="€"' in form

    base = {
        "csrf": csrf,
        "program_id": program_id,
        "knowledge_id": knowledge_id,
        "status": "done",
        "severity": "high",
        "payout": "12",
    }
    assert client.post(f"/findings/{finding_id}/edit", data={**base, "currency": "GBP"}).status_code == 303
    assert client.post(f"/findings/{finding_id}/edit", data={**base, "currency": "BTC"}).status_code == 422


def test_paid_flag_and_date_round_trip(ws):
    client, csrf, _ = ws
    program_id = program(client, csrf, "Paid Co")
    knowledge_id = entry(client, csrf, "Paid later")
    finding_id = finding(
        client, csrf, program_id, knowledge_id, payout="15000000", currency="VND", rewarded_at="2026-04-01", is_paid="0"
    )
    page = client.get(f"/knowledge/{knowledge_id}").text
    assert '<i class="cur-icon" aria-hidden="true">₫</i><span class="num">15,000,000</span>' in page
    assert "paid-badge is-unpaid" in page
    assert "e+07" not in page

    form = client.get(f"/findings/{finding_id}/edit").text
    assert 'name="payout" value="15000000"' in form
    assert 'name="is_paid" value="1" checked' not in form

    # A paid date before submission is refused; a valid one marks the reward as received.
    base = {
        "csrf": csrf,
        "program_id": program_id,
        "knowledge_id": knowledge_id,
        "status": "done",
        "outcome": "accepted",
        "severity": "high",
        "submitted_at": "2026-03-01",
        "payout": "15000000",
        "currency": "VND",
    }
    assert client.post(f"/findings/{finding_id}/edit", data={**base, "paid_at": "2026-02-01"}).status_code == 422
    assert client.post(f"/findings/{finding_id}/edit", data={**base, "paid_at": "2026-05-02"}).status_code == 303
    form = client.get(f"/findings/{finding_id}/edit").text
    assert 'name="is_paid" value="1" checked' in form
    assert 'name="paid_at" value="2026-05-02"' in form


def test_mark_paid_requires_csrf_and_only_redirects_locally(ws):
    client, csrf, _ = ws
    program_id = program(client, csrf, "Owed Co")
    finding_id = finding(client, csrf, program_id, entry(client, csrf, "Owed"), payout="100")

    assert client.post(f"/findings/{finding_id}/paid", data={"csrf": "wrong"}).status_code in (403, 422)
    response = client.post(f"/findings/{finding_id}/paid", data={"csrf": csrf, "return_to": "//evil.example/"})
    assert response.status_code == 303
    assert not response.headers["location"].startswith("//")
    assert "is-unpaid" not in client.get("/earnings?year=all").text.split('id="unpaid"')[1]

    response = client.post(
        f"/findings/{finding_id}/paid", data={"csrf": csrf, "paid": "0", "return_to": "/earnings#unpaid"}
    )
    assert response.headers["location"] == "/earnings#unpaid"
    assert "Mark paid" in client.get("/earnings?year=all").text


def test_search_understands_status_outcome_and_payment(ws):
    client, csrf, _ = ws
    program_id = program(client, csrf, "Search Co")
    finding(client, csrf, program_id, entry(client, csrf, "Waiting one"))
    finding(client, csrf, program_id, entry(client, csrf, "Being handled"), status="processing")
    finding(client, csrf, program_id, entry(client, csrf, "Closed dupe"), status="done", outcome="duplicate")
    finding(client, csrf, program_id, entry(client, csrf, "Money owed"), status="done", outcome="accepted", payout="50")
    finding(
        client,
        csrf,
        program_id,
        entry(client, csrf, "Money in"),
        status="done",
        outcome="accepted",
        payout="70",
        is_paid="1",
    )

    def titles(query: str) -> set[str]:
        page = client.get("/search", params={"q": f"{query} kind:knowledge"}).text
        names = ("Waiting one", "Being handled", "Closed dupe", "Money owed", "Money in")
        return {name for name in names if name in page}

    assert titles("is:open") == {"Waiting one", "Being handled"}
    assert titles("status:processing") == {"Being handled"}
    assert titles("outcome:duplicate") == {"Closed dupe"}
    assert titles("is:accepted") == {"Money owed", "Money in"}
    assert titles("is:paid") == {"Money in"}
    assert titles("is:unpaid") == {"Money owed"}


def test_earnings_page_splits_paid_and_unpaid_per_currency(ws):
    client, csrf, _ = ws
    acme = program(client, csrf, "Acme")
    globex = program(client, csrf, "Globex")
    reward = {"status": "done", "outcome": "accepted"}
    finding(
        client,
        csrf,
        acme,
        entry(client, csrf, "A1"),
        payout="10000000",
        currency="VND",
        rewarded_at="2026-03-10",
        is_paid="1",
        **reward,
    )
    finding(
        client,
        csrf,
        globex,
        entry(client, csrf, "A2"),
        payout="5000000",
        currency="VND",
        rewarded_at="2026-05-10",
        **reward,
    )
    finding(
        client,
        csrf,
        acme,
        entry(client, csrf, "A3"),
        payout="500",
        bonus="50",
        currency="USD",
        rewarded_at="2026-05-12",
        paid_at="2026-06-01",
        **reward,
    )
    finding(
        client,
        csrf,
        acme,
        entry(client, csrf, "Old one"),
        payout="200",
        currency="EUR",
        submitted_at="2025-01-01",
        rewarded_at="2025-02-01",
        is_paid="1",
        **reward,
    )

    assert 'href="/earnings"' in client.get("/").text

    page = client.get("/earnings").text  # latest year by default
    assert re.findall(r'data-earnings-currency="([A-Z]+)"', page) == ["VND", "USD"]
    vnd = page.split('data-earnings-currency="VND"')[1].split('data-earnings-currency="USD"')[0]
    assert '<span class="num">15,000,000</span>' in vnd
    assert '<b class="num">10,000,000</b>' in vnd and '<b class="num">5,000,000</b>' in vnd
    assert "EUR" not in page.split('id="unpaid"')[0].split("earnings-summary")[1]
    # VND is selected first: two months carry its rewards, Globex owes the rest.
    assert re.search(r'title="2026-03: 10,000,000 VND', page)
    assert re.search(r'title="2026-05: 5,000,000 VND', page)
    assert "Globex" in page.split('id="unpaid"')[1]

    usd = client.get("/earnings?year=2026&currency=USD").text
    assert re.search(r'title="2026-06: 550 USD', usd)  # counted when the money arrived

    all_time = client.get("/earnings?year=all").text
    assert re.findall(r'data-earnings-currency="([A-Z]+)"', all_time) == ["VND", "EUR", "USD"]
    assert 'title="2025:' in all_time and 'title="2026:' in all_time

    old = client.get("/earnings?year=2025").text
    assert re.findall(r'data-earnings-currency="([A-Z]+)"', old) == ["EUR"]


def test_earnings_page_has_an_empty_state(ws):
    client, _csrf, _ = ws
    page = client.get("/earnings")
    assert page.status_code == 200
    assert "No bounties recorded yet" in page.text
    assert "Mark paid" not in page.text
