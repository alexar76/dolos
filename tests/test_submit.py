"""submit.py — the guards that keep by-design and advisory findings out of auto-remediation,
and the transport that hands a real one to the SKOPOS conductor.

Two separable properties: *what* may be submitted (submittable) and *how* a submission is
reported back (submit_finding). The second must never turn a network failure into a success.
"""

from __future__ import annotations

import io
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from dolos.submit import _ticket_from_finding, submit_finding, submit_report, submittable

CONDUCTOR = "http://skopos.internal:9450"


def _f(**kw):
    base = {"finding_id": "dol-abc123", "outcome": "finding", "detail": "real bug",
            "target": "X@0x1", "probe": "p", "severity": "high", "category": "authz",
            "target_kind": "evm-contract"}
    base.update(kw)
    return base


class _Reply:
    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return io.BytesIO(json.dumps(self._payload).encode())

    def __exit__(self, *exc):
        return False


@pytest.fixture(autouse=True)
def _no_ambient_conductor(monkeypatch):
    for var in ("DOLOS_CONDUCTOR_URL", "DOLOS_CONDUCTOR_PEER_TOKEN", "SKOPOS_A2A_TOKEN"):
        monkeypatch.delenv(var, raising=False)


# --------------------------------------------------------------------------- submittable


def test_a_real_exploit_is_submittable():
    ok, why = submittable(_f())
    assert ok and not why


def test_held_and_inconclusive_are_not_submittable():
    assert not submittable(_f(outcome="no_finding"))[0]
    assert not submittable(_f(outcome="inconclusive"))[0]


def test_by_design_is_advisory_only():
    ok, why = submittable(_f(detail="[BY DESIGN in the sealed bubble] open mint"))
    assert not ok and "by-design" in why


def test_advisory_non_sandbox_never_auto_remediated():
    ok, why = submittable(_f(detail="[ADVISORY — fork of a non-sandbox chain] drain"))
    assert not ok and "advisory" in why


def test_unsafe_finding_id_rejected():
    """The id reaches a conductor that keys files and tickets by it — path traversal stops here."""
    assert not submittable(_f(finding_id="../etc/passwd"))[0]
    assert not submittable(_f(finding_id=""))[0]
    assert not submittable(_f(finding_id="a" * 120))[0]


def test_a_normal_finding_id_is_accepted():
    assert submittable(_f(finding_id="dol-0123456789abcdef"))[0]


# --------------------------------------------------------------------------- ticket shape


def test_ticket_mirrors_blame_to_finding_id_and_component():
    """The conductor cross-checks blame against the ticket; a mismatch is rejected there."""
    t = _ticket_from_finding(_f())
    assert t["blame"]["finding_id"] == t["finding_id"]
    assert t["blame"]["component"] == t["component"] == t["target"]


def test_ticket_carries_the_full_signed_document():
    t = _ticket_from_finding(_f(signature={"algorithm": "ed25519"}))
    assert t["finding"]["signature"]["algorithm"] == "ed25519"


def test_ticket_truncates_an_essay_of_a_title():
    t = _ticket_from_finding(_f(title="x" * 500))
    assert len(t["blame"]["summary"]) == 200


def test_ticket_defaults_the_target_kind():
    t = _ticket_from_finding({"finding_id": "dol-1", "target": "C"})
    assert t["target_kind"] == "evm-contract"


# --------------------------------------------------------------------------- transport


def test_nothing_is_submitted_when_the_conductor_is_not_configured():
    out = submit_finding(_f())
    assert out == {"submitted": False, "reason": "DOLOS_CONDUCTOR_URL not set"}


def test_an_unsubmittable_finding_never_reaches_the_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not open a connection")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    out = submit_finding(_f(outcome="no_finding"), conductor_url=CONDUCTOR)
    assert out["submitted"] is False and out["reason"] == "not an exploit"


def test_a_working_task_counts_as_submitted(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **k: _Reply({"state": "working", "id": "t-1"}))
    out = submit_finding(_f(), conductor_url=CONDUCTOR)
    assert out["submitted"] is True and out["conductor"]["id"] == "t-1"


def test_any_other_state_is_not_submitted(monkeypatch):
    """A conductor that answered `rejected` has not accepted the work."""
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _Reply({"state": "rejected"}))
    assert submit_finding(_f(), conductor_url=CONDUCTOR)["submitted"] is False


def test_the_remediate_skill_and_ticket_are_what_gets_posted(monkeypatch):
    sent = {}

    def capture(req, timeout=None):
        sent["url"] = req.full_url
        sent["body"] = json.loads(req.data)
        sent["headers"] = {k.lower(): v for k, v in req.header_items()}
        return _Reply({"state": "working"})

    monkeypatch.setattr(urllib.request, "urlopen", capture)
    submit_finding(_f(), conductor_url=CONDUCTOR + "/")
    assert sent["url"] == f"{CONDUCTOR}/a2a/tasks"
    assert sent["body"]["skill"] == "remediate"
    assert sent["body"]["input"]["ticket"]["probe"] == "p"


def test_the_peer_token_is_sent_when_configured(monkeypatch):
    sent = {}

    def capture(req, timeout=None):
        sent.update({k.lower(): v for k, v in req.header_items()})
        return _Reply({"state": "working"})

    monkeypatch.setattr(urllib.request, "urlopen", capture)
    monkeypatch.setenv("SKOPOS_A2A_TOKEN", "s3cret")
    submit_finding(_f(), conductor_url=CONDUCTOR)
    assert sent["X-a2a-token".lower()] == "s3cret"


def test_no_token_header_when_none_is_configured(monkeypatch):
    sent = {}

    def capture(req, timeout=None):
        sent.update({k.lower(): v for k, v in req.header_items()})
        return _Reply({"state": "working"})

    monkeypatch.setattr(urllib.request, "urlopen", capture)
    submit_finding(_f(), conductor_url=CONDUCTOR)
    assert "x-a2a-token" not in sent


def test_an_http_error_is_reported_not_swallowed(monkeypatch):
    def raise_http(*a, **k):
        raise urllib.error.HTTPError(CONDUCTOR, 403, "Forbidden", {}, io.BytesIO(b"nope"))

    monkeypatch.setattr(urllib.request, "urlopen", raise_http)
    out = submit_finding(_f(), conductor_url=CONDUCTOR)
    assert out["submitted"] is False and out["reason"] == "HTTP 403" and "nope" in out["detail"]


def test_an_unreachable_conductor_is_reported_not_swallowed(monkeypatch):
    def raise_url(*a, **k):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", raise_url)
    out = submit_finding(_f(), conductor_url=CONDUCTOR)
    assert out["submitted"] is False and "URLError" in out["reason"]


def test_a_garbled_reply_is_reported_not_swallowed(monkeypatch):
    class Garbage:
        def __enter__(self):
            return io.BytesIO(b"<html>gateway timeout</html>")

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: Garbage())
    out = submit_finding(_f(), conductor_url=CONDUCTOR)
    assert out["submitted"] is False and "Error" in out["reason"]


# --------------------------------------------------------------------------- whole reports


def test_submit_report_only_forwards_the_submittable_findings(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _Reply({"state": "working"}))
    report = {"findings": [
        _f(finding_id="dol-1"),
        _f(finding_id="dol-2", outcome="no_finding"),
        _f(finding_id="dol-3", detail="[BY DESIGN] faucet"),
        _f(finding_id="dol-4", detail="[ADVISORY] mainnet"),
    ]}
    out = submit_report(report, conductor_url=CONDUCTOR)
    assert [r["finding_id"] for r in out] == ["dol-1"]
    assert out[0]["submitted"] is True


def test_submit_report_on_a_clean_scan_submits_nothing(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not open a connection")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    assert submit_report({"findings": []}, conductor_url=CONDUCTOR) == []
