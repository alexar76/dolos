"""The periodic loop — and the one property it exists for: a cycle must never stop the next one.

The failure this guards against is not "the scan crashed". It is "the watcher died three weeks ago
and nobody noticed", because a dead watcher and a watcher reporting no problems look identical from
the outside — the artifact just keeps serving its last green verdict.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from dolos import watch as watch_mod
from dolos.harness import ScanReport, _result_to_finding
from dolos.watch import DEFAULT_INTERVAL_S, MIN_INTERVAL_S, memo_path, resolve_interval, run_watch


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("DOLOS_WATCH_INTERVAL_S", "DOLOS_MEMO_PATH", "DOLOS_DATA_DIR"):
        monkeypatch.delenv(var, raising=False)


def _ok_report(**kw):
    r = ScanReport("http://x", 31337, 12, True, ran=3, held=3, **kw)
    return r


def _run(monkeypatch, tmp_path, scan, cycles=1, **kw):
    """Drive the loop with a scripted run_scan and no real clock."""
    lines: list[dict] = []
    monkeypatch.setattr("dolos.harness.run_scan", scan)
    return run_watch(fork_url="http://127.0.0.1:8545", interval_s=MIN_INTERVAL_S, cycles=cycles,
                     memos_path=str(tmp_path / "m.jsonl"),
                     emit=lambda s: lines.append(json.loads(s)), sleep=lambda _s: None,
                     **kw), lines


# --------------------------------------------------------------------------- interval


def test_the_default_interval_is_an_hour():
    assert resolve_interval() == (DEFAULT_INTERVAL_S, f"default {DEFAULT_INTERVAL_S}s")


def test_the_interval_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("DOLOS_WATCH_INTERVAL_S", "900")
    assert resolve_interval()[0] == 900


def test_an_explicit_interval_beats_the_environment(monkeypatch):
    monkeypatch.setenv("DOLOS_WATCH_INTERVAL_S", "900")
    assert resolve_interval(120)[0] == 120


def test_a_junk_interval_degrades_instead_of_raising():
    """A scheduler that refuses to start because of a typo'd env var stops watching."""
    seconds, why = resolve_interval("every-hour-ish")
    assert seconds == DEFAULT_INTERVAL_S and "unparseable" in why


def test_a_reckless_interval_is_clamped():
    """A one-second loop would fork a chain in a hot loop and look like a resource attack."""
    seconds, why = resolve_interval(1)
    assert seconds == MIN_INTERVAL_S and "floor" in why


def test_the_memo_path_follows_the_data_dir(monkeypatch):
    monkeypatch.setenv("DOLOS_DATA_DIR", "/srv/dolos")
    assert memo_path() == "/srv/dolos/attack_memos.jsonl"
    monkeypatch.setenv("DOLOS_MEMO_PATH", "/explicit.jsonl")
    assert memo_path() == "/explicit.jsonl"
    assert memo_path("/argument.jsonl") == "/argument.jsonl"


# --------------------------------------------------------------------------- a healthy cycle


def test_a_good_cycle_reports_what_it_found(monkeypatch, tmp_path):
    summary, lines = _run(monkeypatch, tmp_path, lambda *a, **k: _ok_report())
    assert summary["scans_ran"] == 1 and summary["scans_failed"] == 0
    assert lines[0]["ok"] is True and lines[0]["chain_id"] == 31337


def test_real_exploits_are_counted_but_by_design_ones_are_not(monkeypatch, tmp_path):
    """The bubble's intended faucet fires every run; counting it would make every cycle look like
    a breach."""
    from conftest import exploit_result

    def scan(*a, **k):
        r = _ok_report()
        r.findings.append(_result_to_finding(exploit_result(), {}, None, sandbox=True))
        r.findings.append(_result_to_finding(exploit_result(by_design=True), {}, None, sandbox=True))
        return r

    summary, lines = _run(monkeypatch, tmp_path, scan)
    assert summary["exploits_found"] == 1 and lines[0]["real_exploits"] == 1


def test_the_loop_runs_exactly_the_cycles_asked_for(monkeypatch, tmp_path):
    calls = []
    summary, lines = _run(monkeypatch, tmp_path,
                          lambda *a, **k: calls.append(1) or _ok_report(), cycles=3)
    assert len(calls) == 3 and summary["cycles"] == 3 and len(lines) == 3


def test_each_cycle_feeds_the_memory(monkeypatch, tmp_path):
    """The point of the loop: what one cycle learns, the next cycle uses."""
    seen = {}

    def scan(*a, **k):
        store = k.get("memos")
        seen["got_store"] = store is not None
        if store is not None:
            from dolos.memos import AttackMemo

            store.record(AttackMemo(probe="escrow_channel_hijack", target_contract="E",
                                    outcome="no_finding", by_design=False))
        return _ok_report()

    summary, _ = _run(monkeypatch, tmp_path, scan, cycles=2)
    assert seen["got_store"] is True
    assert summary["memos"]["memos"] == 2 and summary["memos"]["probes_known"] == 1


# --------------------------------------------------------------------------- a cycle that fails


def test_a_fork_that_never_happened_is_not_counted_as_a_scan(monkeypatch, tmp_path):
    """chain_id None means the fork never happened. That is the absence of a scan, and it must not
    be displayed as a clean one."""
    dead = ScanReport("http://x", None, None, False, note="could not fork: anvil not found")
    summary, lines = _run(monkeypatch, tmp_path, lambda *a, **k: dead)
    assert summary["scans_ran"] == 0 and summary["scans_failed"] == 1
    assert lines[0]["ok"] is False and "anvil not found" in lines[0]["reason"]


def test_an_exception_costs_one_cycle_not_the_watcher(monkeypatch, tmp_path):
    """THE property. A watcher that exits on an unexpected error is indistinguishable from one
    reporting all-clear."""
    calls = {"n": 0}

    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("web3 blew up mid-catalog")
        return _ok_report()

    summary, lines = _run(monkeypatch, tmp_path, flaky, cycles=4)
    assert calls["n"] == 4                     # the loop kept going
    assert summary["scans_ran"] == 3 and summary["scans_failed"] == 1
    assert lines[1]["ok"] is False and "RuntimeError" in lines[1]["reason"]


def test_every_cycle_emits_exactly_one_line(monkeypatch, tmp_path):
    """Under systemd the journal IS the scan history, so a silent cycle is a lost record."""
    summary, lines = _run(monkeypatch, tmp_path, lambda *a, **k: _ok_report(), cycles=5)
    assert len(lines) == 5 and [ln["cycle"] for ln in lines] == [1, 2, 3, 4, 5]


# --------------------------------------------------------------------------- stopping


def test_a_signal_ends_the_loop_cleanly(monkeypatch, tmp_path):
    """systemd sends SIGTERM on stop; a watcher killed mid-attack would orphan an anvil child."""
    real_stopper = watch_mod._Stopper

    class StopAfterFirst(real_stopper):
        def __init__(self):
            super().__init__()
            self._seen = 0

        @property
        def stop(self):
            self._seen += 1
            return self._seen > 2      # let cycle 1 start, then ask to stop

        @stop.setter
        def stop(self, _v):
            pass

    monkeypatch.setattr(watch_mod, "_Stopper", StopAfterFirst)
    summary, lines = _run(monkeypatch, tmp_path, lambda *a, **k: _ok_report(), cycles=0)
    assert summary["stopped_by_signal"] is True
    assert summary["cycles"] <= 2               # it did not run for ever


def test_the_cli_fails_when_not_one_scan_ever_ran(monkeypatch, tmp_path):
    """A permanently unreachable chain must not exit 0 and read as a healthy watcher."""
    from dolos.__main__ import main

    dead = ScanReport("http://x", None, None, False, note="could not fork")
    monkeypatch.setattr("dolos.harness.run_scan", lambda *a, **k: dead)
    monkeypatch.setattr(watch_mod.time, "sleep", lambda _s: None)
    assert main(["watch", "--cycles", "1", "--memos", str(tmp_path / "m.jsonl")]) == 1


def test_the_cli_streams_one_json_line_per_cycle_on_stdout(monkeypatch, tmp_path, capsys):
    """stdout is the cycle stream so `dolos watch | jq` works; the summary goes to stderr, because
    two different JSON shapes on one stream cannot be parsed."""
    from dolos.__main__ import main

    monkeypatch.setattr("dolos.harness.run_scan", lambda *a, **k: _ok_report())
    monkeypatch.setattr(watch_mod.time, "sleep", lambda _s: None)
    assert main(["watch", "--cycles", "2", "--memos", str(tmp_path / "m.jsonl")]) == 0
    out = capsys.readouterr()
    cycles = [json.loads(ln) for ln in out.out.strip().splitlines()]
    assert [c["cycle"] for c in cycles] == [1, 2]
    assert json.loads(out.err)["scans_ran"] == 2


def test_scan_only_builds_a_memo_store_when_asked(monkeypatch, tmp_path):
    """No --memos, no memory: byte-identical to the behaviour before any of this existed."""
    from dolos.__main__ import _memo_store

    assert _memo_store(None) is None
    assert _memo_store("") is None
    assert _memo_store(str(tmp_path / "m.jsonl")) is not None
