"""The orchestrator: snapshot-per-attack, honest counting, and the sandbox consequence gate.

The load-bearing rule here is the one the landing calls the safety boundary: a finding from a
fork of a chain we cannot throw away is tagged ADVISORY, and nothing downstream may auto-fix it.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from conftest import FakeFork
from conftest import exploit_result as _exploit
from conftest import held_result as _held

from dolos import harness
from dolos.harness import ScanReport, _result_to_finding, _write_artifact, load_address_book

BOOK = {"evm_usdt": "0x4268ed" + "0" * 34, "evm_lottery": "0x7635aa" + "0" * 34}


# --------------------------------------------------------------------------- address book


def test_address_book_reads_an_explicit_path(tmp_path):
    p = tmp_path / "universe_config.json"
    p.write_text(json.dumps({"evm_usdt": "0xabc", "block_time": 2}), encoding="utf-8")
    assert load_address_book(str(p)) == {"evm_usdt": "0xabc"}   # non-string values dropped


def test_address_book_is_empty_rather_than_wrong_when_the_config_is_missing(tmp_path):
    assert load_address_book(str(tmp_path / "nope.json")) in ({}, load_address_book())


def test_address_book_survives_a_corrupt_config(tmp_path):
    p = tmp_path / "universe_config.json"
    p.write_text("{not json", encoding="utf-8")
    assert isinstance(load_address_book(str(p)), dict)


# --------------------------------------------------------------------------- result -> finding


def test_finding_target_carries_the_contract_address(tmp_path):
    f = _result_to_finding(_exploit(), BOOK, None, sandbox=True)
    assert f.target.startswith("FakeUSDT@0x4268ed")
    assert f.target_kind == "evm-contract"


def test_finding_target_falls_back_to_the_bare_name_without_a_book():
    assert _result_to_finding(_exploit(), {}, None, sandbox=True).target == "FakeUSDT"


def test_an_exploit_on_a_non_sandbox_fork_is_tagged_advisory():
    """A real, immutable mainnet contract is never changed automatically — the identical finding
    there is reported as advisory and stops at the report. The tag is how downstream knows."""
    f = _result_to_finding(_exploit(), BOOK, None, sandbox=False)
    assert f.detail.startswith("[ADVISORY")


def test_a_sandbox_exploit_is_not_tagged_advisory():
    assert not _result_to_finding(_exploit(), BOOK, None, sandbox=True).detail.startswith("[ADVISORY")


def test_a_by_design_exploit_is_tagged_even_on_the_sandbox():
    f = _result_to_finding(_exploit(by_design=True), BOOK, None, sandbox=True)
    assert "[BY DESIGN" in f.detail


def test_a_held_result_is_never_tagged():
    f = _result_to_finding(_held(), BOOK, None, sandbox=False)
    assert not f.detail.startswith("[ADVISORY") and "[BY DESIGN" not in f.detail
    assert f.outcome == "no_finding"


def test_evidence_digests_are_derived_from_the_reproducer_not_a_payload():
    """DOLOS has no HTTP body to digest; the evidence is the transaction SEQUENCE. Digesting the
    reproducer keeps the evidence real, stable across reruns, and payload-free."""
    a = _result_to_finding(_exploit(), BOOK, None, sandbox=True).evidence
    b = _result_to_finding(_exploit(), BOOK, None, sandbox=True).evidence
    assert a.request_digest == b.request_digest and a.request_digest.startswith("sha256-")
    assert len(a.request_digest) == len("sha256-") + 64


def test_a_different_reproducer_changes_the_evidence_digest():
    a = _result_to_finding(_exploit(), BOOK, None, sandbox=True).evidence
    b = _result_to_finding(_exploit(reproducer="something else"), BOOK, None, sandbox=True).evidence
    assert a.request_digest != b.request_digest


def test_reference_artifacts_drop_empty_entries():
    r = _exploit(reference_artifacts=("contracts/evm/src/FakeUSDT.sol", ""))
    assert _result_to_finding(r, BOOK, None, sandbox=True).evidence.reference_artifacts == (
        "contracts/evm/src/FakeUSDT.sol",)


def test_an_unsigned_finding_still_gets_its_dedup_key():
    """Unsigned findings are readable but not pipeline-payable — they must still dedup."""
    f = _result_to_finding(_exploit(), BOOK, None, sandbox=True)
    assert f.dedup_key.startswith("dedup-") and not f.signature


def test_a_signer_stamps_the_pubkey_into_the_finding(tmp_path):
    from dolos.findings import FindingSigner

    signer = FindingSigner(str(tmp_path / "scanner_key"))
    f = _result_to_finding(_exploit(), BOOK, signer, sandbox=True)
    assert f.scanner_pubkey == signer.pubkey and f.signature["algorithm"] == "ed25519"


# --------------------------------------------------------------------------- sandbox gate


def test_the_sandbox_set_defaults_to_the_uni_anvil():
    assert harness.SANDBOX_CHAIN_IDS == {31337}


def test_the_sandbox_set_is_operator_configurable(monkeypatch):
    import importlib

    monkeypatch.setenv("DOLOS_SANDBOX_CHAIN_IDS", "31337, 1337 ,")
    reloaded = importlib.reload(harness)
    try:
        assert reloaded.SANDBOX_CHAIN_IDS == {31337, 1337}
    finally:
        monkeypatch.delenv("DOLOS_SANDBOX_CHAIN_IDS")
        importlib.reload(harness)


# --------------------------------------------------------------------------- report


def test_as_dict_is_json_serialisable_including_findings():
    report = ScanReport("http://x", 31337, 42, True, ran=1, held=1)
    report.findings.append(_result_to_finding(_held(), BOOK, None, sandbox=True))
    doc = json.loads(json.dumps(report.as_dict()))
    assert doc["chain_id"] == 31337 and doc["findings"][0]["probe"] == "lottery_operator_bypass"


def test_write_artifact_persists_the_scan_for_the_monitor(tmp_path, monkeypatch):
    path = tmp_path / "nested" / "dolos_last_scan.json"
    monkeypatch.setenv("DOLOS_LAST_SCAN_PATH", str(path))
    _write_artifact(ScanReport("http://x", 31337, 42, True, ran=3, held=3))
    doc = json.loads(path.read_text())
    assert doc["ran"] == 3 and doc["scanned_at"].endswith("Z")


def test_write_artifact_never_fails_the_scan(tmp_path, monkeypatch):
    """Best-effort by design: a scan that could not write its report is still a valid scan."""
    monkeypatch.setenv("DOLOS_LAST_SCAN_PATH", str(tmp_path / "file" / "x.json"))
    (tmp_path / "file").write_text("I am a file, not a directory", encoding="utf-8")
    _write_artifact(ScanReport("http://x", 31337, 42, True))   # must not raise


# --------------------------------------------------------------------------- run_scan


class _FakeForkChain:
    """Stands in for ForkChain: `ForkChain(url).start()` in run_scan."""

    instance: FakeFork | None = None

    def __init__(self, url, **kw):
        self.url = url

    def start(self):
        fork = FakeFork()
        fork.fork_url = self.url
        _FakeForkChain.instance = fork
        return fork


@pytest.fixture()
def scan_env(tmp_path, monkeypatch):
    monkeypatch.setenv("DOLOS_LAST_SCAN_PATH", str(tmp_path / "last.json"))
    monkeypatch.setattr("dolos.forkchain.ForkChain", _FakeForkChain)
    monkeypatch.setattr(harness, "load_address_book", lambda *a, **k: BOOK)
    return tmp_path


def test_run_scan_reports_a_fork_it_could_not_create(monkeypatch):
    """`could not fork` must never look like `nothing found`: chain_id None drives CLI exit 2."""
    from dolos.forkchain import ForkError

    class Dead:
        def __init__(self, url, **kw):
            pass

        def start(self):
            raise ForkError("anvil not found")

    monkeypatch.setattr("dolos.forkchain.ForkChain", Dead)
    report = harness.run_scan("http://127.0.0.1:8545")
    assert report.chain_id is None and "could not fork" in report.note
    assert report.findings == []


def test_run_scan_counts_each_outcome_and_snapshots_every_attack(scan_env, monkeypatch):
    monkeypatch.setattr(harness, "catalog", lambda: [
        ("a", lambda ctx: _exploit()),
        ("b", lambda ctx: _held()),
        ("c", lambda ctx: _held(error="rpc died")),
    ])
    report = harness.run_scan("http://127.0.0.1:8545")
    assert (report.ran, report.exploited, report.held, report.inconclusive) == (3, 1, 1, 1)
    fork = _FakeForkChain.instance
    assert fork.snapshots == 3 and fork.reverts == 3      # the fork is left pristine
    assert fork.stopped is True


def test_run_scan_marks_the_uni_anvil_as_a_sandbox(scan_env, monkeypatch):
    monkeypatch.setattr(harness, "catalog", lambda: [("a", lambda ctx: _held())])
    assert harness.run_scan("http://127.0.0.1:8545").sandbox is True


def test_run_scan_keeps_honest_negatives_by_default(scan_env, monkeypatch):
    monkeypatch.setattr(harness, "catalog", lambda: [("b", lambda ctx: _held())])
    report = harness.run_scan("http://127.0.0.1:8545")
    assert [f.outcome for f in report.findings] == ["no_finding"]


def test_run_scan_can_drop_everything_but_exploits(scan_env, monkeypatch):
    monkeypatch.setattr(harness, "catalog", lambda: [
        ("a", lambda ctx: _exploit()), ("b", lambda ctx: _held())])
    report = harness.run_scan("http://127.0.0.1:8545", keep_negatives=False)
    assert [f.outcome for f in report.findings] == ["finding"]
    assert report.held == 1                                # still COUNTED, just not emitted


def test_one_attack_crashing_does_not_stop_the_scan(scan_env, monkeypatch):
    """A catalog entry that raises is the harness's problem, not a verdict on the contract."""
    def boom(ctx):
        raise RuntimeError("web3 blew up")

    monkeypatch.setattr(harness, "catalog", lambda: [("boom", boom), ("b", lambda ctx: _held())])
    report = harness.run_scan("http://127.0.0.1:8545")
    assert report.ran == 2 and report.inconclusive == 1 and report.held == 1
    crashed = [f for f in report.findings if f.probe == "boom"][0]
    assert crashed.outcome == "inconclusive" and "web3 blew up" in crashed.detail


def test_the_fork_is_reverted_even_when_an_attack_raises(scan_env, monkeypatch):
    def boom(ctx):
        raise RuntimeError("nope")

    monkeypatch.setattr(harness, "catalog", lambda: [("boom", boom)])
    harness.run_scan("http://127.0.0.1:8545")
    assert _FakeForkChain.instance.reverts == 1


def test_run_scan_writes_the_monitor_artifact(scan_env, monkeypatch):
    monkeypatch.setattr(harness, "catalog", lambda: [("b", lambda ctx: _held())])
    harness.run_scan("http://127.0.0.1:8545")
    doc = json.loads((scan_env / "last.json").read_text())
    assert doc["ran"] == 1 and doc["sandbox"] is True
