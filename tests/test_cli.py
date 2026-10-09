"""The CLI contract — above all its exit codes, which are what CI and the conductor read.

  scan  0 = the contracts held   1 = a real (non-by-design) exploit   2 = could not run
  canary/fix  0 = the hole was closed   1 = it was not

Conflating 2 with 0 would turn "we never reached the chain" into "all clear", which is the one
mistake this harness exists to avoid.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from conftest import exploit_result, held_result

from dolos import fixloop, harness
from dolos.__main__ import main
from dolos.harness import ScanReport, _result_to_finding


def _report(*results, chain_id=31337, sandbox=True) -> ScanReport:
    r = ScanReport("http://127.0.0.1:8545", chain_id, 12, sandbox)
    for res in results:
        r.findings.append(_result_to_finding(res, {}, None, sandbox))
        r.ran += 1
    return r


@pytest.fixture()
def scan(monkeypatch):
    """Capture what the CLI passed to run_scan, and script what it gets back."""
    seen = {}

    def fake(fork_url, **kw):
        seen.update({"fork_url": fork_url, **kw})
        return seen["report"]

    monkeypatch.setattr(harness, "run_scan", fake)
    return seen


def test_scan_exits_0_when_every_contract_held(scan, capsys):
    scan["report"] = _report(held_result())
    assert main(["scan"]) == 0
    assert json.loads(capsys.readouterr().out)["ran"] == 1


def test_scan_exits_1_on_a_real_exploit(scan):
    scan["report"] = _report(exploit_result())
    assert main(["scan"]) == 1


def test_scan_exits_0_when_the_only_exploit_is_by_design(scan):
    """The bubble's open-mint faucet must not fail CI on every run."""
    scan["report"] = _report(exploit_result(by_design=True))
    assert main(["scan"]) == 0


def test_scan_exits_2_when_the_fork_could_not_be_created(scan):
    scan["report"] = ScanReport("http://x", None, None, False, note="could not fork: no anvil")
    assert main(["scan"]) == 2


def test_scan_exits_1_for_an_advisory_exploit_on_a_non_sandbox_fork(scan):
    """Advisory means "not auto-fixed", not "ignore it" — a human still has to see it."""
    scan["report"] = _report(exploit_result(), sandbox=False, chain_id=8453)
    assert main(["scan"]) == 1


def test_scan_keeps_negatives_by_default(scan):
    scan["report"] = _report(held_result())
    main(["scan"])
    assert scan["keep_negatives"] is True


def test_only_exploits_drops_the_honest_negatives(scan):
    scan["report"] = _report(held_result())
    main(["scan", "--only-exploits"])
    assert scan["keep_negatives"] is False


def test_scan_defaults_to_the_uni_anvil(scan, monkeypatch):
    monkeypatch.delenv("DOLOS_FORK_URL", raising=False)
    scan["report"] = _report(held_result())
    main(["scan"])
    assert scan["fork_url"] == "http://127.0.0.1:8545"


def test_the_fork_url_is_operator_configurable(scan, monkeypatch):
    monkeypatch.setenv("DOLOS_FORK_URL", "http://10.0.0.5:8545")
    scan["report"] = _report(held_result())
    main(["scan"])
    assert scan["fork_url"] == "http://10.0.0.5:8545"


def test_scan_passes_the_realm_key_and_address_book(scan):
    scan["report"] = _report(held_result())
    main(["scan", "--realm", "live", "--address-book", "/tmp/book.json", "--key", "/tmp/k"])
    assert scan["realm"] == "live"
    assert scan["address_book_path"] == "/tmp/book.json"
    assert scan["signing_key_path"] == "/tmp/k"


# --------------------------------------------------------------------------- canary / fix


def test_canary_exits_0_when_the_hole_was_closed(monkeypatch, capsys):
    monkeypatch.setattr(fixloop, "run_canary_cycle", lambda **kw: {"fixed": True, "stages": []})
    assert main(["canary", "--standalone"]) == 0
    assert json.loads(capsys.readouterr().out)["fixed"] is True


def test_canary_exits_1_when_the_hole_is_still_open(monkeypatch):
    monkeypatch.setattr(fixloop, "run_canary_cycle", lambda **kw: {"fixed": False, "stages": []})
    assert main(["canary", "--standalone"]) == 1


def test_standalone_canary_needs_no_live_chain(monkeypatch):
    seen = {}
    monkeypatch.setattr(fixloop, "run_canary_cycle",
                        lambda **kw: seen.update(kw) or {"fixed": True})
    main(["canary", "--standalone"])
    assert seen["fork_url"] is None


def test_canary_forks_the_given_chain_when_not_standalone(monkeypatch):
    seen = {}
    monkeypatch.setattr(fixloop, "run_canary_cycle",
                        lambda **kw: seen.update(kw) or {"fixed": True})
    main(["canary", "--fork-url", "http://127.0.0.1:9999"])
    assert seen["fork_url"] == "http://127.0.0.1:9999"
    assert seen["use_factory"] is False


def test_canary_can_be_told_to_use_the_factory_patcher(monkeypatch):
    seen = {}
    monkeypatch.setattr(fixloop, "run_canary_cycle",
                        lambda **kw: seen.update(kw) or {"fixed": True})
    main(["canary", "--standalone", "--factory"])
    assert seen["use_factory"] is True


def test_fix_forwards_the_independent_verifier_key(monkeypatch):
    seen = {}
    monkeypatch.setattr(fixloop, "run_fix_cycle", lambda **kw: seen.update(kw) or {"fixed": True})
    assert main(["fix", "--finding", "/tmp/f.json", "--verifier-key", "/tmp/v"]) == 0
    assert seen["verifier_key_path"] == "/tmp/v" and seen["allow_promote"] is False


def test_fix_promotion_is_opt_in(monkeypatch):
    seen = {}
    monkeypatch.setattr(fixloop, "run_fix_cycle", lambda **kw: seen.update(kw) or {"fixed": True})
    main(["fix", "--finding", "/tmp/f.json", "--promote"])
    assert seen["allow_promote"] is True


def test_fix_exits_1_when_nothing_was_fixed(monkeypatch):
    monkeypatch.setattr(fixloop, "run_fix_cycle", lambda **kw: {"fixed": False, "note": "nope"})
    assert main(["fix", "--finding", "/tmp/f.json"]) == 1


def test_fix_requires_a_finding_file():
    with pytest.raises(SystemExit) as exc:
        main(["fix"])
    assert exc.value.code == 2


def test_a_subcommand_is_required():
    with pytest.raises(SystemExit):
        main([])
