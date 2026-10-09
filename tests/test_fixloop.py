"""The auto-fix cycle's decision machine, driven without Foundry.

test_smoke.py runs the real loop where anvil+forge exist. These tests pin the parts a green
end-to-end run would hide: what happens when the patch is refused, when `forge test` goes red,
when the canary refuses to be exploited in the first place, and what `fix` will not touch.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from conftest import FakeFork

from dolos import fixloop
from dolos.fixloop import (
    BUILTIN_GUARD,
    FIX_ANCHOR,
    _absolutize_foundry_toml,
    _builtin_patch,
    _deploy_canary,
    _drain_attack,
    _factory_patch,
    _last_line,
    _spawn,
    _StandaloneAnvil,
    run_canary_cycle,
    run_fix_cycle,
)

VULNERABLE = f"""contract DolosCanary {{
    function withdraw(uint256 amount) external {{
        {FIX_ANCHOR}
        payable(msg.sender).transfer(amount);
    }}
}}
"""


# --------------------------------------------------------------------------- patching


def test_builtin_patch_inserts_the_guard_at_the_anchor():
    patched = _builtin_patch(VULNERABLE)
    assert BUILTIN_GUARD.splitlines()[0] in patched
    assert patched.index(FIX_ANCHOR) < patched.index("insufficient balance")


def test_builtin_patch_is_idempotent():
    """A second pass over already-fixed source returns None so the loop reports 'no patch
    produced' instead of stacking a duplicate guard."""
    assert _builtin_patch(_builtin_patch(VULNERABLE)) is None


def test_factory_patch_is_skipped_when_not_configured(monkeypatch):
    monkeypatch.delenv("DOLOS_FACTORY_FIX_URL", raising=False)
    assert _factory_patch(VULNERABLE, {}) is None


def test_factory_patch_accepts_patched_source(monkeypatch):
    monkeypatch.setenv("DOLOS_FACTORY_FIX_URL", "http://factory/api/remediation/solidity")
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **k: _resp({"patched_source": VULNERABLE + "// fixed"}))
    assert _factory_patch(VULNERABLE, {}) == VULNERABLE + "// fixed"


def test_factory_patch_ignores_an_unchanged_source(monkeypatch):
    """A Factory that echoes the input has not fixed anything; the loop must fall back."""
    monkeypatch.setenv("DOLOS_FACTORY_FIX_URL", "http://factory/x")
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _resp({"source": VULNERABLE}))
    assert _factory_patch(VULNERABLE, {}) is None


def test_factory_being_down_never_blocks_the_loop(monkeypatch):
    monkeypatch.setenv("DOLOS_FACTORY_FIX_URL", "http://factory/x")

    def boom(*a, **k):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    assert _factory_patch(VULNERABLE, {}) is None


@contextlib.contextmanager
def _resp_cm(payload):
    yield io.BytesIO(json.dumps(payload).encode())


def _resp(payload):
    return _resp_cm(payload)


# --------------------------------------------------------------------------- helpers


def test_last_line_returns_the_final_non_empty_line():
    assert _last_line("a\n\nSuite result: ok\n\n") == "Suite result: ok"
    assert _last_line("") == ""


def test_spawn_uses_a_standalone_anvil_when_there_is_nothing_to_fork():
    """`canary --standalone` must need no live chain at all."""
    assert isinstance(_spawn(None), _StandaloneAnvil)
    assert _spawn(None).fork_url == "standalone"


def test_spawn_forks_the_given_url():
    from dolos.forkchain import ForkChain

    fork = _spawn("http://127.0.0.1:8545")
    assert isinstance(fork, ForkChain) and not isinstance(fork, _StandaloneAnvil)


def test_absolutize_foundry_toml_rewrites_the_relative_lib_path(tmp_path):
    """The scratch copy lives in /tmp, so a relative `../../contracts/evm/lib` would not resolve."""
    (tmp_path / "foundry.toml").write_text('libs = ["../../contracts/evm/lib"]', encoding="utf-8")
    _absolutize_foundry_toml(tmp_path)
    assert "../../contracts/evm/lib" not in (tmp_path / "foundry.toml").read_text()


def test_absolutize_foundry_toml_is_a_noop_without_a_toml(tmp_path):
    _absolutize_foundry_toml(tmp_path)      # must not raise


# --------------------------------------------------------------------------- deploy parsing


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def test_deploy_reads_the_address_from_the_forge_log(tmp_path, monkeypatch):
    addr = "0x" + "ab" * 20
    monkeypatch.setattr(fixloop, "_forge", lambda *a, **k: _Proc(stdout=f"DolosCanary: {addr}\n"))
    assert _deploy_canary(tmp_path, "http://x") == addr


def test_deploy_falls_back_to_the_broadcast_run_file(tmp_path, monkeypatch):
    addr = "0x" + "cd" * 20
    run = tmp_path / "broadcast" / "DeployCanary.s.sol" / "31337"
    run.mkdir(parents=True)
    (run / "run-latest.json").write_text(json.dumps(
        {"transactions": [{"contractName": "DolosCanary", "contractAddress": addr}]}))
    monkeypatch.setattr(fixloop, "_forge", lambda *a, **k: _Proc(stdout="no address here"))
    assert _deploy_canary(tmp_path, "http://x") == addr


def test_deploy_returns_none_when_forge_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(fixloop, "_forge", lambda *a, **k: _Proc(returncode=1, stderr="revert"))
    assert _deploy_canary(tmp_path, "http://x") is None


def test_deploy_returns_none_when_nothing_names_the_contract(tmp_path, monkeypatch):
    monkeypatch.setattr(fixloop, "_forge", lambda *a, **k: _Proc(stdout="quiet"))
    assert _deploy_canary(tmp_path, "http://x") is None


# --------------------------------------------------------------------------- the drain attack


CANARY = "0x" + "99" * 20


def _scripted_balances(fork, values):
    """`_drain_attack` reads balances in a fixed order (vault, attacker-before, attacker-after,
    vault-after…), so scripting the sequence is clearer than faking an EVM."""
    seq = iter(values)
    fork.balance = lambda addr, _seq=seq: next(_seq, 0)
    return fork


def test_drain_attack_reports_a_successful_drain():
    """The stranger walked away with ether it never deposited: vault down, attacker up."""
    fork = _scripted_balances(
        FakeFork(), [5 * 10**18,          # vault after the victim's deposit
                     10 * 10**18,         # attacker before
                     14 * 10**18,         # attacker after — richer
                     0, 0])               # vault after — emptied
    fork.send_results = [{"status": "0x1"}, {"status": "0x1"}]
    result = _drain_attack(fork, CANARY)
    assert result["exploited"] is True and "drained" in result["detail"]
    assert result["vault_before"] == 5 * 10**18 and result["vault_after"] == 0


def test_a_withdraw_that_moved_nothing_is_not_a_drain():
    """Receipt status 1 is not proof of theft — the balances have to have moved."""
    fork = _scripted_balances(
        FakeFork(), [5 * 10**18, 10 * 10**18, 10 * 10**18, 5 * 10**18, 5 * 10**18])
    fork.send_results = [{"status": "0x1"}, {"status": "0x1"}]
    assert _drain_attack(fork, CANARY)["exploited"] is False


def test_drain_attack_reports_a_vault_that_held():
    """The post-fix shape: the withdraw reverts, so nothing moved."""
    fork = _scripted_balances(FakeFork(), [5 * 10**18] * 6)
    fork.send_results = [{"status": "0x1"}, {"status": "0x0"}]
    result = _drain_attack(fork, CANARY)
    assert result["exploited"] is False and "held" in result["detail"]


def test_drain_attack_treats_a_fork_error_as_a_revert():
    from dolos.forkchain import ForkError

    fork = _scripted_balances(FakeFork(), [5 * 10**18] * 6)
    fork.send_results = [{"status": "0x1"}, ForkError("no receipt")]
    assert _drain_attack(fork, CANARY)["exploited"] is False


# --------------------------------------------------------------------------- the cycle


@pytest.fixture()
def cycle(monkeypatch):
    """Drive run_canary_cycle with every external tool replaced, so only its logic is under test."""
    state = {"deploys": 0, "attacks": [], "forge_rc": 0}

    @contextlib.contextmanager
    def fake_spawn(url):
        yield FakeFork()

    def fake_deploy(project, rpc):
        state["deploys"] += 1
        return None if state.get("deploy_fails") else "0x" + "ee" * 20

    def fake_drain(fork, addr):
        exploited = state["attacks_plan"].pop(0)
        state["attacks"].append(exploited)
        return {"exploited": exploited, "detail": "drained" if exploited else "held"}

    monkeypatch.setattr(fixloop, "_spawn", fake_spawn)
    monkeypatch.setattr(fixloop, "_deploy_canary", fake_deploy)
    monkeypatch.setattr(fixloop, "_drain_attack", fake_drain)
    monkeypatch.setattr(fixloop, "_forge",
                        lambda *a, **k: _Proc(returncode=state["forge_rc"], stdout="Suite ok"))
    state["attacks_plan"] = [True, False]
    return state


def _stages(report):
    return {s["stage"]: s for s in report["stages"]}


def test_the_cycle_closes_the_hole(cycle):
    report = run_canary_cycle(fork_url=None)
    stages = _stages(report)
    assert stages["attack_before_fix"]["exploited"] is True
    assert stages["fix"]["patcher"] == "builtin"
    assert stages["forge_test"]["ok"] is True
    assert stages["attack_after_fix"]["exploited"] is False
    assert report["fixed"] is True and stages["verdict"]["fixed"] is True


def test_a_fix_that_breaks_the_legit_suite_is_rejected(cycle):
    """A patch that closes the hole by breaking legitimate withdrawals is not a fix."""
    cycle["forge_rc"] = 1
    report = run_canary_cycle(fork_url=None)
    stages = _stages(report)
    assert stages["forge_test"]["ok"] is False and "reject" in stages
    assert report["fixed"] is False and "attack_after_fix" not in stages


def test_a_canary_that_cannot_be_exploited_aborts_before_patching(cycle):
    """Nothing to prove a fix against — and silently 'fixing' it would be a lie."""
    cycle["attacks_plan"] = [False]
    report = run_canary_cycle(fork_url=None)
    stages = _stages(report)
    assert "abort" in stages and "fix" not in stages and report["fixed"] is False


def test_a_failed_deploy_stops_the_cycle(cycle):
    cycle["deploy_fails"] = True
    report = run_canary_cycle(fork_url=None)
    assert _stages(report)["deploy"]["ok"] is False and report["fixed"] is False


def test_the_cycle_never_touches_the_repo_source(cycle):
    """It patches a scratch copy; the committed canary must stay vulnerable for the next run."""
    src = fixloop._canary_dir() / fixloop.CANARY_SRC_REL
    before = src.read_text()
    run_canary_cycle(fork_url=None)
    assert src.read_text() == before


def test_keep_workdir_reports_where_the_scratch_copy_is(cycle, tmp_path):
    import shutil

    report = run_canary_cycle(fork_url=None, keep_workdir=True)
    assert os.path.isdir(report["workdir"])
    shutil.rmtree(report["workdir"], ignore_errors=True)


def test_the_factory_patcher_is_used_when_asked(cycle, monkeypatch):
    monkeypatch.setattr(fixloop, "_factory_patch", lambda src, finding: src + "// factory guard")
    report = run_canary_cycle(fork_url=None, use_factory=True)
    assert _stages(report)["fix"]["patcher"] == "factory"


def test_the_builtin_patcher_covers_for_a_silent_factory(cycle, monkeypatch):
    monkeypatch.setattr(fixloop, "_factory_patch", lambda src, finding: None)
    report = run_canary_cycle(fork_url=None, use_factory=True)
    assert _stages(report)["fix"]["patcher"] == "builtin"


# --------------------------------------------------------------------------- run_fix_cycle guards


def test_fix_refuses_a_finding_file_it_cannot_read(tmp_path):
    out = run_fix_cycle(fork_url="http://x", finding_file=str(tmp_path / "nope.json"))
    assert out["fixed"] is False and "could not read" in out["note"]


def test_fix_refuses_a_probe_it_cannot_prove(tmp_path):
    """Auto-fix is proven on the canary only. Everything else is advisory — including every real
    UNI contract, all of which held."""
    p = tmp_path / "f.json"
    p.write_text(json.dumps({"probe": "escrow_channel_hijack"}), encoding="utf-8")
    out = run_fix_cycle(fork_url="http://x", finding_file=str(p))
    assert out["fixed"] is False and "advisory only" in out["note"]


def test_fix_runs_the_canary_cycle_and_never_auto_promotes(tmp_path, monkeypatch):
    """Promotion to a live chain is a separate, sandbox-gated step — never a side effect."""
    p = tmp_path / "f.json"
    p.write_text(json.dumps({"probe": "canary_vault_drain"}), encoding="utf-8")
    monkeypatch.setattr(fixloop, "run_canary_cycle",
                        lambda **kw: {"fixed": True, "stages": []})
    out = run_fix_cycle(fork_url="http://x", finding_file=str(p),
                        verifier_key_path=str(tmp_path / "verifier_key"))
    assert out["fixed"] is True and out["promoted"] is False
    assert out["fix_verdict_pubkey"]                       # signed by an INDEPENDENT key
