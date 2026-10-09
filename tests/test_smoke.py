"""Integration smoke tests. Guarded: they self-skip where Foundry (anvil/forge) or web3 is
absent, so the suite is green on a laptop with only the pure deps and exercises the real thing in
a container that has the toolchain."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest


def _has(bin_name: str) -> bool:
    return shutil.which(os.getenv(f"DOLOS_{bin_name.upper()}_BIN", "") or bin_name) is not None


def _has_web3() -> bool:
    try:
        import web3  # noqa: F401
        return True
    except Exception:
        return False


anvil_only = pytest.mark.skipif(not _has("anvil"), reason="anvil not installed")
full_stack = pytest.mark.skipif(not (_has("anvil") and _has("forge") and _has_web3()),
                                reason="needs anvil + forge + web3")


@anvil_only
def test_fork_snapshot_revert_roundtrip():
    """A mutation inside a snapshot must vanish on revert — the property that makes attacks safe."""
    from dolos.forkchain import ForkChain

    # spin a source anvil to fork
    src = subprocess.Popen(["anvil", "--port", "8557", "--silent"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(2)
        with ForkChain(fork_url="http://127.0.0.1:8557") as fork:
            assert fork.chain_id == 31337
            victim = "0x1111111111111111111111111111111111111111"
            dst = "0x2222222222222222222222222222222222222222"
            fork.set_balance(victim, 5 * 10**18)
            fork.impersonate(victim)
            snap = fork.snapshot()
            fork.send_from(victim, dst, value=10**18)
            assert fork.balance(dst) == 10**18
            assert fork.revert(snap)
            assert fork.balance(dst) == 0  # the mutation did not outlive the snapshot
    finally:
        src.terminate()


@anvil_only
def test_fork_refuses_without_a_url():
    from dolos.forkchain import ForkChain, ForkError

    with pytest.raises(ForkError):
        ForkChain(fork_url="")


@full_stack
def test_canary_cycle_closes_the_hole():
    """The whole point: attack proves the drain, the fix closes it, the same attack is then
    refused, and legitimate withdrawals still pass. Runs on a standalone throwaway anvil."""
    from dolos.fixloop import run_canary_cycle

    report = run_canary_cycle(fork_url=None)
    stages = {s["stage"]: s for s in report["stages"]}
    assert stages["attack_before_fix"]["exploited"] is True, "the canary should be drainable"
    assert stages["forge_test"]["ok"] is True, "the fix must keep the legit suite green"
    assert stages["attack_after_fix"]["exploited"] is False, "the fix must close the drain"
    assert report["fixed"] is True
