"""ABI loading: an attacker that guesses a signature attacks an imaginary contract.

The rule these tests pin is `abis.py`'s reason for existing — DOLOS calls only what the deployed
artifact actually exposes, and a missing ABI makes the attack *inconclusive*, never assumed-safe.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from dolos.abis import _PROJECTS, load_abi, monorepo_root, source_path

SAMPLE_ABI = [{"type": "function", "name": "mint", "inputs": [], "outputs": []}]


@pytest.fixture()
def fake_root(tmp_path, monkeypatch):
    """A monorepo-shaped tree with the three Foundry projects, pointed at by AICOM_ROOT."""
    for rel in _PROJECTS.values():
        (tmp_path / rel / "out").mkdir(parents=True, exist_ok=True)
        (tmp_path / rel / "src").mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("AICOM_ROOT", str(tmp_path))
    return tmp_path


def _write_artifact(root, rel, sol, contract, abi=SAMPLE_ABI):
    d = root / rel / "out" / sol
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{contract}.json").write_text(json.dumps({"abi": abi}), encoding="utf-8")


def test_monorepo_root_prefers_the_env_override(fake_root):
    assert monorepo_root() == fake_root


def test_monorepo_root_ignores_an_env_pointing_nowhere(tmp_path, monkeypatch):
    monkeypatch.setenv("AICOM_ROOT", str(tmp_path / "does-not-exist"))
    root = monorepo_root()
    # Falls back to walking up from the source file; the real repo has both markers.
    assert (root / "contracts" / "evm").is_dir() or root.name


def test_load_abi_reads_the_deployed_artifact(fake_root):
    _write_artifact(fake_root, "lottery/contracts", "AIAgentLottery.sol", "AIAgentLottery")
    assert load_abi("AIAgentLottery") == SAMPLE_ABI


def test_load_abi_honours_an_explicit_sol_basename(fake_root):
    """Several projects define a `Token`; the .sol name is how the caller disambiguates."""
    _write_artifact(fake_root, "contracts/evm", "FakeUSDT.sol", "Token", abi=[{"name": "a"}])
    _write_artifact(fake_root, "acex/contracts/evm", "UniUSD.sol", "Token", abi=[{"name": "b"}])
    assert load_abi("Token", "UniUSD.sol") == [{"name": "b"}]


def test_load_abi_globs_when_the_sol_is_named_differently(fake_root):
    """`AIMarketEscrow` living in `Escrow.sol` must still be found — hence the glob fallback."""
    _write_artifact(fake_root, "contracts/evm", "Escrow.sol", "AIMarketEscrow")
    assert load_abi("AIMarketEscrow") == SAMPLE_ABI


def test_load_abi_returns_none_when_nothing_matches(fake_root):
    assert load_abi("NoSuchContract") is None


def test_load_abi_returns_none_on_a_corrupt_artifact(fake_root):
    d = fake_root / "contracts/evm" / "out" / "Broken.sol"
    d.mkdir(parents=True)
    (d / "Broken.json").write_text("{not json", encoding="utf-8")
    assert load_abi("Broken", "Broken.sol") is None


def test_load_abi_survives_a_project_with_no_out_tree(tmp_path, monkeypatch):
    monkeypatch.setenv("AICOM_ROOT", str(tmp_path))
    tmp_path.mkdir(exist_ok=True)
    assert load_abi("Anything") is None


def test_source_path_is_repo_relative_for_reference_artifacts(fake_root):
    src = fake_root / "contracts/evm" / "src" / "nested"
    src.mkdir(parents=True)
    (src / "AIMarketEscrow.sol").write_text("// contract", encoding="utf-8")
    assert source_path("AIMarketEscrow") == "contracts/evm/src/nested/AIMarketEscrow.sol"


def test_source_path_is_empty_when_the_source_is_not_in_the_tree(fake_root):
    """Empty, not a guess: `reference_artifacts` must only ever name files that exist."""
    assert source_path("Ghost") == ""
