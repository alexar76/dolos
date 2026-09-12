"""Load contract ABIs from the Foundry build output — the same artifacts the deployer used.

An attacker that guesses a function signature attacks a contract of its own imagination. DOLOS
reads the ABI straight from `<project>/out/<Sol>/<Name>.json`, so every call it makes is a call
the real contract actually exposes; an ABI that is missing means the attack is skipped (reported
as inconclusive), never faked against a made-up interface.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

# project dir (under the monorepo root) -> where its `out/` lives
_PROJECTS = {
    "core": "contracts/evm",
    "lottery": "lottery/contracts",
    "acex": "acex/contracts/evm",
}


def monorepo_root() -> Path:
    env = (os.getenv("AICOM_ROOT") or os.getenv("AICOM_MONOREPO_ROOT") or "").strip()
    if env and Path(env).is_dir():
        return Path(env)
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "contracts" / "evm").is_dir() and (parent / "lottery").is_dir():
            return parent
    return here.parents[2]  # dolos/dolos/abis.py -> repo root


def load_abi(contract: str, sol_file: str | None = None) -> list[dict[str, Any]] | None:
    """The ABI for `contract` (e.g. 'AIAgentLottery'), searched across the three projects'
    `out/` trees. `sol_file` narrows the .sol basename when several define the same name."""
    root = monorepo_root()
    sol = sol_file or f"{contract}.sol"
    for rel in _PROJECTS.values():
        candidate = root / rel / "out" / sol / f"{contract}.json"
        if candidate.is_file():
            try:
                return json.loads(candidate.read_text(encoding="utf-8")).get("abi")
            except (OSError, ValueError):
                return None
    # Fall back to a glob: some contracts live in a .sol named differently than the contract.
    for rel in _PROJECTS.values():
        out = root / rel / "out"
        if not out.is_dir():
            continue
        for path in out.glob(f"*/{contract}.json"):
            try:
                return json.loads(path.read_text(encoding="utf-8")).get("abi")
            except (OSError, ValueError):
                continue
    return None


def source_path(contract: str) -> str:
    """Repo-relative path of a contract's source, for a finding's reference_artifacts (the files
    whoever fixes the bug must read). Best-effort: returns '' when the source is not found."""
    root = monorepo_root()
    for rel in _PROJECTS.values():
        for src in (root / rel / "src").rglob(f"{contract}.sol"):
            return src.relative_to(root).as_posix()
    return ""
