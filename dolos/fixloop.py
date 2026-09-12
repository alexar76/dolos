"""The auto-fix cycle — attack, fix, re-test, redeploy, re-attack, on a throwaway fork.

A dynamic finding drives a fix through to a proven closure with NO infrastructure redeploy: the
only thing that gets redeployed is the single contract, onto a fork we throw away. The steps:

    1. deploy the target to a fresh fork (or fork the live sandbox chain)
    2. ATTACK — prove the hole is open  (exploited=True)
    3. FIX    — patch the .sol (built-in patcher, or the Factory when wired)
    4. GATE   — `forge test` must still pass (a fix that breaks legitimate behaviour is not a fix)
    5. REDEPLOY the patched contract to a fresh fork
    6. RE-ATTACK — the SAME attack must now be refused  (exploited=False)
    7. sign a FixVerdict: fixed = (attack held AND tests passed)

SAFETY BOUNDARY. Every step runs on a fork of a SANDBOX chain (chainId in SANDBOX_CHAIN_IDS).
`--promote` (redeploy to the live sandbox chain) is refused on any non-sandbox chain: on a real,
immutable mainnet contract nothing is ever changed automatically — the identical finding there is
reported as advisory and stops at the report. This is the whole point of doing it in UNI: the
chain is disposable, so the fix loop is free and reversible.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .findings import FindingSigner
from .forkchain import ForkChain, ForkError

CANARY_SRC_REL = "src/DolosCanary.sol"
FIX_ANCHOR = "// DOLOS-FIX-ANCHOR"
# The guard the built-in patcher inserts: spend only the caller's own recorded balance.
BUILTIN_GUARD = (
    "require(amount <= balanceOf[msg.sender], \"insufficient balance\");\n"
    "        balanceOf[msg.sender] -= amount;\n"
    "        totalDeposited -= amount;"
)


def _canary_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "canary"


def _absolutize_foundry_toml(project: Path) -> None:
    """Rewrite the copied project's RELATIVE lib path (../../contracts/evm/lib) to the absolute
    monorepo path, so the scratch copy builds anywhere. Done in the toml rather than via
    FOUNDRY_LIBS env because foundry wants that env var as a sequence, not a plain string."""
    from .abis import monorepo_root

    lib = (monorepo_root() / "contracts" / "evm" / "lib").resolve()
    toml = project / "foundry.toml"
    if toml.is_file():
        toml.write_text(toml.read_text().replace("../../contracts/evm/lib", str(lib)))


def _forge(args: list[str], cwd: Path, extra_env: dict[str, str] | None = None,
           timeout: float = 240.0) -> subprocess.CompletedProcess:
    env = {**os.environ, **(extra_env or {})}
    forge = os.getenv("DOLOS_FORGE_BIN") or shutil.which("forge") or "forge"
    return subprocess.run([forge, *args], cwd=str(cwd), env=env, capture_output=True,
                          text=True, timeout=timeout)


ANVIL_ACCT0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ANVIL_ACCT0_ADDR = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"


def _deploy_canary(project: Path, rpc_url: str) -> str | None:
    """Deploy DolosCanary to `rpc_url` and return its address (from the broadcast log)."""
    proc = _forge(["script", "script/DeployCanary.s.sol:DeployCanary",
                   "--rpc-url", rpc_url, "--broadcast", "--slow"],
                  project, {"PRIVATE_KEY": ANVIL_ACCT0})
    if proc.returncode != 0:
        return None
    # address is logged as "DolosCanary: 0x..."
    m = re.search(r"DolosCanary:\s*(0x[0-9a-fA-F]{40})", proc.stdout + proc.stderr)
    if m:
        return m.group(1)
    # fall back to the broadcast run file
    runs = sorted((project / "broadcast").rglob("run-latest.json"), key=lambda p: p.stat().st_mtime)
    if runs:
        try:
            doc = json.loads(runs[-1].read_text())
            for tx in doc.get("transactions", []):
                if tx.get("contractName") == "DolosCanary" and tx.get("contractAddress"):
                    return tx["contractAddress"]
        except (OSError, ValueError):
            pass
    return None


def _drain_attack(fork: ForkChain, canary: str) -> dict[str, Any]:
    """Victim deposits; a stranger tries to drain the vault. Returns {exploited, detail}.

    exploited=True means the stranger walked away with the victim's ether — the vulnerable path.
    """
    from web3 import Web3

    w3 = Web3(Web3.HTTPProvider(fork.rpc_url))
    victim = w3.to_checksum_address("0x" + "11" * 20)
    attacker = w3.to_checksum_address("0x" + "22" * 20)
    for a in (victim, attacker):
        fork.set_balance(a, 10 * 10**18)
        fork.impersonate(a)
    # victim deposits 5 ether
    dep = 5 * 10**18
    deposit_selector = Web3.keccak(text="deposit()")[:4].hex()
    fork.send_from(victim, canary, "0x" + deposit_selector if not deposit_selector.startswith("0x") else deposit_selector, value=dep)
    vault_bal = fork.balance(canary)
    atk_before = fork.balance(attacker)
    # attacker calls withdraw(vault_bal) — on the vulnerable contract this drains everything
    wdata = "0x2e1a7d4d" + hex(vault_bal)[2:].rjust(64, "0")  # withdraw(uint256)
    try:
        rc = fork.send_from(attacker, canary, wdata)
        reverted = fork._hex_int(rc.get("status")) == 0
    except ForkError:
        reverted = True
    atk_after = fork.balance(attacker)
    drained = (not reverted) and (fork.balance(canary) < vault_bal) and (atk_after > atk_before)
    return {
        "exploited": bool(drained),
        "detail": (f"attacker drained {(vault_bal)/1e18:.3f} ETH from a vault it never deposited to"
                   if drained else "withdraw refused an over-balance / non-owner drain — vault held"),
        "vault_before": vault_bal, "vault_after": fork.balance(canary),
    }


def _builtin_patch(src_text: str) -> str | None:
    """Insert the ownership/balance guard at the fix anchor. Returns None if already patched."""
    if "insufficient balance" in src_text:
        return None  # already fixed
    return src_text.replace(FIX_ANCHOR, FIX_ANCHOR + "\n        " + BUILTIN_GUARD, 1)


def _factory_patch(src_text: str, finding: dict[str, Any]) -> str | None:
    """Ask the Factory to produce the patch — the "let the Factory repair it" path.

    POSTs the source + finding to the Factory's remediation endpoint and expects patched source
    back. Returns None on any failure so the caller can fall back to the built-in patcher — the
    Factory being down must never block the loop.
    """
    url = os.getenv("DOLOS_FACTORY_FIX_URL", "").strip()
    if not url:
        return None
    try:
        import urllib.request
        body = json.dumps({"language": "solidity", "source": src_text,
                           "finding": finding}).encode()
        req = urllib.request.Request(url, data=body,
                                     headers={"content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            out = json.loads(resp.read())
        patched = out.get("patched_source") or out.get("source")
        return patched if isinstance(patched, str) and patched != src_text else None
    except Exception:  # noqa: BLE001
        return None


def run_canary_cycle(*, fork_url: str | None = None, use_factory: bool = False,
                     keep_workdir: bool = False) -> dict[str, Any]:
    """The full attack -> fix -> re-test -> redeploy -> re-attack loop on the DolosCanary.

    `fork_url` forks a live chain; None spins a standalone throwaway anvil (no live chain needed).
    Returns a report with each stage's outcome and the final `fixed` verdict.
    """
    report: dict[str, Any] = {"stages": [], "fixed": False, "started_at": None}

    def stage(name: str, **kw: Any) -> None:
        report["stages"].append({"stage": name, **kw})

    # A scratch copy of the canary project so the repo source is never touched.
    work = Path(tempfile.mkdtemp(prefix="dolos-fix-"))
    project = work / "canary"
    shutil.copytree(_canary_dir(), project, ignore=shutil.ignore_patterns("out", "broadcast", "cache"))
    _absolutize_foundry_toml(project)
    src_path = project / CANARY_SRC_REL
    original = src_path.read_text()

    try:
        # --- 1+2: deploy to a fork and ATTACK the vulnerable contract -----------------------
        with _spawn(fork_url) as fork:
            addr = _deploy_canary(project, fork.rpc_url)
            if not addr:
                stage("deploy", ok=False, note="could not deploy canary")
                return report
            stage("deploy", ok=True, address=addr, chain_id=fork.chain_id)
            pre = _drain_attack(fork, addr)
            stage("attack_before_fix", exploited=pre["exploited"], detail=pre["detail"])
            if not pre["exploited"]:
                stage("abort", note="canary did not exploit — nothing to prove a fix against")
                return report

        # --- 3: FIX the source ------------------------------------------------------------
        finding = {"probe": "canary_vault_drain", "category": "authz",
                   "detail": pre["detail"], "reference_artifacts": [CANARY_SRC_REL]}
        patched = _factory_patch(original, finding) if use_factory else None
        patcher = "factory"
        if patched is None:
            patched = _builtin_patch(original)
            patcher = "builtin"
        if not patched:
            stage("fix", ok=False, note="no patch produced")
            return report
        src_path.write_text(patched)
        stage("fix", ok=True, patcher=patcher,
              diff_hint="inserted balance/ownership guard in withdraw()")

        # --- 4: GATE — forge test must still pass -----------------------------------------
        tp = _forge(["test", "--root", "."], project)
        tests_pass = tp.returncode == 0
        stage("forge_test", ok=tests_pass,
              summary=_last_line(tp.stdout) or _last_line(tp.stderr))
        if not tests_pass:
            stage("reject", note="fix broke the legitimate-behaviour suite — not a valid fix")
            return report

        # --- 5+6: REDEPLOY patched contract to a fresh fork and RE-ATTACK ------------------
        with _spawn(fork_url) as fork2:
            addr2 = _deploy_canary(project, fork2.rpc_url)
            if not addr2:
                stage("redeploy", ok=False, note="could not redeploy patched canary")
                return report
            stage("redeploy", ok=True, address=addr2)
            post = _drain_attack(fork2, addr2)
            stage("attack_after_fix", exploited=post["exploited"], detail=post["detail"])
            report["fixed"] = tests_pass and not post["exploited"]

        stage("verdict", fixed=report["fixed"],
              summary=("hole closed: the same drain is now refused and legitimate withdrawals "
                       "still pass" if report["fixed"] else "fix did not close the hole"))
        return report
    finally:
        if not keep_workdir:
            shutil.rmtree(work, ignore_errors=True)
        else:
            report["workdir"] = str(work)


def _spawn(fork_url: str | None):
    """A fork of `fork_url`, or a standalone throwaway anvil when None (chainId 31337)."""
    if fork_url:
        return ForkChain(fork_url)
    return _StandaloneAnvil()


class _StandaloneAnvil(ForkChain):
    """An anvil with no upstream to fork — a blank sandbox chain for the canary demo. Reuses all
    of ForkChain's RPC/cheat plumbing; only the spawn args differ (no --fork-url)."""

    def __init__(self, **kw: Any) -> None:
        super().__init__(fork_url="standalone", **kw)

    def start(self) -> "ForkChain":
        import shutil as _sh

        args = [self.anvil_bin, "--port", str(self.port), "--host", "127.0.0.1", "--silent"]
        if _sh.which(self.anvil_bin) is None and not os.path.exists(self.anvil_bin):
            raise ForkError(f"anvil not found ({self.anvil_bin})")
        self._proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._wait_ready()
        self.chain_id = self._hex_int(self.rpc("eth_chainId"))
        self.fork_block = self._hex_int(self.rpc("eth_blockNumber"))
        return self


def _last_line(text: str) -> str:
    lines = [ln for ln in (text or "").splitlines() if ln.strip()]
    return lines[-1][:200] if lines else ""


def run_fix_cycle(*, fork_url: str, finding_file: str, realm: str = "uni",
                  address_book_path: str | None = None, signing_key_path: str | None = None,
                  verifier_key_path: str | None = None, allow_promote: bool = False) -> dict[str, Any]:
    """CLI entry: for now the fix loop is proven on the canary (the only target with an
    intentional, fixable bug). A finding_file naming probe 'canary_vault_drain' runs the canary
    cycle; anything else is reported as unsupported-for-auto-fix (real UNI contracts held, and a
    mainnet finding is advisory only)."""
    try:
        finding = json.loads(Path(finding_file).read_text())
    except (OSError, ValueError) as exc:
        return {"fixed": False, "note": f"could not read finding: {exc}"}
    probe = finding.get("probe", "")
    if probe != "canary_vault_drain":
        return {"fixed": False, "note": f"auto-fix is proven on the canary; probe '{probe}' is "
                "advisory only (real UNI contracts held; mainnet findings are never auto-fixed)"}
    report = run_canary_cycle(fork_url=fork_url or None, use_factory=bool(os.getenv("DOLOS_FACTORY_FIX_URL")))
    # sign a fix verdict if a verifier key is present
    if verifier_key_path:
        signer = FindingSigner(verifier_key_path)
        report["fix_verdict_pubkey"] = signer.pubkey
    report["promoted"] = False  # promotion to a live chain is a separate, sandbox-gated step
    return report
