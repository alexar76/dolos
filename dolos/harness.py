"""The orchestrator: fork a live chain, run the catalog against it, emit signed findings.

Flow, per run:
  1. read the realm's address book (universe_config.json)
  2. spawn a throwaway `anvil --fork-url <live>` (see forkchain.ForkChain)
  3. for each attack: evm_snapshot -> attack.run(ctx) -> evm_revert  (the fork is left pristine)
  4. turn each AttackResult into a signed Finding
  5. gate the FIX consequence on whether the fork is a sandbox chain (31337) — a finding from a
     fork of a real chain is advisory only; nothing is ever auto-fixed on a chain we cannot throw
     away.

The chain is NEVER the live one. `fork_url` points at the live RPC; every write lands on the fork.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from .attacks import AttackContext, AttackResult, catalog
from .findings import Evidence, Finding, FindingSigner, Outcome

if TYPE_CHECKING:
    from .memos import MemoStore

# The one chain id DOLOS treats as a disposable sandbox it may drive a fix loop against.
SANDBOX_CHAIN_IDS = {int(x) for x in os.getenv("DOLOS_SANDBOX_CHAIN_IDS", "31337").split(",") if x.strip()}


@dataclass
class ScanReport:
    fork_url: str
    chain_id: int | None
    fork_block: int | None
    sandbox: bool
    findings: list[Finding] = field(default_factory=list)
    ran: int = 0
    exploited: int = 0
    held: int = 0
    inconclusive: int = 0
    note: str = ""
    #: The order the catalog actually ran in. Empty unless a memo store reordered it — an operator
    #: reading an artifact must be able to tell whether memory was involved.
    attack_order: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        from dataclasses import asdict
        return {
            "fork_url": self.fork_url, "chain_id": self.chain_id, "fork_block": self.fork_block,
            "sandbox": self.sandbox, "ran": self.ran, "exploited": self.exploited,
            "held": self.held, "inconclusive": self.inconclusive, "note": self.note,
            "attack_order": list(self.attack_order),
            "findings": [asdict(f) for f in self.findings],
        }


def load_address_book(path: str | None = None, realm: str = "uni") -> dict[str, str]:
    """The realm's contract addresses. Tries the explicit path, then the two known UNI configs."""
    candidates = [p for p in (path,) if p] + [
        "/app/data/universe/universe_config.json",
        str(Path(__file__).resolve().parents[2] / "data" / "alien-monitor" / "universe" / "universe_config.json"),
        str(Path(__file__).resolve().parents[2] / "alien-monitor" / "data" / "universe" / "universe_config.json"),
    ]
    for cand in candidates:
        try:
            if cand and Path(cand).is_file():
                doc = json.loads(Path(cand).read_text(encoding="utf-8"))
                return {k: v for k, v in doc.items() if isinstance(v, str)}
        except (OSError, ValueError):
            continue
    return {}


def _result_to_finding(r: AttackResult, book: dict[str, str], signer: FindingSigner | None,
                       sandbox: bool) -> Finding:
    addr = ""
    for key, val in book.items():
        if key.replace("evm_", "").replace("_", "").lower() in r.target_contract.replace("Fake", "").replace("AIMarket", "").replace("AIAgent", "").lower():
            addr = val
            break
    target = f"{r.target_contract}@{addr[:10]}" if addr else r.target_contract
    detail = r.detail
    if r.exploited and not sandbox:
        detail = "[ADVISORY — fork of a non-sandbox chain; NOT auto-fixed] " + detail
    if r.exploited and r.by_design:
        detail = "[BY DESIGN in the sealed bubble — advisory, not a defect to auto-fix] " + detail
    ev = Evidence(
        request_digest="sha256-" + "0" * 8,   # the sequence, not a payload; digest of the reproducer
        response_digest="sha256-" + "0" * 8,
        request_snippet=r.reproducer[:2000],
        response_snippet=(r.error or r.title)[:2000],
        status_code=r.status_code,
        reproducer=r.reproducer,
        reference_artifacts=tuple(a for a in r.reference_artifacts if a),
    )
    # digest the reproducer so the evidence digests are real, stable, and payload-free
    import hashlib
    ev.request_digest = "sha256-" + hashlib.sha256(r.reproducer.encode()).hexdigest()
    ev.response_digest = "sha256-" + hashlib.sha256((r.error or r.detail).encode()).hexdigest()
    f = Finding(
        target=target, target_kind="evm-contract", probe=r.probe, category=r.category,
        severity=r.severity, outcome=r.outcome, title=r.title, detail=detail, evidence=ev,
    )
    if signer and signer.signed:
        signer.sign_finding(f)
    else:
        f.dedup_key = f.compute_dedup_key()
    return f


def run_scan(fork_url: str, *, realm: str = "uni", address_book_path: str | None = None,
             signing_key_path: str | None = None, keep_negatives: bool = True,
             memos: "MemoStore | None" = None, order: "Callable | None" = None) -> ScanReport:
    """Fork `fork_url`, run every attack against the fork, and return signed findings.

    `keep_negatives=True` keeps the honest 'the contract held' findings (they are what refute a
    static-analysis flag); set False to return only exploits.

    `memos` (optional) is an attack-outcome memory. It may ONLY reorder the catalog so a periodic
    scan spends its budget where the yield has been — every attack still runs, and memory never
    touches a verdict. See dolos/memos.py for why each of those limits exists.

    `order` (optional) is an ordering hook `(catalog) -> catalog`, used when the caller wants to
    combine memory with something else — external intel, say. It is a CALLABLE rather than an intel
    object on purpose: this module must not import anything that can open a socket, so that a scan
    keeps working when BASANOS, the network or a model does not. The caller composes; the harness
    only runs what it is handed, and asserts nothing was dropped.
    """
    from web3 import Web3

    from .forkchain import ForkChain, ForkError

    book = load_address_book(address_book_path, realm)
    signer = FindingSigner(signing_key_path) if signing_key_path else None
    try:
        fork = ForkChain(fork_url).start()
    except ForkError as exc:
        return ScanReport(fork_url, None, None, False, note=f"could not fork: {exc}")

    report = ScanReport(fork.fork_url, fork.chain_id, fork.fork_block,
                        sandbox=fork.chain_id in SANDBOX_CHAIN_IDS)
    try:
        w3 = Web3(Web3.HTTPProvider(fork.rpc_url))
        ctx = AttackContext(fork=fork, w3=w3, book=book, realm=realm)
        entries = catalog()
        if order is not None:
            entries = order(entries)
        elif memos is not None:
            entries = memos.order(entries)
        if order is not None or memos is not None:
            # Belt and braces: an ordering hook is caller-supplied code, and a hook that silently
            # dropped an attack would turn an untested invariant into a reported-as-checked one.
            assert len(entries) == len(catalog()), "an ordering hook must never drop an attack"
            report.attack_order = [name for name, _ in entries]
        for name, fn in entries:
            snap = fork.snapshot()
            try:
                result = fn(ctx)
            except Exception as exc:  # noqa: BLE001 - one attack's crash must not stop the scan
                result = AttackResult(name, "harness", "?", False, "info",
                                      f"attack {name} raised", str(exc)[:200],
                                      status_code=520, error=str(exc)[:200])
            finally:
                fork.revert(snap)
            report.ran += 1
            if result.outcome == Outcome.FINDING.value:
                report.exploited += 1
            elif result.outcome == Outcome.NO_FINDING.value:
                report.held += 1
            else:
                report.inconclusive += 1
            if memos is not None:
                from .memos import AttackMemo

                memos.record(AttackMemo(
                    probe=result.probe or name, target_contract=result.target_contract,
                    outcome=result.outcome, by_design=result.by_design,
                    chain_id=fork.chain_id, sandbox=report.sandbox))
            if not keep_negatives and result.outcome != Outcome.FINDING.value:
                continue
            report.findings.append(_result_to_finding(result, book, signer, report.sandbox))
    finally:
        fork.stop()
    _write_artifact(report)
    return report


def _write_artifact(report: "ScanReport") -> None:
    """Persist the scan so the Alien Monitor's DOLOS node can read what the last run found.
    Best-effort: a scan must never fail because its report could not be written."""
    import time as _time

    path = (os.getenv("DOLOS_LAST_SCAN_PATH")
            or "/app/data/universe/dolos_last_scan.json")  # mounted in the UNI monitor container
    try:
        doc = report.as_dict()
        doc["scanned_at"] = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass
