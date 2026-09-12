"""DOLOS CLI:  python -m dolos scan|watch|canary|fix

  scan   fork a live chain, run the attack catalog, print signed findings (JSON)
  watch  the same scan, on an interval, until stopped — the periodic auditor
  canary run the full attack->fix->retest->redeploy->re-attack cycle on the DolosCanary
  fix    run the auto-fix loop for one confirmed finding on a sandbox fork
  explain  advisory prose for a finding that ALREADY has a verdict (LLM optional)
  propose  candidate attacks from a contract's source, into an inert review queue
  intel    what BASANOS currently knows, and which weakness classes DOLOS has no attack for

`--memos PATH` on `scan` and `watch` gives DOLOS a memory of its own past outcomes. It may ONLY
reorder the catalog so a cycle spends its budget where the yield has been; it never changes a
verdict and never drops an attack. See dolos/memos.py.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _memo_store(path: str | None):
    """A memo store only when asked for — no path, no memory, byte-identical old behaviour."""
    if not path:
        return None
    from dolos.memos import MemoStore

    return MemoStore(path)


def _order_hook(store, intel_url: str | None):
    """Compose memory + external intel into ONE ordering callable for the harness.

    Composed here rather than inside the harness so the harness never imports a module that can
    open a socket — see dolos/harness.py's `order` parameter.
    """
    if store is None and not intel_url:
        return None
    from dolos.intel import catalog_categories, fetch, order_with_intel

    snap = fetch(intel_url)
    cats = catalog_categories()
    return lambda c: order_with_intel(c, memos=store, snapshot=snap, categories=cats)


def _cmd_scan(args: argparse.Namespace) -> int:
    from dolos.harness import run_scan

    store = _memo_store(args.memos)
    report = run_scan(
        args.fork_url,
        realm=args.realm,
        address_book_path=args.address_book,
        signing_key_path=args.key,
        keep_negatives=not args.only_exploits,
        memos=store,
        order=_order_hook(store, args.intel_url),
    )
    print(json.dumps(report.as_dict(), indent=1, ensure_ascii=False))
    # Exit code: 2 = could not run, 1 = at least one non-by-design exploit, 0 = clean/held-only
    if report.chain_id is None:
        return 2
    real_exploits = [f for f in report.findings
                     if f.outcome == "finding" and "[BY DESIGN" not in f.detail]
    return 1 if real_exploits else 0


def _cmd_intel(args: argparse.Namespace) -> int:
    """What BASANOS knows, and what DOLOS has nothing for. Read-only; changes no state."""
    from dolos.intel import catalog_categories, fetch

    snap = fetch(args.intel_url)
    cats = catalog_categories()
    print(json.dumps({
        **snap.describe(),
        "covered_categories": sorted(set(cats.values())),
        # The actionable half: a hot class with no attack is what `dolos propose` is for.
        "gaps": snap.gaps(set(cats.values())),
        "recent_cards": snap.recent,
    }, indent=1, ensure_ascii=False))
    return 0


def _cmd_explain(args: argparse.Namespace) -> int:
    """Prose for a finding that already has a verdict. The verdict is INPUT here, never output."""
    from dolos.llm import LLMConfig, explain_finding

    finding = json.loads(Path(args.finding).read_text(encoding="utf-8"))
    cfg = LLMConfig.from_env()
    out = explain_finding(finding, cfg=cfg)
    # The verdict is echoed back unchanged next to the prose, so a reader can see that the
    # explanation did not restate it into something else.
    print(json.dumps({"probe": finding.get("probe"), "outcome": finding.get("outcome"),
                      **out, "llm": cfg.describe()}, indent=1, ensure_ascii=False))
    return 0


def _cmd_propose(args: argparse.Namespace) -> int:
    """Candidate attacks for a human to read. Nothing here registers or runs anything."""
    from dolos.attacks import catalog
    from dolos.llm import LLMConfig, ProposalQueue, propose_attacks

    source = Path(args.source).read_text(encoding="utf-8")
    cfg = LLMConfig.from_env()
    before = [name for name, _ in catalog()]
    proposals = propose_attacks(source, existing_probes=before, cfg=cfg)
    queue = ProposalQueue(args.queue)
    fresh = queue.add(proposals)
    # Asserted, not assumed: the catalog this command saw is the catalog it leaves behind.
    assert [name for name, _ in catalog()] == before, "propose must never register an attack"
    print(json.dumps({
        "proposed": len(proposals), "new": len(fresh), "queue": str(queue.path),
        "catalog_unchanged": True, "llm": cfg.describe(),
        "proposals": [__import__("dataclasses").asdict(p) for p in fresh],
    }, indent=1, ensure_ascii=False))
    return 0


def _cmd_watch(args: argparse.Namespace) -> int:
    from dolos.watch import run_watch

    summary = run_watch(
        fork_url=args.fork_url, interval_s=args.interval, cycles=args.cycles,
        realm=args.realm, address_book_path=args.address_book,
        signing_key_path=args.key, memos_path=args.memos, intel_url=args.intel_url,
    )
    # The per-cycle lines are this command's real output and go to stdout, one JSON object per
    # line, so `dolos watch | jq` streams. The closing summary goes to stderr — otherwise stdout
    # would carry two different JSON shapes and nothing could parse it.
    print(json.dumps(summary, indent=1, ensure_ascii=False), file=sys.stderr)
    # A watcher that never completed a single scan is a failure, however long it ran — otherwise a
    # permanently unreachable chain would exit 0 and read as a healthy watcher.
    return 0 if summary["scans_ran"] else 1


def _cmd_canary(args: argparse.Namespace) -> int:
    from dolos.fixloop import run_canary_cycle

    report = run_canary_cycle(
        fork_url=None if args.standalone else args.fork_url,
        use_factory=args.factory,
    )
    print(json.dumps(report, indent=1, ensure_ascii=False))
    return 0 if report.get("fixed") else 1


def _cmd_fix(args: argparse.Namespace) -> int:
    from dolos.fixloop import run_fix_cycle

    result = run_fix_cycle(
        fork_url=args.fork_url,
        finding_file=args.finding,
        realm=args.realm,
        address_book_path=args.address_book,
        signing_key_path=args.key,
        verifier_key_path=args.verifier_key,
        allow_promote=args.promote,
    )
    print(json.dumps(result, indent=1, ensure_ascii=False))
    return 0 if result.get("fixed") else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="dolos", description="Dynamic EVM attack harness (UNI bubble)")
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--fork-url", default=os.getenv("DOLOS_FORK_URL", "http://127.0.0.1:8545"),
                        help="RPC of the LIVE chain to fork (default: the UNI anvil)")
    common.add_argument("--realm", default=os.getenv("DOLOS_REALM", "uni"))
    common.add_argument("--address-book", default=os.getenv("DOLOS_ADDRESS_BOOK"))
    common.add_argument("--key", default=os.getenv("DOLOS_SIGNING_KEY_PATH"),
                        help="Ed25519 scanner key path (findings are unsigned without it)")

    common.add_argument("--memos", default=os.getenv("DOLOS_MEMO_PATH"),
                        help="attack-memory journal; reorders the catalog, never a verdict")
    common.add_argument("--intel-url", default=os.getenv("DOLOS_INTEL_URL"),
                        help="BASANOS base URL; its distilled advisories reorder the catalog "
                             "(bounded) and report classes DOLOS has no attack for")

    s = sub.add_parser("scan", parents=[common], help="run the attack catalog")
    s.add_argument("--only-exploits", action="store_true", help="drop honest-negative findings")
    s.set_defaults(func=_cmd_scan)

    w = sub.add_parser("watch", parents=[common],
                       help="scan on an interval until stopped (the periodic auditor)")
    w.add_argument("--interval", type=int, default=None,
                   help="seconds between cycles (env DOLOS_WATCH_INTERVAL_S, default 3600)")
    w.add_argument("--cycles", type=int, default=0, help="0 = run until stopped")
    w.set_defaults(func=_cmd_watch)

    cy = sub.add_parser("canary", parents=[common],
                        help="run the full attack->fix->retest->redeploy->re-attack cycle on the DolosCanary")
    cy.add_argument("--standalone", action="store_true",
                    help="spin a throwaway anvil instead of forking --fork-url")
    cy.add_argument("--factory", action="store_true",
                    help="use the Factory patcher (DOLOS_FACTORY_FIX_URL) instead of the built-in one")
    cy.set_defaults(func=_cmd_canary)

    it = sub.add_parser("intel", help="what BASANOS knows, and which classes DOLOS cannot test")
    it.add_argument("--intel-url", default=os.getenv("DOLOS_INTEL_URL"))
    it.set_defaults(func=_cmd_intel)

    e = sub.add_parser("explain", help="advisory prose for a finding that already has a verdict")
    e.add_argument("--finding", required=True, help="path to a finding JSON")
    e.set_defaults(func=_cmd_explain)

    pr = sub.add_parser("propose", help="candidate attacks from a contract's source (inert queue)")
    pr.add_argument("--source", required=True, help="path to a .sol file")
    pr.add_argument("--queue", default=os.getenv("DOLOS_PROPOSAL_QUEUE",
                                                 "data/attack_proposals.jsonl"))
    pr.set_defaults(func=_cmd_propose)

    f = sub.add_parser("fix", parents=[common], help="auto-fix one finding on a sandbox fork")
    f.add_argument("--finding", required=True, help="path to a finding JSON to fix")
    f.add_argument("--verifier-key", default=os.getenv("DOLOS_VERIFIER_KEY_PATH"),
                   help="INDEPENDENT verifier key (must differ from --key)")
    f.add_argument("--promote", action="store_true",
                   help="after a verified fix, redeploy to the live sandbox chain (UNI only)")
    f.set_defaults(func=_cmd_fix)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
