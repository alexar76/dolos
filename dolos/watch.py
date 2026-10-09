"""Periodic scanning — the loop that turns DOLOS from a thing you run into a thing that watches.

Until this existed, nothing in the tree scheduled a contract scan: no timer, no cron, no interval.
The monitor node therefore showed whatever the last hand-run had left behind, and "DOLOS audits the
bubble's contracts" was true only on the days somebody typed the command. Neither BASANOS nor MOMUS
had a scheduler either — this is the first one.

TWO WAYS TO RUN IT, AND WHICH TO PREFER
---------------------------------------
- **A systemd timer calling `dolos scan --memos …`** — the recommended production shape. Each cycle
  is a fresh process, so a leak, a wedged anvil child or an OOM costs one cycle instead of the
  watcher; the timer restarts it for free and `OnCalendar` does not drift. See `deploy/` below.
- **`dolos watch`** — this module. One long-lived process on an interval. Right for a laptop, a
  container without a timer, or watching the loop while you develop it.

WHAT A CYCLE MUST NEVER DO
--------------------------
Stop the next one. A cycle that cannot reach the chain, cannot read the address book or raises
somewhere unexpected records the reason and waits — it never exits the loop. The failure mode this
avoids is the one that matters: a watcher that died three weeks ago looks exactly like a watcher
reporting no problems, and the artifact would keep serving a stale green verdict.

Every cycle emits one JSON line on stdout, so under systemd the journal *is* the scan history.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import time
from typing import Any

#: Default gap between cycles. An hour: long enough that a fork-and-attack pass is a rounding error
#: on the host, short enough that a regression is caught the same working day.
DEFAULT_INTERVAL_S = 3600

#: Refuse to spin faster than this. A one-second watch loop would fork a chain in a hot loop and
#: look, from the outside, exactly like a resource attack on the host.
MIN_INTERVAL_S = 30


def resolve_interval(raw: str | int | None = None) -> tuple[int, str]:
    """Interval in seconds, plus a human reason. Junk degrades to the default rather than raising —
    a scheduler that refuses to start because of a typo'd env var stops watching."""
    value = raw if raw is not None else os.environ.get("DOLOS_WATCH_INTERVAL_S")
    try:
        seconds = int(str(value).strip())
    except (TypeError, ValueError):
        if value in (None, ""):
            return DEFAULT_INTERVAL_S, f"default {DEFAULT_INTERVAL_S}s"
        return DEFAULT_INTERVAL_S, f"unparseable interval {value!r} — using {DEFAULT_INTERVAL_S}s"
    if seconds < MIN_INTERVAL_S:
        return MIN_INTERVAL_S, f"{seconds}s is below the {MIN_INTERVAL_S}s floor — clamped"
    return seconds, f"{seconds}s"


def memo_path(explicit: str | None = None) -> str:
    return (explicit or os.environ.get("DOLOS_MEMO_PATH")
            or os.path.join(os.environ.get("DOLOS_DATA_DIR", "data"), "attack_memos.jsonl"))


class _Stopper:
    """Turns SIGTERM/SIGINT into a clean end-of-cycle exit instead of a traceback.

    systemd sends SIGTERM on stop and restart, and a watcher killed mid-attack would leave an anvil
    child orphaned — the loop finishes the cycle it is in, then stops.
    """

    def __init__(self) -> None:
        self.stop = False
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, self._handle)
            except (ValueError, OSError):
                pass        # not the main thread (e.g. under a test runner) — polling still works

    def _handle(self, *_a: Any) -> None:
        self.stop = True


def run_watch(*, fork_url: str, interval_s: int | None = None, cycles: int = 0,
              realm: str = "uni", address_book_path: str | None = None,
              signing_key_path: str | None = None, memos_path: str | None = None,
              intel_url: str | None = None, emit=None, sleep=None) -> dict[str, Any]:
    """Scan on an interval until stopped (or until `cycles` cycles have run).

    `cycles=0` means forever. `emit`/`sleep` are injected so the loop is testable without a clock.

    Both default to None rather than to `print`/`time.sleep` directly: a default argument is bound
    once, when the function is DEFINED, so `sleep=time.sleep` would capture the real clock and no
    later monkeypatch could reach it — a test would then sleep for the whole interval instead of
    running.
    """
    from .harness import run_scan
    from .intel import catalog_categories, fetch, order_with_intel
    from .memos import MemoStore

    emit = emit or print
    sleep = sleep or time.sleep

    interval, why = resolve_interval(interval_s)
    store = MemoStore(memo_path(memos_path))
    stopper = _Stopper()
    summary: dict[str, Any] = {"cycles": 0, "scans_ran": 0, "scans_failed": 0,
                               "exploits_found": 0, "interval_s": interval, "interval_reason": why}

    n = 0
    while not stopper.stop and (cycles == 0 or n < cycles):
        n += 1
        started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        line: dict[str, Any] = {"cycle": n, "started_at": started}
        try:
            # Intel is refetched per cycle, not once at startup: an advisory published an hour ago
            # should reach the next cycle, and a BASANOS that was down at boot must not disable
            # intel for the life of the watcher.
            snap = fetch(intel_url)
            cats = catalog_categories()
            report = run_scan(fork_url, realm=realm, address_book_path=address_book_path,
                              signing_key_path=signing_key_path, memos=store,
                              order=lambda c: order_with_intel(c, memos=store, snapshot=snap,
                                                               categories=cats))
            # A report with no chain_id means the fork never happened. That is the absence of a
            # scan, and it must not be counted or displayed as a clean one.
            if report.chain_id is None:
                summary["scans_failed"] += 1
                line.update(ok=False, reason=report.note or "could not fork")
            else:
                summary["scans_ran"] += 1
                real = sum(1 for f in report.findings
                           if f.outcome == "finding" and "[BY DESIGN" not in f.detail)
                summary["exploits_found"] += real
                line.update(ok=True, chain_id=report.chain_id, ran=report.ran,
                            held=report.held, exploited=report.exploited,
                            inconclusive=report.inconclusive, real_exploits=real,
                            order=report.attack_order, intel=snap.describe(),
                            gaps=snap.gaps(set(cats.values())))
        except Exception as exc:                                    # noqa: BLE001
            # Deliberately broad: ANY exception must cost one cycle, never the watcher. A watcher
            # that exits on an unexpected error is indistinguishable from one reporting all-clear.
            summary["scans_failed"] += 1
            line.update(ok=False, reason=f"{type(exc).__name__}: {str(exc)[:200]}")

        summary["cycles"] = n
        emit(json.dumps(line, ensure_ascii=False))

        last_cycle = cycles and n >= cycles
        if stopper.stop or last_cycle:
            break
        # Sleep in slices so a SIGTERM during a one-hour gap is honoured in seconds, not an hour.
        waited = 0
        while waited < interval and not stopper.stop:
            step = min(1, interval - waited)
            sleep(step)
            waited += step

    summary["stopped_by_signal"] = stopper.stop
    summary["memos"] = store.summary()
    return summary


def main(argv: list[str] | None = None) -> int:
    """Console entry so a systemd unit can call `python -m dolos.watch` directly."""
    import argparse

    p = argparse.ArgumentParser(prog="dolos-watch", description="Periodic DOLOS contract scan")
    p.add_argument("--fork-url", default=os.getenv("DOLOS_FORK_URL", "http://127.0.0.1:8545"))
    p.add_argument("--interval", type=int, default=None, help="seconds between cycles")
    p.add_argument("--cycles", type=int, default=0, help="0 = run until stopped")
    p.add_argument("--realm", default=os.getenv("DOLOS_REALM", "uni"))
    p.add_argument("--address-book", default=os.getenv("DOLOS_ADDRESS_BOOK"))
    p.add_argument("--key", default=os.getenv("DOLOS_SIGNING_KEY_PATH"))
    p.add_argument("--memos", default=None)
    a = p.parse_args(argv)
    out = run_watch(fork_url=a.fork_url, interval_s=a.interval, cycles=a.cycles, realm=a.realm,
                    address_book_path=a.address_book, signing_key_path=a.key, memos_path=a.memos)
    print(json.dumps(out, indent=1, ensure_ascii=False), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
