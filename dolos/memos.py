"""Attack memos — what DOLOS learned from its own past scans, and the one thing it may do with it.

A periodic scanner has a budget problem: every cycle it forks a chain and runs the whole catalog,
and most attacks come back `held` every single time. Memos let it spend the expensive part of a
cycle where the yield has actually been — the same idea as BASANOS's detector memory, applied to
attacks instead of detectors.

WHAT A MEMO MAY DO
------------------
Reorder the catalog. That is the entire list.

WHAT A MEMO MAY NOT DO — and why each one matters
--------------------------------------------------
- **Add an attack.** The catalog is CLOSED. An attack is a hand-written invariant plus a concrete
  transaction sequence; memory cannot invent either, and a scanner that could grow its own attack
  surface from its own history is a scanner nobody can audit.
- **Change a verdict.** `held` / `exploited` / `inconclusive` come from what the fork actually did.
  History has no vote. If memory could tip a verdict, the honest negative — the whole reason DOLOS
  sits next to BASANOS — would stop being honest.
- **Skip an attack.** Ordering is not filtering. Every attack in the catalog still runs every
  cycle; low-ranked ones simply run later. An attack that stopped running would silently become an
  untested invariant, reported as if it had been checked.
- **Flip `by_design`.** That tag is policy about the bubble, not an observation.

THE TRAP THIS ENCODES
---------------------
The UNI stablecoin's open mint is `exploited=True` on *every* run — it is the bubble's intended
faucet (`by_design`). Ranking on raw exploit count would therefore pin the faucet at the top of the
catalogue for ever and push the attacks that might find something real to the back. So yield counts
**non-by-design** findings only: a by-design hit is worth exactly as much as a `held`.
"""

from __future__ import annotations

import json
import math
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

#: Beyond this the journal is trimmed oldest-first. A memo is a few hundred bytes and a periodic
#: scanner writes one per attack per cycle, so this is roughly a year of hourly scans.
MAX_MEMOS = 20_000

#: How hard to favour attacks we have barely tried. Higher = more exploration.
DEFAULT_ALPHA = 1.4


def _now_z() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class AttackMemo:
    """One attack's outcome in one cycle. Data, not a conclusion."""

    probe: str                  # the attack id — the stable identity we learn about
    target_contract: str
    outcome: str                # "finding" | "no_finding" | "inconclusive"
    by_design: bool             # an intended bubble affordance, not a defect
    chain_id: int | None = None
    sandbox: bool = True
    ts: str = ""

    @property
    def productive(self) -> bool:
        """A real, non-by-design exploit. The only outcome that earns an attack a higher rank."""
        return self.outcome == "finding" and not self.by_design


@dataclass
class ProbeStats:
    probe: str
    runs: int = 0
    productive: int = 0
    held: int = 0
    inconclusive: int = 0
    by_design: int = 0
    last_seen: str = ""

    @property
    def yield_rate(self) -> float:
        return (self.productive / self.runs) if self.runs else 0.0


class MemoStore:
    """An append-only journal of attack outcomes, and the ordering it supports.

    Deliberately dependency-free and file-backed: a periodic scanner must not gain a database to
    remember things, and a store that cannot be read is worse than no store at all — a corrupt or
    unreadable journal degrades to "no memory", never to a crash.
    """

    def __init__(self, path: str, *, alpha: float = DEFAULT_ALPHA) -> None:
        self.path = Path(path)
        self.alpha = alpha
        self.memos: list[AttackMemo] = []
        self._load()

    # -- persistence -----------------------------------------------------------------

    def _load(self) -> None:
        if not self.path.is_file():
            return
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
                self.memos.append(AttackMemo(
                    probe=str(doc["probe"]), target_contract=str(doc.get("target_contract", "")),
                    outcome=str(doc.get("outcome", "inconclusive")),
                    by_design=bool(doc.get("by_design", False)),
                    chain_id=doc.get("chain_id"), sandbox=bool(doc.get("sandbox", True)),
                    ts=str(doc.get("ts", "")),
                ))
            except (ValueError, KeyError, TypeError):
                continue        # one bad line must not cost us the whole memory

    def record(self, memo: AttackMemo) -> None:
        if not memo.ts:
            memo.ts = _now_z()
        self.memos.append(memo)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(memo), ensure_ascii=False) + "\n")
        except OSError:
            pass                # learning is best-effort; a scan never fails because of it
        if len(self.memos) > MAX_MEMOS:
            self._trim()

    def _trim(self) -> None:
        keep = self.memos[-MAX_MEMOS:]
        self.memos = keep
        try:
            self.path.write_text(
                "".join(json.dumps(asdict(m), ensure_ascii=False) + "\n" for m in keep),
                encoding="utf-8")
        except OSError:
            pass

    # -- what it learned -------------------------------------------------------------

    def stats(self) -> dict[str, ProbeStats]:
        out: dict[str, ProbeStats] = {}
        for m in self.memos:
            st = out.setdefault(m.probe, ProbeStats(probe=m.probe))
            st.runs += 1
            st.last_seen = m.ts or st.last_seen
            if m.outcome == "inconclusive":
                st.inconclusive += 1
            elif m.productive:
                st.productive += 1
            elif m.outcome == "finding":
                st.by_design += 1
            else:
                st.held += 1
        return out

    def score(self, probe: str, *, total_runs: int) -> float:
        """UCB1 over the productive rate. An attack never run scores +inf, so a new catalog entry
        is always tried before anything with a history."""
        st = self.stats().get(probe)
        if st is None or st.runs == 0:
            return math.inf
        bonus = self.alpha * math.sqrt(math.log(max(total_runs, 2)) / st.runs)
        # An attack that keeps failing to RUN is worth retrying too — an inconclusive is the absence
        # of a test, so it should not sink to the bottom the way a genuine `held` does.
        stall = 0.25 * (st.inconclusive / st.runs)
        return st.yield_rate + stall + bonus

    def order(self, catalog: list[tuple[str, Any]]) -> list[tuple[str, Any]]:
        """Reorder — never filter. Every entry in, every entry out, highest score first.

        Ties keep catalog order so the sequence is deterministic for a given memory, which matters:
        a periodic scanner whose order jittered per cycle would be impossible to reason about.
        """
        total = len(self.memos)
        indexed = list(enumerate(catalog))
        ranked = sorted(indexed, key=lambda p: (-self.score(p[1][0], total_runs=total), p[0]))
        ordered = [entry for _, entry in ranked]
        assert len(ordered) == len(catalog), "ordering must never drop an attack"
        return ordered

    def distill_lessons(self, *, min_runs: int = 3) -> list[dict[str, Any]]:
        """Compact counts, not prose. What an operator (or the monitor card) can read at a glance."""
        lessons = []
        for st in sorted(self.stats().values(), key=lambda s: -s.runs):
            if st.runs < min_runs:
                continue
            if st.productive:
                verdict = f"found a real exploit {st.productive}/{st.runs} runs"
            elif st.by_design and not st.held:
                verdict = f"by-design affordance every run ({st.by_design}) — advisory, never a defect"
            elif st.inconclusive >= st.runs / 2:
                verdict = f"could not run {st.inconclusive}/{st.runs} — check the address book, not the contract"
            else:
                verdict = f"held {st.held}/{st.runs} runs"
            lessons.append({"probe": st.probe, "runs": st.runs, "verdict": verdict,
                            "yield_rate": round(st.yield_rate, 4), "last_seen": st.last_seen})
        return lessons

    def summary(self) -> dict[str, Any]:
        st = self.stats()
        return {
            "memos": len(self.memos),
            "probes_known": len(st),
            "productive_probes": sum(1 for s in st.values() if s.productive),
            # Falls as the store grows: how much a cycle is still spent exploring rather than
            # exploiting what it already knows.
            "exploration": round(math.sqrt(1.0 / (1.0 + len(self.memos))), 4),
            "lessons": self.distill_lessons(),
        }
