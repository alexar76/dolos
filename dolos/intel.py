"""External threat intel for DOLOS — read from BASANOS, never fetched here.

DOLOS's own memory (memos.py) is endogenous: it learns which of ITS attacks have paid off. That
says nothing about a weakness class the world just learned about. This module is the other half —
but it is deliberately not a second feed.

WHY IT READS BASANOS INSTEAD OF FETCHING
----------------------------------------
BASANOS already ingests OSV (`@openzeppelin/contracts`, `solmate`) and GHSA behind a host
allowlist, and distills each advisory onto its CLOSED detector-category set. Standing up a second
fetcher in DOLOS would mean a second allowlist to keep correct, a second set of rate limits, and a
second place where an advisory can be mishandled — for data BASANOS has already vetted. So DOLOS
reads `GET /intel` and consumes the distilled result.

That also draws the layer boundary the right way round: BASANOS reads SOURCE and flags a class;
DOLOS attacks what is DEPLOYED and finds out whether the class is actually reachable. An advisory
against a library our contracts import is exactly the question BASANOS cannot answer.

THE INJECTION SURFACE, AND WHY IT IS ABSENT RATHER THAN GUARDED
---------------------------------------------------------------
An advisory is untrusted text written by strangers. The obvious design — feed card titles and
summaries into a ranker — would put attacker-controlled prose on the path that decides what DOLOS
does. It is not guarded here; it is structurally absent:

**Ordering reads ONLY `category_scores` — floats keyed by a closed 11-value enum — and never a
title, summary, url or identifier.** Free text cannot influence the order because the ordering code
never sees it. Card text is carried only for display to a human and for `propose`, and both are
sanitised on the way out (`safe_text`).

WHAT A CARD MAY DO
------------------
Raise an existing attack's priority, by a BOUNDED amount. That is the list.

It may not add an attack, drop one, change a verdict, or outrank a measured result by more than
`MAX_BOOST` — a flood of advisories in one category must not be able to reshuffle the whole
catalog, which is the same reason the boost is capped rather than summed.

WHAT IT REPORTS INSTEAD
-----------------------
A hot category with NO attack in the catalog is a **gap**, and gaps are the genuinely new
information here: "the world is worried about reentrancy and DOLOS has no reentrancy attack" is
precisely the input `dolos propose` exists to turn into a reviewed candidate. Gaps are reported,
never auto-filled.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

#: BASANOS's closed detector-category set. Anything outside it is ignored, so a card claiming a
#: category we do not know cannot invent one.
BASANOS_CATEGORIES = (
    "reentrancy", "access-control", "oracle", "entropy", "delegatecall", "selfdestruct",
    "tx-origin", "pragma", "unchecked-call", "secret", "dead-guard",
)

#: BASANOS category -> the DOLOS attack category it corresponds to.
#:
#: Deliberately SPARSE. Only mappings that are defensible one-to-one are here; the rest are left
#: unmapped on purpose, because an invented mapping would silently boost the wrong attack and look
#: like intel working. Unmapped hot categories surface as gaps instead — which is more useful.
CATEGORY_MAP: dict[str, str] = {
    "access-control": "authz",
    "reentrancy": "reentrancy",
    "oracle": "oracle",
}

#: The most intel can add to an attack's score. Bounded, not summed: a flood of advisories in one
#: category must not be able to outrank what DOLOS has actually MEASURED about its own attacks.
MAX_BOOST = 0.5

#: A category is "hot" above this. Below it, intel has nothing to say.
HOT = 0.15

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def safe_text(value: Any, *, limit: int = 300) -> str:
    """Advisory text, made safe to display or hand to a model.

    Strips control characters (which can forge log/prompt boundaries), collapses whitespace, and
    truncates. This is for the DISPLAY path only — the ordering path never calls it, because the
    ordering path never touches free text at all.
    """
    text = _CONTROL.sub("", str(value or ""))
    return re.sub(r"\s+", " ", text).strip()[:limit]


@dataclass
class IntelSnapshot:
    """What BASANOS currently knows, reduced to what DOLOS may act on."""

    #: category -> score, filtered to the closed enum. THE ONLY FIELD ORDERING READS.
    category_scores: dict[str, float] = field(default_factory=dict)
    cards_total: int = 0
    #: Sanitised, display-only. Never consulted when ordering.
    recent: list[dict[str, str]] = field(default_factory=list)
    available: bool = False
    reason: str = ""

    def boost(self, attack_category: str) -> float:
        """Bounded priority bump for one DOLOS attack category. 0.0 when intel says nothing."""
        best = 0.0
        for basanos_cat, dolos_cat in CATEGORY_MAP.items():
            if dolos_cat != attack_category:
                continue
            best = max(best, float(self.category_scores.get(basanos_cat, 0.0) or 0.0))
        if best < HOT:
            return 0.0
        return min(MAX_BOOST, best * MAX_BOOST)

    def gaps(self, covered_categories: set[str]) -> list[dict[str, Any]]:
        """Hot categories the catalog has no attack for. The input `dolos propose` deserves.

        Includes categories with no mapping at all: those are the clearest gaps of the lot — the
        world has a name for the weakness and DOLOS has nothing that tries it.
        """
        out = []
        for cat, score in sorted(self.category_scores.items(), key=lambda kv: -kv[1]):
            if score < HOT:
                continue
            mapped = CATEGORY_MAP.get(cat)
            if mapped and mapped in covered_categories:
                continue
            out.append({"basanos_category": cat, "score": round(float(score), 4),
                        "dolos_category": mapped or None,
                        "why": ("no attack in the catalog covers this class"
                                if mapped else "no DOLOS attack category maps to this class")})
        return out

    def describe(self) -> dict[str, Any]:
        return {"available": self.available, "reason": self.reason, "cards": self.cards_total,
                "hot": {c: round(s, 4) for c, s in self.category_scores.items() if s >= HOT},
                # Stated where an operator can see it, like the LLM's own limits.
                "reorders_only": True, "can_add_attacks": False}


def basanos_url(explicit: str | None = None) -> str:
    return (explicit or os.environ.get("DOLOS_INTEL_URL") or "").strip().rstrip("/")


def fetch(url: str | None = None, *, timeout_s: float = 10.0) -> IntelSnapshot:
    """Read BASANOS's distilled intel. Unreachable or malformed yields an EMPTY snapshot.

    Never raises and never partially applies: intel that could not be read must leave ordering
    exactly as it was, not half-applied. Unset URL means "no intel", which is the default — DOLOS
    works with no BASANOS at all.
    """
    base = basanos_url(url)
    if not base:
        return IntelSnapshot(reason="DOLOS_INTEL_URL not set — running without external intel")
    try:
        req = urllib.request.Request(f"{base}/intel", headers={"accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            body = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return IntelSnapshot(reason=f"BASANOS /intel HTTP {exc.code}")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return IntelSnapshot(reason=f"BASANOS unreachable: {type(exc).__name__}")
    if not isinstance(body, dict):
        return IntelSnapshot(reason="BASANOS /intel returned a non-object")
    return _snapshot_from(body)


def _snapshot_from(body: dict[str, Any]) -> IntelSnapshot:
    raw_scores = body.get("category_scores")
    scores: dict[str, float] = {}
    if isinstance(raw_scores, dict):
        for cat, value in raw_scores.items():
            # The closed enum is the whole validation: a card cannot introduce a category, and a
            # non-numeric score is dropped rather than coerced.
            if cat in BASANOS_CATEGORIES and isinstance(value, (int, float)) and value == value:
                scores[cat] = max(0.0, float(value))
    recent = []
    for card in (body.get("recent_cards") or [])[:8]:
        if not isinstance(card, dict):
            continue
        recent.append({
            "card_id": safe_text(card.get("card_id"), limit=64),
            "source": safe_text(card.get("source"), limit=32),
            "title": safe_text(card.get("title")),
            "url": safe_text(card.get("url"), limit=200),
            "categories": ",".join(c for c in (card.get("mapped_categories") or [])
                                   if c in BASANOS_CATEGORIES),
        })
    total = body.get("cards_total")
    return IntelSnapshot(
        category_scores=scores,
        cards_total=int(total) if isinstance(total, int) else 0,
        recent=recent,
        available=True,
        reason="intel from BASANOS" if scores else "BASANOS reachable but has no scored categories",
    )


def order_with_intel(catalog: list[tuple[str, Any]], *, memos: Any = None,
                     snapshot: IntelSnapshot | None = None,
                     categories: dict[str, str] | None = None) -> list[tuple[str, Any]]:
    """Reorder the catalog using measured memory FIRST and intel as a bounded nudge.

    `categories` maps probe name -> DOLOS attack category. Reordering never filters: every entry in,
    every entry out, exactly as `MemoStore.order` guarantees on its own.
    """
    snap = snapshot if snapshot is not None else IntelSnapshot()
    cats = categories or {}
    total = len(getattr(memos, "memos", []) or [])

    def score(name: str) -> float:
        base = memos.score(name, total_runs=total) if memos is not None else 0.0
        if base == float("inf"):
            return base                     # never-run attacks stay first; intel cannot demote them
        return base + snap.boost(cats.get(name, ""))

    ranked = sorted(enumerate(catalog), key=lambda p: (-score(p[1][0]), p[0]))
    ordered = [entry for _, entry in ranked]
    assert len(ordered) == len(catalog), "intel ordering must never drop an attack"
    return ordered


def catalog_categories() -> dict[str, str]:
    """probe -> category, read off the attack registry so it cannot drift from the catalog."""
    from .attacks import categories

    return categories()
