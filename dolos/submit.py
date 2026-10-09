"""Hand a confirmed DOLOS finding to the existing self-healing loop.

DOLOS runs its OWN contract fix cycle (fixloop.py) — the SKOPOS conductor's fix/deploy hands are
built for services (Python images + git deploy), not for a `forge`-redeployed contract, so DOLOS
is the contract-aware fixer. What this module does is the OTHER half of "feed the loop": it submits
a confirmed finding to the conductor's `/a2a/tasks` `remediate` skill so the finding is TRACKED,
BOUNTIED and — for a security-core component — ESCALATED to a human, exactly like a MOMUS finding.

Nothing is submitted unless configured (`DOLOS_CONDUCTOR_URL`); a finding from a non-sandbox fork,
or one tagged by-design/advisory, is never submitted for auto-remediation.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$")


def _ticket_from_finding(f: dict[str, Any]) -> dict[str, Any]:
    """Shape a conductor ticket from a DOLOS finding dict (as emitted by harness.ScanReport)."""
    fid = str(f.get("finding_id") or "")
    component = str(f.get("target") or "")
    return {
        "finding_id": fid,
        "component": component,
        "probe": str(f.get("probe") or ""),
        "category": str(f.get("category") or ""),
        "severity": str(f.get("severity") or ""),
        "target": component,
        "target_kind": str(f.get("target_kind") or "evm-contract"),
        # The conductor cross-checks blame.finding_id == ticket.finding_id and
        # blame.component == ticket.component (conductor.py:210-212), so mirror them.
        "blame": {"finding_id": fid, "component": component,
                  "severity": str(f.get("severity") or ""),
                  "summary": str(f.get("title") or "")[:200]},
        "finding": f,  # the full signed document, for the record
    }


def submittable(f: dict[str, Any]) -> tuple[bool, str]:
    """Whether a finding may be auto-submitted. Guards: it must be a real exploit (not held / not
    inconclusive), not by-design, not advisory (a non-sandbox fork), and carry a safe id."""
    if f.get("outcome") != "finding":
        return False, "not an exploit"
    detail = str(f.get("detail") or "")
    if "[BY DESIGN" in detail:
        return False, "by-design bubble affordance — advisory only"
    if "[ADVISORY" in detail:
        return False, "advisory (non-sandbox fork) — never auto-remediated"
    if not _SAFE_ID.fullmatch(str(f.get("finding_id") or "")):
        return False, "unsafe finding_id"
    return True, ""


def submit_finding(f: dict[str, Any], *, conductor_url: str | None = None,
                   peer_token: str | None = None, timeout: float = 20.0) -> dict[str, Any]:
    """POST one finding to the conductor as a `remediate` task. Returns the conductor's reply, or a
    `{submitted: False, reason}` when it is not configured or the finding is not submittable."""
    url = (conductor_url or os.getenv("DOLOS_CONDUCTOR_URL") or "").rstrip("/")
    if not url:
        return {"submitted": False, "reason": "DOLOS_CONDUCTOR_URL not set"}
    ok, why = submittable(f)
    if not ok:
        return {"submitted": False, "reason": why}
    body = json.dumps({"skill": "remediate",
                       "input": {"ticket": _ticket_from_finding(f)}}).encode()
    headers = {"content-type": "application/json"}
    token = peer_token or os.getenv("DOLOS_CONDUCTOR_PEER_TOKEN") or os.getenv("SKOPOS_A2A_TOKEN")
    if token:
        headers["x-a2a-token"] = token
    req = urllib.request.Request(f"{url}/a2a/tasks", data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            reply = json.loads(resp.read())
        return {"submitted": reply.get("state") == "working", "conductor": reply}
    except urllib.error.HTTPError as exc:
        return {"submitted": False, "reason": f"HTTP {exc.code}", "detail": exc.read()[:200].decode("utf-8", "replace")}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"submitted": False, "reason": f"{type(exc).__name__}: {str(exc)[:120]}"}


def submit_report(report: dict[str, Any], **kw: Any) -> list[dict[str, Any]]:
    """Submit every submittable finding in a ScanReport dict; returns one result per attempt."""
    out = []
    for f in report.get("findings", []):
        ok, why = submittable(f)
        if ok:
            out.append({"finding_id": f.get("finding_id"), **submit_finding(f, **kw)})
    return out
