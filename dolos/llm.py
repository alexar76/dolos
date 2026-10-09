"""An optional LLM for DOLOS — and a hard boundary around what it is allowed to touch.

DOLOS's verdicts come from what a fork actually did: a revert, a drained balance, a receipt status.
That is the whole reason it is worth having next to BASANOS — a static scanner *flags*, DOLOS
*proves*. A model cannot make a revert more or less true, so a model gets no say in a verdict.

THE TWO ROLES IT DOES GET
-------------------------
1. **EXPLAIN** — turn a finished finding into prose an operator can read. Runs strictly AFTER a
   verdict exists, takes the verdict as input, and cannot change it.
2. **PROPOSE** — read a contract's source and suggest *candidate* attacks: an invariant the
   contract seems to claim, plus a transaction sequence that would break it. Proposals land in an
   inert queue for a human to read. They are NOT registered, NOT executed, and NOT counted.

WHY PROPOSALS ARE INERT
-----------------------
The attack catalog is CLOSED, for the same reason the memo store may only reorder it: a scanner
that grows its own attack surface from its own suggestions is a scanner nobody can audit. Worse,
an auto-registered attack would arrive with no reviewed reproducer, and its first `exploited=True`
would be indistinguishable from a real one. So a proposal is a *note to a human* — turning one into
an attack means somebody writes the code, reads the sequence, and commits it.

STRUCTURALLY UNREACHABLE FROM THE VERDICT PATH
----------------------------------------------
`attacks.py`, `harness.py`, `forkchain.py`, `findings.py` and `fixloop.py` do not import this
module and must never start: `tests/test_llm.py` asserts it. A module that cannot be imported
cannot influence an outcome, which turns "the LLM does not decide verdicts" from a promise into a
property. That is also why `explain` is an operator-invoked CLI step rather than something the scan
calls — keeping the network out of a cycle that has to keep working when things are broken.

The default provider is `offline`: deterministic, no network, no key. The whole suite runs with no
model reachable, the same way MOMUS and GAIA ship deterministic stand-ins.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

#: Provider presets. `deepseek`/`openai`/`ollama`/`lmstudio` share one wire format (OpenAI
#: chat-completions) and differ only in defaults — they are named presets because an operator picks
#: them by name, not because the code forks.
PRESETS: dict[str, dict[str, str]] = {
    "offline":   {"base_url": "", "model": "deterministic", "wire": "offline"},
    "anthropic": {"base_url": "https://api.anthropic.com", "model": "claude-sonnet-5", "wire": "anthropic"},
    "openai":    {"base_url": "https://api.openai.com/v1", "model": "gpt-4o-mini", "wire": "openai"},
    "deepseek":  {"base_url": "https://api.deepseek.com/v1", "model": "deepseek-v4-pro", "wire": "openai"},
    # The intended production setting for DOLOS. base_url and model are the ecosystem's existing
    # constants (llm/persist_openrouter.py:29-31) rather than fresh ones — the factory already
    # runs MiniMax M3 through OpenRouter, and a satellite inventing its own model id would drift.
    "openrouter": {"base_url": "https://openrouter.ai/api/v1", "model": "minimax/minimax-m3", "wire": "openai"},
    "ollama":    {"base_url": "http://host.docker.internal:11434/v1", "model": "qwen2.5-coder", "wire": "openai"},
    "lmstudio":  {"base_url": "http://host.docker.internal:1234/v1", "model": "local-model", "wire": "openai"},
}

#: A proposal is never bigger than this; a model that returns an essay is returning noise.
MAX_PROPOSALS = 8

#: Default output budget. Deliberately generous: `deepseek-v4-pro` and `minimax/minimax-m3` are
#: REASONING models — they spend this budget on `reasoning_content` BEFORE emitting any `content`.
#: At 1200 a live propose call came back HTTP 200 with an empty message and degraded silently to
#: the offline stand-in, which looked exactly like "the provider is down".
DEFAULT_MAX_TOKENS = 6000


@dataclass
class LLMConfig:
    provider: str = "offline"
    model: str = "deterministic"
    base_url: str = ""
    api_key: str = ""
    wire: str = "offline"
    temperature: float = 0.2
    max_tokens: int = DEFAULT_MAX_TOKENS
    timeout_s: float = 60.0

    @property
    def enabled(self) -> bool:
        """`offline` is not 'disabled' — it is a deterministic provider. But it never opens a socket."""
        return self.wire != "offline"

    @classmethod
    def from_env(cls) -> "LLMConfig":
        """Build from DOLOS_LLM_* — the same names MOMUS uses, so an operator learns one scheme.

        Defaults to `offline` on purpose: an unset provider must mean "no network", not "guess".
        """
        raw = (os.environ.get("DOLOS_LLM_PROVIDER") or "offline").strip().lower()
        preset = PRESETS.get(raw)
        if preset is None:
            # An unknown provider degrades to offline rather than raising. A typo'd provider that
            # crashed the CLI would take the deterministic path down with it.
            raw, preset = "offline", PRESETS["offline"]
        # DOLOS_LLM_API_KEY wins; otherwise fall back to the provider's own conventional variable
        # so an operator who already exported OPENROUTER_API_KEY for the factory does not have to
        # duplicate it. A file is read last, for a secrets mount that is not in the environment
        # (the factory keeps this one at secrets/llm/openrouter_api_key).
        key = (os.environ.get("DOLOS_LLM_API_KEY") or "").strip()
        if not key:
            key = (os.environ.get({
                "openrouter": "OPENROUTER_API_KEY",
                "deepseek": "DEEPSEEK_API_KEY",
                "anthropic": "ANTHROPIC_API_KEY",
                "openai": "OPENAI_API_KEY",
            }.get(raw, "")) or "").strip()
        if not key:
            key = _key_from_file(os.environ.get("DOLOS_LLM_API_KEY_FILE"))
        if not key:
            # Last: the ecosystem's canonical secrets mount. On the factory host the key already
            # lives here (llm/persist_openrouter.py keeps it at secrets/llm/<provider>_api_key), so
            # a container that mounts the secrets dir but does not inject the env var still works
            # with NO configuration. This is why the key never needs copying anywhere.
            key = _key_from_file(_conventional_secret_path(raw))
        return cls(
            provider=raw,
            model=(os.environ.get("DOLOS_LLM_MODEL") or "").strip() or preset["model"],
            base_url=(os.environ.get("DOLOS_LLM_BASE_URL") or "").strip() or preset["base_url"],
            api_key=key,
            wire=preset["wire"],
            temperature=_float_env("DOLOS_LLM_TEMPERATURE", 0.2),
            max_tokens=_int_env("DOLOS_LLM_MAX_TOKENS", DEFAULT_MAX_TOKENS),
            timeout_s=_float_env("DOLOS_LLM_TIMEOUT_S", 60.0),
        )

    def describe(self) -> dict[str, Any]:
        return {"provider": self.provider, "model": self.model, "network": self.enabled,
                "has_key": bool(self.api_key),
                # Stated in the payload on purpose: it is the boundary, where an operator can see it.
                "decides_verdicts": False, "registers_attacks": False}


#: Where the factory keeps provider keys, relative to AIFACTORY_DATA_ROOT.
SECRET_REL = "secrets/llm/{provider}_api_key"


def _conventional_secret_path(provider: str) -> str:
    """The ecosystem's own secrets location for this provider, or "" for offline.

    Read, never written: DOLOS consumes a key the factory already manages. Hardcoding a key into
    the tree is how one leaked before — the mirror publish ignored .gitignore and shipped it.
    """
    if provider == "offline":
        return ""
    root = os.environ.get("AIFACTORY_DATA_ROOT", "/app/data")
    return str(Path(root) / SECRET_REL.format(provider=provider))


def _key_from_file(path: str | None) -> str:
    """A key from a secrets mount. Unreadable or absent yields "" — a missing key must degrade to
    the offline path, never raise inside config resolution."""
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _float_env(name: str, default: float) -> float:
    try:
        return float((os.environ.get(name) or "").strip())
    except ValueError:
        return default


def _int_env(name: str, default: int) -> int:
    try:
        return int((os.environ.get(name) or "").strip())
    except ValueError:
        return default


@dataclass
class AttackProposal:
    """A candidate attack: a note to a human, not an attack.

    `status` is always "proposed". Nothing in this package ever writes another value — becoming an
    attack means a person writes the code and commits it.
    """

    invariant: str                      # the property the contract appears to claim
    sequence: list[str]                 # the transaction sequence that would break it
    target_hint: str = ""               # contract / function the proposal is about
    rationale: str = ""
    provider: str = "offline"
    proposal_id: str = ""
    created_at: str = ""
    status: str = "proposed"
    #: Set when this came from the offline stand-in because the model produced nothing usable.
    #: Names the reason, so a truncated reasoning model is not mistaken for an outage.
    degraded: str = ""

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if not self.proposal_id:
            basis = f"{self.invariant}|{self.target_hint}|{'|'.join(self.sequence)}"
            self.proposal_id = "prop-" + hashlib.sha256(basis.encode()).hexdigest()[:16]


class ProposalQueue:
    """An append-only file of candidate attacks. Deliberately not a registry.

    Dedup is by `proposal_id` (a digest of invariant + target + sequence), so re-running `propose`
    over the same source does not bury the queue in copies of the same idea.
    """

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.seen: set[str] = set()
        if self.path.is_file():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                try:
                    self.seen.add(str(json.loads(line)["proposal_id"]))
                except (ValueError, KeyError, TypeError):
                    continue

    def add(self, proposals: list[AttackProposal]) -> list[AttackProposal]:
        fresh = [p for p in proposals if p.proposal_id not in self.seen]
        if not fresh:
            return []
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                for p in fresh:
                    fh.write(json.dumps(asdict(p), ensure_ascii=False) + "\n")
        except OSError:
            pass            # a queue that cannot be written must not fail the command
        self.seen.update(p.proposal_id for p in fresh)
        return fresh


# ─────────────────────────────────────────────────────────────────── the wire


def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str],
               timeout_s: float) -> dict[str, Any]:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"content-type": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        return json.loads(resp.read())


def _complete(cfg: LLMConfig, system: str, user: str) -> tuple[str, str]:
    """One completion as `(text, degraded_reason)`. Never raises — an unreachable model degrades
    the ADVISORY layer and must not take a command down with it.

    The reason matters. "the provider is unreachable" and "the provider answered, but spent the
    whole token budget thinking" both yield empty text, and they need different fixes: one is an
    outage, the other is `DOLOS_LLM_MAX_TOKENS` set too low. Reporting both as a silent fallback
    sent me chasing a network problem that did not exist.
    """
    if not cfg.enabled:
        return "", ""
    try:
        if cfg.wire == "anthropic":
            body = _post_json(
                f"{cfg.base_url}/v1/messages",
                {"model": cfg.model, "max_tokens": cfg.max_tokens,
                 "temperature": cfg.temperature, "system": system,
                 "messages": [{"role": "user", "content": user}]},
                {"x-api-key": cfg.api_key, "anthropic-version": "2023-06-01"}, cfg.timeout_s)
            parts = body.get("content") or []
            text = "".join(p.get("text", "") for p in parts if isinstance(p, dict))
            if not text and body.get("stop_reason") == "max_tokens":
                return "", "truncated: raise DOLOS_LLM_MAX_TOKENS"
            return text, "" if text else "provider returned no text"
        headers = {"authorization": f"Bearer {cfg.api_key}"} if cfg.api_key else {}
        if cfg.provider == "openrouter":
            # OpenRouter attributes traffic by these two; optional on the wire, but omitting them
            # makes our usage anonymous in a dashboard the operator actually reads.
            headers["http-referer"] = "https://github.com/alexar76/dolos"
            headers["x-title"] = "DOLOS"
        body = _post_json(
            f"{cfg.base_url}/chat/completions",
            {"model": cfg.model, "temperature": cfg.temperature, "max_tokens": cfg.max_tokens,
             "messages": [{"role": "system", "content": system},
                          {"role": "user", "content": user}]},
            headers, cfg.timeout_s)
        choices = body.get("choices") or []
        if not choices:
            return "", "provider returned no choices"
        choice = choices[0]
        text = str((choice.get("message") or {}).get("content", ""))
        if not text and choice.get("finish_reason") == "length":
            # A reasoning model burned the budget on `reasoning_content` and emitted nothing.
            return "", "truncated before any content: raise DOLOS_LLM_MAX_TOKENS"
        return text, "" if text else "provider returned empty content"
    except (urllib.error.HTTPError,) as exc:
        return "", f"HTTP {exc.code}"
    except (urllib.error.URLError, OSError, ValueError, KeyError, IndexError, TypeError) as exc:
        return "", f"{type(exc).__name__}"


# ─────────────────────────────────────────────────────────────────── role 1: explain


EXPLAIN_SYSTEM = (
    "You explain the result of a smart-contract red-team run to an operator. "
    "The verdict is already decided by what the chain did and is GIVEN to you — never dispute it, "
    "never soften it, never suggest it might be wrong. If the contract held, say plainly that the "
    "attack was refused and what that rules out. If it broke, say what an attacker gains. "
    "Three sentences maximum. No preamble, no markdown headings."
)


def explain_finding(finding: dict[str, Any], *, cfg: LLMConfig | None = None) -> dict[str, Any]:
    """Advisory prose for a finding that ALREADY has a verdict.

    Returns `{explanation, provider, advisory: True}`. The finding is not modified — this function
    takes a dict and returns a separate one, so there is no path by which prose reaches a verdict.
    """
    cfg = cfg or LLMConfig.from_env()
    outcome = str(finding.get("outcome", "")) or "unknown"
    detail = str(finding.get("detail", ""))[:1500]
    if not cfg.enabled:
        return {"explanation": _offline_explanation(finding), "provider": cfg.provider,
                "advisory": True}
    text, degraded = _complete(cfg, EXPLAIN_SYSTEM, json.dumps({
        "verdict": outcome, "probe": finding.get("probe"), "target": finding.get("target"),
        "title": finding.get("title"), "detail": detail,
        "reproducer": str((finding.get("evidence") or {}).get("reproducer", ""))[:600],
    }, ensure_ascii=False))
    out = {"explanation": text.strip() or _offline_explanation(finding),
           "provider": cfg.provider if text.strip() else f"{cfg.provider}→offline",
           "advisory": True}
    if not text.strip() and degraded:
        out["degraded"] = degraded
    return out


def _offline_explanation(finding: dict[str, Any]) -> str:
    """Deterministic prose from the fields themselves. Not a model — a template, and honest about it."""
    outcome = str(finding.get("outcome", ""))
    probe = finding.get("probe") or "the attack"
    target = finding.get("target") or "the contract"
    if outcome == "no_finding":
        return (f"{target} refused {probe}: the invariant held, so this is an honest negative — "
                f"it rules the flaw out rather than leaving it unknown.")
    if outcome == "finding":
        tag = " (an intended bubble affordance, advisory only)" if "[BY DESIGN" in str(
            finding.get("detail", "")) else ""
        return (f"{probe} broke {target}'s invariant{tag}. The reproducer in the evidence is the "
                f"exact transaction sequence that did it.")
    return (f"{probe} could not be run against {target}. That is the absence of a test, not a pass — "
            f"nothing was proven either way.")


# ─────────────────────────────────────────────────────────────────── role 2: propose


PROPOSE_SYSTEM = (
    "You read Solidity and propose CANDIDATE attacks for a human to review. "
    "Each candidate is (a) an invariant the contract appears to claim, and (b) a concrete "
    "transaction sequence that would break it if the guard is missing. "
    "Do not propose anything you cannot express as a sequence of calls. Do not claim a bug exists — "
    "you are proposing something to TEST. "
    'Reply with JSON only: {"proposals":[{"invariant":"…","sequence":["…"],'
    '"target_hint":"…","rationale":"…"}]}'
)


def propose_attacks(source: str, *, existing_probes: list[str] | None = None,
                    cfg: LLMConfig | None = None) -> list[AttackProposal]:
    """Candidate attacks for a human to read. Never registered, never executed, never counted.

    `existing_probes` is passed to the model so it does not re-propose what the catalog already
    covers; it is advisory context, not a filter on the result.
    """
    cfg = cfg or LLMConfig.from_env()
    if not cfg.enabled:
        return _offline_proposals(source)
    text, degraded = _complete(cfg, PROPOSE_SYSTEM, json.dumps({
        "existing_attacks": existing_probes or [],
        "source": source[:20_000],
    }, ensure_ascii=False))
    parsed = _parse_proposals(text, provider=cfg.provider)
    if parsed:
        return parsed
    fallback = _offline_proposals(source)
    for p in fallback:
        p.degraded = degraded or ("model returned no usable proposals" if text else "")
    return fallback


def _parse_proposals(text: str, *, provider: str) -> list[AttackProposal]:
    """Tolerant parse: models fence JSON, prefix it, or return one object instead of a list."""
    if not text.strip():
        return []
    blob = text.strip()
    fence = re.search(r"```(?:json)?\s*(.+?)```", blob, re.S)
    if fence:
        blob = fence.group(1).strip()
    start = blob.find("{")
    if start > 0:
        blob = blob[start:]
    try:
        doc = json.loads(blob)
    except ValueError:
        return []
    if isinstance(doc, dict):
        # Models return three shapes: {"proposals":[…]}, a bare list, or — often enough to matter —
        # ONE proposal object with no wrapper at all. The third used to parse to nothing.
        items = doc.get("proposals", doc if "invariant" in doc else None)
    else:
        items = doc
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list):
        return []
    out: list[AttackProposal] = []
    for raw in items[:MAX_PROPOSALS]:
        if not isinstance(raw, dict):
            continue
        invariant = str(raw.get("invariant", "")).strip()
        seq = raw.get("sequence") or []
        seq = [str(s).strip() for s in seq if str(s).strip()] if isinstance(seq, list) else []
        # A proposal with no sequence is an opinion, not a candidate attack — drop it.
        if not invariant or not seq:
            continue
        out.append(AttackProposal(
            invariant=invariant, sequence=seq,
            target_hint=str(raw.get("target_hint", "")).strip(),
            rationale=str(raw.get("rationale", "")).strip(), provider=provider))
    return out


#: Functions whose name suggests a privileged action. Used only by the offline stand-in.
_PRIVILEGED = ("mint", "withdraw", "burn", "setowner", "transferownership", "pause",
               "upgrade", "sweep", "rescue", "setfee", "openround", "openchannel")


def _offline_proposals(source: str) -> list[AttackProposal]:
    """A deterministic stand-in so the pipeline is exercisable with no model reachable.

    It is a FIXTURE, not an analysis: it looks for externally-callable functions with a
    privileged-sounding name and no visible modifier, and proposes the obvious authz invariant.
    Real static analysis is BASANOS's job, and this does not pretend otherwise.
    """
    out: list[AttackProposal] = []
    pattern = re.compile(
        r"function\s+(\w+)\s*\(([^)]*)\)\s*([^{;]*)", re.S)
    for match in pattern.finditer(source or ""):
        name, _args, tail = match.group(1), match.group(2), match.group(3)
        if "external" not in tail and "public" not in tail:
            continue
        if "onlyowner" in tail.lower() or "onlyrole" in tail.lower():
            continue
        if name.lower() not in _PRIVILEGED:
            continue
        out.append(AttackProposal(
            invariant=f"only an authorized caller may call {name}()",
            sequence=["impersonate a fresh no-role address",
                      f"call {name}() from it",
                      "assert the call reverts"],
            target_hint=name,
            rationale=(f"{name}() is externally callable and carries no visible access-control "
                       f"modifier in the source given."),
            provider="offline"))
        if len(out) >= MAX_PROPOSALS:
            break
    return out
