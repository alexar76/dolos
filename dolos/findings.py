"""Signed findings — byte-compatible with the MOMUS pipeline.

A DOLOS finding is the SAME document a MOMUS probe emits (momus/momus/findings.py): the AWR-shaped
triad Finding / Verdict / Blame, Ed25519-signed over a canonical, compact, sorted JSON form. We
mirror the shape field-for-field rather than importing momus, so DOLOS stays a standalone satellite
that depends only on the ecosystem's signing primitive — but a finding it emits drops straight into
the MOMUS store, verifier and Treasury because the canonical bytes are identical.

The security property is the same one MOMUS enforces: the finding is signed by the SCANNER key; a
verdict is signed by a DIFFERENT verifier key; neither is the treasury key that releases a bounty.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Outcome(str, Enum):
    FINDING = "finding"
    NO_FINDING = "no_finding"
    INCONCLUSIVE = "inconclusive"


class Status(str, Enum):
    RAW = "raw"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    DISPUTED = "disputed"


def _now_z() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _canon_str(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(obj: Any) -> str:
    return "sha256-" + hashlib.sha256(_canon_str(obj).encode()).hexdigest()


@dataclass
class Evidence:
    request_digest: str
    response_digest: str
    request_snippet: str = ""
    response_snippet: str = ""
    status_code: int | None = None
    reproducer: str = ""
    reference_artifacts: tuple[str, ...] = ()


@dataclass
class Finding:
    """A signed claim by the DOLOS scanner. Same shape as momus Finding; only the id prefix
    differs so a reader can tell an on-chain finding from an HTTP one at a glance."""

    target: str            # the contract, e.g. "AIAgentLottery@0x7635…"
    target_kind: str       # "evm-contract"
    probe: str             # attack id, e.g. "lottery_operator_bypass"
    category: str
    severity: str
    outcome: str
    title: str
    detail: str
    evidence: Evidence
    finding_id: str = field(default_factory=lambda: f"dol-{uuid.uuid4().hex[:16]}")
    dedup_key: str = ""
    created_at: str = field(default_factory=_now_z)
    status: str = Status.RAW.value
    scanner_pubkey: str = ""
    signature: dict[str, Any] = field(default_factory=dict)

    def canonical(self) -> dict[str, Any]:
        body = asdict(self)
        body.pop("signature", None)
        return body

    def compute_dedup_key(self) -> str:
        basis = {
            "target": self.target,
            "probe": self.probe,
            "category": self.category,
            "status_code": self.evidence.status_code,
        }
        return "dedup-" + hashlib.sha256(_canon_str(basis).encode()).hexdigest()[:24]

    def digest(self) -> str:
        """SRI digest over the SIGNED document (signature included) — a Verdict binds to this."""
        return _digest(asdict(self))


def _load_signer(key_path: str):
    """The ecosystem's Ed25519 Signer if oracle-core is importable; else a cryptography-backed
    stand-in with the SAME public API (public_key_b64, sign_payload). Signing never silently
    no-ops: if neither is available the caller gets an unsigned finding and is told."""
    try:
        from oracle_core.signing import Signer  # type: ignore
        return Signer(key_path)
    except Exception:  # noqa: BLE001 - fall through to the local signer
        return _LocalEd25519Signer(key_path)


class _LocalEd25519Signer:
    """Minimal Ed25519 signer matching oracle_core.signing.Signer's surface, so DOLOS can sign
    where oracle-core is not installed. Seed is read from / written to `key_path` (32 raw bytes)."""

    def __init__(self, key_path: str):
        import base64
        import os

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self._b64 = base64
        if key_path and os.path.exists(key_path):
            seed = open(key_path, "rb").read()[:32]
            self._sk = Ed25519PrivateKey.from_private_bytes(seed)
        else:
            self._sk = Ed25519PrivateKey.generate()
            if key_path:
                os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)
                from cryptography.hazmat.primitives import serialization
                raw = self._sk.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption())
                with open(key_path, "wb") as fh:
                    fh.write(raw)

    @property
    def public_key_b64(self) -> str:
        from cryptography.hazmat.primitives import serialization
        raw = self._sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        return self._b64.b64encode(raw).decode()

    def sign_payload(self, canonical: str) -> dict[str, Any]:
        """Sign the CANONICAL STRING, exactly like `oracle_core.signing.Signer.sign_payload`.

        The surface has to match byte-for-byte, not just in spirit: `FindingSigner` cannot know
        which of the two backends it got, and oracle-core's signer takes the already-canonical
        string. Taking a dict here worked only while oracle-core was absent — with it installed,
        signing raised `AttributeError: 'dict' object has no attribute 'encode'`, i.e. it broke
        in exactly the deployment the pipeline runs."""
        sig = self._sk.sign(canonical.encode())
        return {"algorithm": "ed25519", "public_key": self.public_key_b64,
                "value": self._b64.b64encode(sig).decode()}


class FindingSigner:
    """Signs findings with a role key. Mirrors momus.findings.FindingSigner: it STAMPS dedup_key
    and scanner_pubkey INTO the finding before signing, so both are inside the signed bytes."""

    def __init__(self, key_path: str):
        self._signer = _load_signer(key_path)

    @property
    def pubkey(self) -> str:
        return self._signer.public_key_b64

    @property
    def signed(self) -> bool:
        return bool(self.pubkey)

    def sign_finding(self, f: Finding) -> Finding:
        if not f.dedup_key:
            f.dedup_key = f.compute_dedup_key()
        f.scanner_pubkey = self.pubkey
        # Canonicalize HERE, like momus.findings.FindingSigner does, so the signed bytes are the
        # ones a MOMUS verifier recomputes — and so both signer backends get the same argument.
        f.signature = self._signer.sign_payload(_canon_str(f.canonical()))
        return f
