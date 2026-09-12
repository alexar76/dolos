"""Findings: the signed document must verify, and the dedup key must be stable across rescans."""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from dolos.findings import Evidence, Finding, FindingSigner, Outcome, Severity


def _has_crypto() -> bool:
    try:
        import cryptography.hazmat.primitives.asymmetric.ed25519  # noqa: F401
        return True
    except Exception:
        return False


def _finding(status_code: int = 561, probe: str = "unauthorized_token_mint") -> Finding:
    return Finding(
        target="FakeUSDT@0x4268ed", target_kind="evm-contract", probe=probe,
        category="supply", severity=Severity.HIGH.value, outcome=Outcome.FINDING.value,
        title="mint() is open", detail="anyone can mint",
        evidence=Evidence("sha256-a", "sha256-b", status_code=status_code,
                          reproducer="cast send ... mint(...)"),
    )


def test_dedup_key_is_stable_across_rediscovery():
    """The same bug found twice must produce the same dedup key, or it is payable twice — the
    exact defect momus's audit warned about. The key must NOT depend on any per-run value."""
    a, b = _finding().compute_dedup_key(), _finding().compute_dedup_key()
    assert a == b and a.startswith("dedup-")


def test_dedup_key_differs_for_a_different_bug():
    assert _finding(probe="lottery_operator_bypass").compute_dedup_key() != _finding().compute_dedup_key()


def test_dedup_excludes_response_so_a_fresh_body_does_not_change_it():
    f1 = _finding()
    f2 = _finding()
    f2.evidence.response_snippet = "a totally different response body with a nonce"
    assert f1.compute_dedup_key() == f2.compute_dedup_key()


def test_canonical_drops_only_the_signature_block():
    f = _finding()
    canon = f.canonical()
    assert "signature" not in canon
    assert canon["target"] == f.target and canon["evidence"]["status_code"] == 561


@pytest.mark.skipif(not _has_crypto(), reason="no signer backend")
def test_signature_verifies_over_the_canonical_form():
    with tempfile.TemporaryDirectory() as d:
        signer = FindingSigner(os.path.join(d, "scanner_key"))
        assert signer.signed
        f = signer.sign_finding(_finding())
        # scanner_pubkey and dedup_key are stamped INTO the signed body
        assert f.scanner_pubkey == signer.pubkey and f.dedup_key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(f.signature["public_key"]))
        canon = json.dumps(f.canonical(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        pub.verify(base64.b64decode(f.signature["value"]), canon.encode())  # raises on failure


def test_tampering_breaks_the_signature():
    if not _has_crypto():
        pytest.skip("no crypto backend")
    with tempfile.TemporaryDirectory() as d:
        signer = FindingSigner(os.path.join(d, "scanner_key"))
        f = signer.sign_finding(_finding())
        f.title = "TAMPERED"
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(f.signature["public_key"]))
        canon = json.dumps(f.canonical(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with pytest.raises(InvalidSignature):
            pub.verify(base64.b64decode(f.signature["value"]), canon.encode())


# ------------------------------------------------------------------------------------------
# Signer-backend compatibility.
#
# DOLOS signs with the ecosystem's oracle-core Signer when it is installed and with a local
# cryptography-backed stand-in when it is not. The two MUST take the same argument: oracle-core's
# `sign_payload` takes the already-canonical STRING. Handing it a dict raised
# `AttributeError: 'dict' object has no attribute 'encode'` — i.e. signing broke in exactly the
# deployment the pipeline runs, and only worked on a laptop without oracle-core.
# ------------------------------------------------------------------------------------------


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _has_oracle_core() -> bool:
    try:
        from oracle_core.signing import Signer  # noqa: F401
        return True
    except Exception:
        return False


class _RecordingSigner:
    """Stands in for either backend and records exactly what it was handed."""

    public_key_b64 = "cHVia2V5"

    def __init__(self):
        self.seen = None

    def sign_payload(self, canonical):
        self.seen = canonical
        return {"algorithm": "ed25519", "public_key": self.public_key_b64, "value": "c2ln"}


def test_the_signer_is_handed_the_canonical_string_not_a_dict():
    """The regression guard. Both backends take a string; only one of them would have crashed."""

    signer = FindingSigner.__new__(FindingSigner)
    recorder = _RecordingSigner()
    signer._signer = recorder
    f = signer.sign_finding(_finding())
    assert isinstance(recorder.seen, str)
    assert recorder.seen == _canon(f.canonical())


@pytest.mark.skipif(not _has_oracle_core(), reason="oracle-core not installed")
def test_the_ecosystem_signer_backend_produces_a_verifiable_signature(tmp_path):
    """With oracle-core installed, a DOLOS finding must sign and verify — the deployment that
    used to raise. Verified through oracle-core's OWN verifier, over the canonical string."""
    from oracle_core.signing import Signer

    signer = FindingSigner(str(tmp_path / "scanner_key"))
    f = signer.sign_finding(_finding())
    assert Signer.verify(_canon(f.canonical()), f.signature["value"], f.signature["public_key"])


@pytest.mark.skipif(not _has_crypto(), reason="no signer backend")
def test_the_local_backend_signs_the_same_bytes_as_momus(tmp_path):
    """MOMUS canonicalizes then signs. Byte-compatibility is the whole reason a DOLOS finding
    drops into the MOMUS store — so the local backend must sign the identical string."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from dolos.findings import _LocalEd25519Signer

    local = _LocalEd25519Signer(str(tmp_path / "k"))
    canonical = _canon({"b": 2, "a": 1})
    sig = local.sign_payload(canonical)
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(sig["public_key"]))
    pub.verify(base64.b64decode(sig["value"]), canonical.encode())     # raises on failure


@pytest.mark.skipif(not _has_crypto(), reason="no signer backend")
def test_the_local_backend_persists_and_reuses_its_seed(tmp_path):
    """A scanner key that changed per run would give every rescan a new identity."""
    from dolos.findings import _LocalEd25519Signer

    path = str(tmp_path / "scanner_key")
    first = _LocalEd25519Signer(path).public_key_b64
    assert os.path.getsize(path) == 32
    assert _LocalEd25519Signer(path).public_key_b64 == first


def test_the_local_backend_is_used_when_oracle_core_is_unavailable(tmp_path, monkeypatch):
    from dolos.findings import _load_signer, _LocalEd25519Signer

    monkeypatch.setitem(sys.modules, "oracle_core.signing", None)
    assert isinstance(_load_signer(str(tmp_path / "k")), _LocalEd25519Signer)


# ------------------------------------------------------------------------------------------
# Document shape — the vocabulary MOMUS's store, verifier and Treasury read.
# ------------------------------------------------------------------------------------------


def test_the_outcome_vocabulary_matches_the_momus_pipeline():
    assert [o.value for o in Outcome] == ["finding", "no_finding", "inconclusive"]


def test_the_severity_ladder_is_the_shared_one():
    assert [s.value for s in Severity] == ["info", "low", "medium", "high", "critical"]


def test_a_finding_starts_raw_and_unsigned():
    f = _finding()
    assert f.status == "raw" and f.signature == {} and f.scanner_pubkey == ""


def test_finding_ids_are_prefixed_so_a_chain_finding_is_recognisable():
    """`dol-` vs momus's own prefix: a reader can tell an on-chain finding from an HTTP one."""
    assert _finding().finding_id.startswith("dol-")
    assert _finding().finding_id != _finding().finding_id


@pytest.mark.skipif(not _has_crypto(), reason="no signer backend")
def test_the_digest_covers_the_signature_so_a_verdict_cannot_be_transplanted(tmp_path):
    """A Verdict binds to `finding.digest()`. If the digest ignored the signature, a verdict for
    one scanner's finding would validate against another scanner's copy of the same claim."""
    signer = FindingSigner(str(tmp_path / "k"))
    signed = signer.sign_finding(_finding())
    unsigned = _finding()
    unsigned.finding_id = signed.finding_id
    unsigned.created_at = signed.created_at
    unsigned.dedup_key = signed.dedup_key
    assert signed.digest() != unsigned.digest()


def test_dedup_key_ignores_the_finding_id_so_a_rescan_is_not_payable_twice():
    a, b = _finding(), _finding()
    assert a.finding_id != b.finding_id and a.compute_dedup_key() == b.compute_dedup_key()


def test_signing_does_not_overwrite_an_existing_dedup_key(tmp_path):
    if not _has_crypto():
        pytest.skip("no crypto backend")
    f = _finding()
    f.dedup_key = "dedup-preserved"
    assert FindingSigner(str(tmp_path / "k")).sign_finding(f).dedup_key == "dedup-preserved"
