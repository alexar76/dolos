"""The LLM, and the boundary around it.

A model cannot make a revert more or less true, so it gets no say in a verdict and no ability to
grow the catalog. Both limits are asserted structurally — the verdict path cannot even IMPORT this
module — because a promise in a docstring is not a property.
"""

from __future__ import annotations

import ast
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from dolos.llm import (
    DEFAULT_MAX_TOKENS,
    PRESETS,
    AttackProposal,
    LLMConfig,
    ProposalQueue,
    _offline_proposals,
    _parse_proposals,
    explain_finding,
    propose_attacks,
)

DOLOS_PKG = Path(__file__).resolve().parents[1] / "dolos"

SOL = """
contract Vault {
    function deposit() external payable {}
    function withdraw(uint256 amount) external { payable(msg.sender).transfer(amount); }
    function setOwner(address who) public { owner = who; }
    function pause() external onlyOwner {}
    function _internalMint() internal {}
}
"""


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("DOLOS_LLM_PROVIDER", "DOLOS_LLM_MODEL", "DOLOS_LLM_BASE_URL", "DOLOS_LLM_API_KEY",
                "DOLOS_LLM_API_KEY_FILE", "DOLOS_LLM_TEMPERATURE", "DOLOS_LLM_MAX_TOKENS",
                "DOLOS_LLM_TIMEOUT_S", "OPENROUTER_API_KEY", "DEEPSEEK_API_KEY",
                "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(var, raising=False)


# ═══════════════════════════════════════════════ THE BOUNDARY ════════════════════════

VERDICT_PATH = ["attacks.py", "harness.py", "forkchain.py", "findings.py", "fixloop.py",
                "abis.py", "submit.py", "memos.py"]


def _imports(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            # Relative `from .llm import x` has module="llm" and level=1.
            if node.module:
                found.add(node.module)
                found.add(f"dolos.{node.module}")
    return found


@pytest.mark.parametrize("rel", VERDICT_PATH)
def test_the_verdict_path_cannot_import_the_llm(rel):
    """THE structural guarantee. A module that cannot import a model cannot be influenced by one."""
    path = DOLOS_PKG / rel
    assert path.is_file(), f"{rel} is missing — fix the list rather than letting the guard pass"
    leaked = _imports(path) & {"llm", "dolos.llm"}
    assert not leaked, f"{rel} imports the LLM — the verdict path must stay model-free"


def test_the_scan_never_reaches_the_network_through_the_llm():
    """`dolos scan` must not gain a network dependency by the back door: harness.py is on the
    verdict path AND is what the periodic watcher calls every cycle."""
    assert "llm" not in _imports(DOLOS_PKG / "harness.py")
    assert "llm" not in _imports(DOLOS_PKG / "watch.py")


def test_the_config_states_its_own_limits():
    d = LLMConfig.from_env().describe()
    assert d["decides_verdicts"] is False and d["registers_attacks"] is False


# ═══════════════════════════════════════════════ CONFIG ══════════════════════════════


def test_the_default_is_offline_with_no_network():
    cfg = LLMConfig.from_env()
    assert cfg.provider == "offline" and cfg.enabled is False and cfg.base_url == ""


def test_an_unknown_provider_degrades_to_offline(monkeypatch):
    """A typo'd provider that crashed the CLI would take the deterministic path down with it."""
    monkeypatch.setenv("DOLOS_LLM_PROVIDER", "gpt5-turbo-max")
    assert LLMConfig.from_env().provider == "offline"


def test_openrouter_uses_the_ecosystems_own_model_id(monkeypatch):
    """Not a fresh id: llm/persist_openrouter.py already pins minimax/minimax-m3, and a satellite
    inventing its own would drift from what the factory actually runs."""
    monkeypatch.setenv("DOLOS_LLM_PROVIDER", "openrouter")
    cfg = LLMConfig.from_env()
    assert cfg.model == "minimax/minimax-m3"
    assert cfg.base_url == "https://openrouter.ai/api/v1"
    assert cfg.enabled is True


def test_openrouter_picks_up_the_factorys_existing_key(monkeypatch):
    """An operator who already exported OPENROUTER_API_KEY should not have to duplicate it."""
    monkeypatch.setenv("DOLOS_LLM_PROVIDER", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-abc")
    assert LLMConfig.from_env().api_key == "sk-or-abc"


def test_an_explicit_key_beats_the_conventional_one(monkeypatch):
    monkeypatch.setenv("DOLOS_LLM_PROVIDER", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-conventional")
    monkeypatch.setenv("DOLOS_LLM_API_KEY", "sk-explicit")
    assert LLMConfig.from_env().api_key == "sk-explicit"


def test_a_key_can_come_from_a_secrets_mount(monkeypatch, tmp_path):
    secret = tmp_path / "openrouter_api_key"
    secret.write_text("sk-from-file\n", encoding="utf-8")
    monkeypatch.setenv("DOLOS_LLM_PROVIDER", "openrouter")
    monkeypatch.setenv("DOLOS_LLM_API_KEY_FILE", str(secret))
    assert LLMConfig.from_env().api_key == "sk-from-file"


def test_a_missing_secrets_file_degrades_instead_of_raising(monkeypatch, tmp_path):
    monkeypatch.setenv("DOLOS_LLM_PROVIDER", "openrouter")
    monkeypatch.setenv("DOLOS_LLM_API_KEY_FILE", str(tmp_path / "nope"))
    assert LLMConfig.from_env().api_key == ""


def test_junk_knobs_fall_back_to_defaults(monkeypatch):
    monkeypatch.setenv("DOLOS_LLM_TEMPERATURE", "warm")
    monkeypatch.setenv("DOLOS_LLM_MAX_TOKENS", "lots")
    cfg = LLMConfig.from_env()
    assert cfg.temperature == 0.2 and cfg.max_tokens == DEFAULT_MAX_TOKENS


def test_the_token_budget_suits_a_reasoning_model():
    """deepseek-v4-pro and minimax/minimax-m3 spend the budget on reasoning_content BEFORE emitting
    any content. At 1200 a live call returned HTTP 200 with an empty message and degraded silently,
    which looked exactly like an outage."""
    assert DEFAULT_MAX_TOKENS >= 4000


def test_a_truncated_reasoning_model_is_named_not_mistaken_for_an_outage(monkeypatch):
    """The two empty-text cases need different fixes: one is a network problem, the other is
    DOLOS_LLM_MAX_TOKENS set too low."""
    import io

    monkeypatch.setenv("DOLOS_LLM_PROVIDER", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-x")
    body = {"choices": [{"message": {"role": "assistant", "content": "",
                                     "reasoning_content": "thinking…"},
                         "finish_reason": "length"}]}

    class Reply:
        def __enter__(self):
            return io.BytesIO(json.dumps(body).encode())

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: Reply())
    out = explain_finding(_finding())
    assert "DOLOS_LLM_MAX_TOKENS" in out["degraded"]

    props = propose_attacks(SOL)
    assert props and "DOLOS_LLM_MAX_TOKENS" in props[0].degraded


def test_an_http_error_is_named_by_its_code(monkeypatch):
    import io

    monkeypatch.setenv("DOLOS_LLM_PROVIDER", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-bad")

    def raise_401(*a, **k):
        raise urllib.error.HTTPError("u", 401, "Unauthorized", {}, io.BytesIO(b""))

    monkeypatch.setattr(urllib.request, "urlopen", raise_401)
    assert explain_finding(_finding())["degraded"] == "HTTP 401"


def test_every_preset_declares_a_wire():
    assert all(p["wire"] in ("offline", "openai", "anthropic") for p in PRESETS.values())


# ═══════════════════════════════════════════════ EXPLAIN ═════════════════════════════


def _finding(outcome="no_finding", detail="onlyRole enforced"):
    return {"probe": "lottery_operator_bypass", "target": "AIAgentLottery@0x76",
            "outcome": outcome, "title": "role gate holds", "detail": detail,
            "evidence": {"reproducer": "cast send ..."}}


def test_explain_never_mutates_the_finding():
    """The verdict is INPUT. If prose could reach the finding dict, it could reach the verdict."""
    f = _finding()
    before = json.dumps(f, sort_keys=True)
    explain_finding(f)
    assert json.dumps(f, sort_keys=True) == before


def test_explain_is_marked_advisory():
    assert explain_finding(_finding())["advisory"] is True


def test_offline_prose_distinguishes_the_three_outcomes():
    held = explain_finding(_finding("no_finding"))["explanation"]
    broke = explain_finding(_finding("finding"))["explanation"]
    unrun = explain_finding(_finding("inconclusive"))["explanation"]
    assert "honest negative" in held
    assert "broke" in broke
    assert "absence of a test" in unrun and "not a pass" in unrun


def test_offline_prose_flags_a_by_design_exploit():
    text = explain_finding(_finding("finding", "[BY DESIGN in the sealed bubble] open mint"))
    assert "intended bubble affordance" in text["explanation"]


def test_an_unreachable_model_falls_back_to_deterministic_prose(monkeypatch):
    """Advisory means advisory: a dead provider degrades the prose, never the command."""
    monkeypatch.setenv("DOLOS_LLM_PROVIDER", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-x")

    def dead(*a, **k):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", dead)
    out = explain_finding(_finding())
    assert "honest negative" in out["explanation"] and out["provider"].endswith("offline")


# ═══════════════════════════════════════════════ PROPOSE ═════════════════════════════


def test_proposals_are_always_inert():
    for p in _offline_proposals(SOL):
        assert p.status == "proposed"


def test_proposing_never_changes_the_catalog():
    """The catalog is CLOSED — a scanner that grows its own attack surface cannot be audited."""
    from dolos.attacks import catalog

    before = [n for n, _ in catalog()]
    propose_attacks(SOL)
    assert [n for n, _ in catalog()] == before


def test_the_offline_stand_in_finds_unguarded_privileged_functions():
    hints = {p.target_hint for p in _offline_proposals(SOL)}
    assert "withdraw" in hints and "setOwner" in hints


def test_it_skips_guarded_and_internal_functions():
    hints = {p.target_hint for p in _offline_proposals(SOL)}
    assert "pause" not in hints            # onlyOwner
    assert "_internalMint" not in hints    # internal
    assert "deposit" not in hints          # not privileged-sounding


def test_every_proposal_carries_a_sequence():
    """An invariant with no transaction sequence is an opinion, not a candidate attack."""
    assert all(p.sequence for p in _offline_proposals(SOL))


def test_proposal_ids_are_content_addressed():
    a, b = _offline_proposals(SOL), _offline_proposals(SOL)
    assert [p.proposal_id for p in a] == [p.proposal_id for p in b]


# --- parsing what a model returns ------------------------------------------------------


def test_a_fenced_json_reply_parses():
    text = '```json\n{"proposals":[{"invariant":"i","sequence":["a"],"target_hint":"t"}]}\n```'
    out = _parse_proposals(text, provider="openrouter")
    assert len(out) == 1 and out[0].provider == "openrouter"


def test_a_chatty_prefix_is_tolerated():
    text = 'Sure! Here you go:\n{"proposals":[{"invariant":"i","sequence":["a"]}]}'
    assert len(_parse_proposals(text, provider="x")) == 1


def test_a_bare_object_is_accepted_as_one_proposal():
    assert len(_parse_proposals('{"invariant":"i","sequence":["a"]}', provider="x")) == 1


def test_a_proposal_without_a_sequence_is_dropped():
    text = '{"proposals":[{"invariant":"i","sequence":[]},{"invariant":"j","sequence":["a"]}]}'
    out = _parse_proposals(text, provider="x")
    assert [p.invariant for p in out] == ["j"]


def test_unparseable_output_yields_nothing_rather_than_raising():
    assert _parse_proposals("I cannot help with that.", provider="x") == []
    assert _parse_proposals("", provider="x") == []


def test_a_model_essay_is_capped():
    many = {"proposals": [{"invariant": f"i{n}", "sequence": ["a"]} for n in range(50)]}
    assert len(_parse_proposals(json.dumps(many), provider="x")) <= 8


def test_a_dead_model_falls_back_to_the_offline_proposals(monkeypatch):
    monkeypatch.setenv("DOLOS_LLM_PROVIDER", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-x")
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **k: (_ for _ in ()).throw(urllib.error.URLError("down")))
    assert {p.target_hint for p in propose_attacks(SOL)} >= {"withdraw"}


# --- the queue -------------------------------------------------------------------------


def test_the_queue_dedups_by_content(tmp_path):
    q = ProposalQueue(str(tmp_path / "q.jsonl"))
    assert len(q.add(_offline_proposals(SOL))) == 2
    assert q.add(_offline_proposals(SOL)) == []          # same ideas, second run


def test_the_queue_survives_a_restart(tmp_path):
    path = str(tmp_path / "q.jsonl")
    ProposalQueue(path).add(_offline_proposals(SOL))
    assert ProposalQueue(path).add(_offline_proposals(SOL)) == []


def test_an_unwritable_queue_never_fails_the_command(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("file", encoding="utf-8")
    q = ProposalQueue(str(blocker / "q.jsonl"))
    assert len(q.add([AttackProposal(invariant="i", sequence=["a"])])) == 1


def test_a_corrupt_queue_line_costs_one_entry(tmp_path):
    path = tmp_path / "q.jsonl"
    path.write_text('{"proposal_id":"prop-1"}\n{not json\n', encoding="utf-8")
    assert ProposalQueue(str(path)).seen == {"prop-1"}


# --- the CLI ---------------------------------------------------------------------------


def test_the_propose_command_reports_the_catalog_is_unchanged(tmp_path, capsys):
    from dolos.__main__ import main

    src = tmp_path / "V.sol"
    src.write_text(SOL, encoding="utf-8")
    assert main(["propose", "--source", str(src), "--queue", str(tmp_path / "q.jsonl")]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["catalog_unchanged"] is True and out["new"] == 2
    assert all(p["status"] == "proposed" for p in out["proposals"])


def test_the_explain_command_echoes_the_verdict_unchanged(tmp_path, capsys):
    from dolos.__main__ import main

    f = tmp_path / "f.json"
    f.write_text(json.dumps(_finding("finding")), encoding="utf-8")
    assert main(["explain", "--finding", str(f)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["outcome"] == "finding" and out["advisory"] is True
