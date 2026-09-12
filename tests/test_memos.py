"""Attack memory: it may reorder the catalog, and that is the whole list of things it may do.

Each limit here is a separate test because each one, if it broke, would break something different:
dropping an attack silently un-tests an invariant; changing a verdict destroys the honest negative;
ranking on raw exploit count pins the bubble's intended faucet at the top for ever.
"""

from __future__ import annotations

import json
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from dolos.memos import MAX_MEMOS, AttackMemo, MemoStore


def _memo(probe="escrow_channel_hijack", outcome="no_finding", by_design=False, target="AIMarketEscrow"):
    return AttackMemo(probe=probe, target_contract=target, outcome=outcome, by_design=by_design)


def _store(tmp_path, name="memos.jsonl"):
    return MemoStore(str(tmp_path / name))


CATALOG = [("unauthorized_token_mint", object()), ("escrow_channel_hijack", object()),
           ("lottery_operator_bypass", object())]


# --------------------------------------------------------------------------- what a memo is


def test_a_productive_memo_is_a_real_non_by_design_exploit():
    assert _memo(outcome="finding").productive is True
    assert _memo(outcome="finding", by_design=True).productive is False
    assert _memo(outcome="no_finding").productive is False
    assert _memo(outcome="inconclusive").productive is False


def test_recording_stamps_a_timestamp(tmp_path):
    m = _memo()
    assert m.ts == ""
    _store(tmp_path).record(m)
    assert m.ts.endswith("Z")


def test_an_explicit_timestamp_is_not_overwritten(tmp_path):
    m = _memo()
    m.ts = "2020-01-01T00:00:00Z"
    _store(tmp_path).record(m)
    assert m.ts == "2020-01-01T00:00:00Z"


# --------------------------------------------------------------------------- persistence


def test_memos_survive_a_restart(tmp_path):
    s = _store(tmp_path)
    s.record(_memo(outcome="finding"))
    s.record(_memo(probe="lottery_operator_bypass"))
    assert len(MemoStore(str(tmp_path / "memos.jsonl")).memos) == 2


def test_the_journal_is_one_json_object_per_line(tmp_path):
    s = _store(tmp_path)
    s.record(_memo())
    doc = json.loads((tmp_path / "memos.jsonl").read_text().splitlines()[0])
    assert doc["probe"] == "escrow_channel_hijack" and doc["ts"].endswith("Z")


def test_a_corrupt_line_costs_one_memo_not_the_memory(tmp_path):
    """A store that raised on a bad line would take the whole memory down with it."""
    path = tmp_path / "memos.jsonl"
    good = json.dumps({"probe": "a", "outcome": "finding", "by_design": False})
    path.write_text(f"{good}\n{{not json\n\n{good}\n", encoding="utf-8")
    assert len(MemoStore(str(path)).memos) == 2


def test_a_line_missing_the_probe_is_dropped(tmp_path):
    """`probe` is the identity we learn about; a memo without one teaches nothing."""
    path = tmp_path / "memos.jsonl"
    path.write_text(json.dumps({"outcome": "finding"}) + "\n", encoding="utf-8")
    assert MemoStore(str(path)).memos == []


def test_an_unwritable_path_never_breaks_a_scan(tmp_path):
    """Learning is best-effort. A scan must not fail because its memory could not be written."""
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file", encoding="utf-8")
    s = MemoStore(str(blocker / "memos.jsonl"))
    s.record(_memo())                       # must not raise
    assert len(s.memos) == 1                # still learned in-process


def test_the_journal_is_trimmed_rather_than_grown_for_ever(tmp_path):
    s = _store(tmp_path)
    s.memos = [_memo() for _ in range(MAX_MEMOS)]
    s.record(_memo(probe="newest"))
    assert len(s.memos) == MAX_MEMOS and s.memos[-1].probe == "newest"


# --------------------------------------------------------------------------- what it learned


def test_stats_count_each_outcome_separately(tmp_path):
    s = _store(tmp_path)
    for outcome, by_design in [("finding", False), ("finding", True), ("no_finding", False),
                               ("inconclusive", False)]:
        s.record(_memo(probe="p", outcome=outcome, by_design=by_design))
    st = s.stats()["p"]
    assert (st.runs, st.productive, st.by_design, st.held, st.inconclusive) == (4, 1, 1, 1, 1)


def test_yield_rate_is_productive_over_runs(tmp_path):
    s = _store(tmp_path)
    s.record(_memo(probe="p", outcome="finding"))
    s.record(_memo(probe="p", outcome="no_finding"))
    assert s.stats()["p"].yield_rate == pytest.approx(0.5)


def test_an_unrun_attack_scores_infinity_so_it_is_tried_first(tmp_path):
    s = _store(tmp_path)
    s.record(_memo(probe="known", outcome="finding"))
    assert s.score("never-run", total_runs=1) == math.inf


# --------------------------------------------------------------------------- ordering


def test_ordering_never_drops_or_adds_an_attack(tmp_path):
    """Ordering is not filtering. An attack that stopped running would silently become an untested
    invariant, reported as though it had been checked."""
    s = _store(tmp_path)
    for _ in range(5):
        s.record(_memo(probe="escrow_channel_hijack"))
    ordered = s.order(CATALOG)
    assert sorted(n for n, _ in ordered) == sorted(n for n, _ in CATALOG)
    assert len(ordered) == len(CATALOG)


def test_a_productive_attack_outranks_one_that_always_held(tmp_path):
    s = _store(tmp_path)
    for _ in range(6):
        s.record(_memo(probe="escrow_channel_hijack", outcome="finding"))
        s.record(_memo(probe="lottery_operator_bypass", outcome="no_finding"))
        s.record(_memo(probe="unauthorized_token_mint", outcome="no_finding"))
    names = [n for n, _ in s.order(CATALOG)]
    assert names[0] == "escrow_channel_hijack"


def test_the_by_design_faucet_does_not_get_pinned_to_the_top(tmp_path):
    """THE trap: the UNI stablecoin's open mint is exploited=True every single run because it is
    the bubble's intended faucet. Ranking on raw exploit count would park it first for ever and
    push the attacks that might find something real to the back."""
    s = _store(tmp_path)
    for _ in range(8):
        s.record(_memo(probe="unauthorized_token_mint", outcome="finding", by_design=True))
        s.record(_memo(probe="escrow_channel_hijack", outcome="finding", by_design=False))
        s.record(_memo(probe="lottery_operator_bypass", outcome="no_finding"))
    names = [n for n, _ in s.order(CATALOG)]
    assert names.index("escrow_channel_hijack") < names.index("unauthorized_token_mint")


def test_an_attack_that_keeps_failing_to_run_is_retried_not_buried(tmp_path):
    """An inconclusive is the absence of a test, so it must not sink like a genuine `held` —
    otherwise a misconfigured address book would quietly stop being retried."""
    s = _store(tmp_path)
    for _ in range(6):
        s.record(_memo(probe="escrow_channel_hijack", outcome="inconclusive"))
        s.record(_memo(probe="lottery_operator_bypass", outcome="no_finding"))
        s.record(_memo(probe="unauthorized_token_mint", outcome="no_finding"))
    names = [n for n, _ in s.order(CATALOG)]
    assert names.index("escrow_channel_hijack") < names.index("lottery_operator_bypass")


def test_ordering_is_deterministic_for_a_given_memory(tmp_path):
    """A periodic scanner whose order jittered per cycle would be impossible to reason about."""
    s = _store(tmp_path)
    for _ in range(4):
        s.record(_memo(probe="lottery_operator_bypass", outcome="no_finding"))
    assert [n for n, _ in s.order(CATALOG)] == [n for n, _ in s.order(CATALOG)]


def test_an_empty_memory_leaves_the_catalog_order_alone(tmp_path):
    """All-infinity scores must fall back to catalog order, not to an arbitrary one."""
    assert [n for n, _ in _store(tmp_path).order(CATALOG)] == [n for n, _ in CATALOG]


# --------------------------------------------------------------------------- lessons + summary


def test_lessons_need_a_few_runs_before_they_claim_anything(tmp_path):
    s = _store(tmp_path)
    s.record(_memo(probe="p"))
    assert s.distill_lessons() == []


def test_lessons_name_the_reason_not_just_the_count(tmp_path):
    s = _store(tmp_path)
    for _ in range(4):
        s.record(_memo(probe="held_one", outcome="no_finding"))
        s.record(_memo(probe="faucet", outcome="finding", by_design=True))
        s.record(_memo(probe="broken", outcome="inconclusive"))
        s.record(_memo(probe="real", outcome="finding"))
    by = {ls["probe"]: ls["verdict"] for ls in s.distill_lessons()}
    assert "held 4/4" in by["held_one"]
    assert "by-design" in by["faucet"] and "never a defect" in by["faucet"]
    assert "address book, not the contract" in by["broken"]
    assert "found a real exploit 4/4" in by["real"]


def test_summary_reports_shrinking_exploration_as_it_learns(tmp_path):
    s = _store(tmp_path)
    first = s.summary()["exploration"]
    for _ in range(20):
        s.record(_memo(probe="p", outcome="no_finding"))
    later = s.summary()
    assert later["exploration"] < first
    assert later["memos"] == 20 and later["probes_known"] == 1


def test_summary_counts_only_probes_that_found_something_real(tmp_path):
    s = _store(tmp_path)
    s.record(_memo(probe="faucet", outcome="finding", by_design=True))
    s.record(_memo(probe="real", outcome="finding"))
    assert s.summary()["productive_probes"] == 1
