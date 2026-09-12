"""The attack catalog: an attack is an invariant, and its verdict is binary and honest.

The three outcomes each mean something different downstream, so each gets its own test:

  exploited  -> a real finding, payable, with a reproducer
  held       -> an honest negative that REFUTES a static flag (this is why DOLOS exists)
  inconclusive -> the attack could not run; NEVER to be read as "the contract is safe"
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from conftest import FakeContract, FakeFork, FakeW3

from dolos import abis
from dolos.attacks import (
    CODE_EXPLOITED,
    CODE_HELD,
    CODE_INCONCLUSIVE,
    AttackContext,
    AttackResult,
    _calldata,
    _fund_token,
    catalog,
    escrow_channel_hijack,
    lottery_operator_bypass,
    unauthorized_token_mint,
)

ABI = [{"type": "function", "name": "mint"}]
USDT = "0x" + "11" * 20
ESCROW = "0x" + "22" * 20
LOTTERY = "0x" + "33" * 20


@pytest.fixture()
def ctx(book, monkeypatch):
    monkeypatch.setattr(abis, "load_abi", lambda *a, **k: ABI)
    monkeypatch.setattr(abis, "source_path", lambda name: f"src/{name}.sol")
    return AttackContext(fork=FakeFork(), w3=FakeW3(), book=book)


def _put(ctx: AttackContext, address: str, values: dict) -> FakeContract:
    c = FakeContract(ctx.w3.to_checksum_address(address), values)
    ctx.w3.contracts[ctx.w3.to_checksum_address(address)] = c
    return c


# --------------------------------------------------------------------------- result shape


def test_outcome_maps_the_three_states():
    held = AttackResult("p", "authz", "C", False, "info", "t", "d")
    exploited = AttackResult("p", "authz", "C", True, "high", "t", "d")
    broken = AttackResult("p", "authz", "C", False, "info", "t", "d", error="rpc died")
    assert (held.outcome, exploited.outcome, broken.outcome) == (
        "no_finding", "finding", "inconclusive")


def test_an_error_outranks_exploited_so_a_crash_is_never_a_finding():
    """A crashed attack that happens to have `exploited=True` set must still read inconclusive —
    an unrun attack is the absence of a test, not a result."""
    r = AttackResult("p", "authz", "C", True, "high", "t", "d", error="anvil died")
    assert r.outcome == "inconclusive"


def test_status_codes_are_per_class_not_per_run():
    """The dedup key is built from the status code; a per-run code would make one bug payable on
    every rescan. The three codes are constants, and they differ."""
    assert len({CODE_EXPLOITED, CODE_HELD, CODE_INCONCLUSIVE}) == 3


def test_catalog_exposes_stable_probe_ids():
    names = [name for name, _ in catalog()]
    assert names == ["unauthorized_token_mint", "escrow_channel_hijack", "lottery_operator_bypass"]


def test_catalog_returns_a_copy_so_a_caller_cannot_mutate_the_registry():
    catalog().append(("evil", lambda c: None))
    assert "evil" not in [n for n, _ in catalog()]


# --------------------------------------------------------------------------- context


def test_addr_checksums_a_hex_address(ctx):
    assert ctx.addr("evm_usdt") == ctx.w3.to_checksum_address(USDT)


def test_addr_returns_none_for_a_non_address_value(ctx):
    """The address book holds realm strings too; a non-0x value must not become a target."""
    assert ctx.addr("not_an_address") is None
    assert ctx.addr("missing_key") is None


def test_random_attacker_is_funded_and_impersonated(ctx):
    """The whole trick: an address holding no role and no key we know, that we can still act as."""
    a = ctx.random_attacker()
    assert a in ctx.fork.impersonated
    assert (a, 10 * 10**18) in ctx.fork.funded


def test_random_attacker_is_fresh_each_time(ctx):
    assert ctx.random_attacker() != ctx.random_attacker()


# --------------------------------------------------------------------------- calldata shim


def test_calldata_uses_web3_v7_encode_abi():
    class V7:
        def encode_abi(self, fn, args=None):
            return f"v7:{fn}:{args}"

    assert _calldata(V7(), "mint", [1]) == "v7:mint:[1]"


def test_calldata_falls_back_to_the_keyword_form_of_encode_abi():
    """Some 7.x releases only accept `abi_element_identifier=`; the positional call raises."""
    class V7Kw:
        def encode_abi(self, fn=None, args=None, abi_element_identifier=None):
            if fn is not None:
                raise TypeError("positional not supported")
            return f"kw:{abi_element_identifier}:{args}"

    assert _calldata(V7Kw(), "mint", [2]) == "kw:mint:[2]"


def test_calldata_uses_web3_v6_encodeabi():
    class V6:
        def encodeABI(self, fn_name=None, args=None):
            return f"v6:{fn_name}:{args}"

    assert _calldata(V6(), "mint", [3]) == "v6:mint:[3]"


# --------------------------------------------------------------------------- token funding


def test_fund_token_moves_real_balance_from_the_holder(ctx):
    """FakeUSDT has no open mint for the escrow test, so funding must come from whoever holds it."""
    token = _put(ctx, USDT, {"balanceOf": 10**12, "transfer": None})
    assert _fund_token(ctx, token, "0xdead", 10**6) is True
    assert ctx.addr("payment_recipient") in ctx.fork.impersonated


def test_fund_token_refuses_when_the_holder_is_too_poor(ctx):
    token = _put(ctx, USDT, {"balanceOf": 1})
    assert _fund_token(ctx, token, "0xdead", 10**6) is False
    assert ctx.fork.sends == []          # nothing was attempted


def test_fund_token_swallows_a_transfer_revert(ctx):
    ctx.fork.send_results = [RuntimeError("transfer reverted")]
    token = _put(ctx, USDT, {"balanceOf": 10**12, "transfer": None})
    assert _fund_token(ctx, token, "0xdead", 10**6) is False


# --------------------------------------------------------------------------- unauthorized_token_mint


def test_mint_attack_reports_an_open_mint_as_by_design_in_the_bubble(ctx):
    """The UNI stablecoin's open mint IS the bubble's faucet. DOLOS states the fact and tags the
    consequence — `by_design` is what keeps it out of auto-remediation."""
    balances = iter([0, 10**12])
    _put(ctx, USDT, {"mint": None, "balanceOf": lambda: next(balances)})
    r = unauthorized_token_mint(ctx)
    assert r.exploited and r.by_design and r.severity == "high"
    assert r.status_code == CODE_EXPLOITED
    assert "cast send" in r.reproducer
    assert r.reference_artifacts == ("src/FakeUSDT.sol",)


def test_mint_attack_reports_a_guarded_supply_as_held(ctx):
    ctx.fork.send_results = [RuntimeError("execution reverted: not minter")]
    _put(ctx, USDT, {"mint": None, "balanceOf": 0})
    r = unauthorized_token_mint(ctx)
    assert not r.exploited and r.outcome == "no_finding" and r.status_code == CODE_HELD
    assert "guarded" in r.title


def test_mint_attack_is_held_when_the_token_exposes_no_mint(ctx):
    _put(ctx, USDT, {"balanceOf": 0})
    r = unauthorized_token_mint(ctx)
    assert not r.exploited and "no mint()" in r.title


def test_mint_attack_that_changes_no_balance_is_held(ctx):
    _put(ctx, USDT, {"mint": None, "balanceOf": 500})
    r = unauthorized_token_mint(ctx)
    assert not r.exploited and "did not change balance" in r.title


def test_mint_attack_is_inconclusive_when_the_token_has_no_code(ctx, monkeypatch):
    """No code on the fork means the attack never ran — inconclusive, never 'held'."""
    ctx.fork.code_sizes[ctx.w3.to_checksum_address(USDT)] = 0
    r = unauthorized_token_mint(ctx)
    assert r.outcome == "inconclusive" and r.status_code == CODE_INCONCLUSIVE


def test_mint_attack_is_inconclusive_when_no_abi_is_available(ctx, monkeypatch):
    monkeypatch.setattr(abis, "load_abi", lambda *a, **k: None)
    r = unauthorized_token_mint(ctx)
    assert r.outcome == "inconclusive" and "ABI" in r.error


# --------------------------------------------------------------------------- escrow_channel_hijack


def _escrow_scene(ctx, *, last_send):
    _put(ctx, USDT, {"balanceOf": 10**12, "transfer": None, "approve": None})
    _put(ctx, ESCROW, {"openChannel": None})
    # 4 funding/approve sends, then the victim's openChannel, then the attacker's attempt
    ctx.fork.send_results = [{"status": "0x1"}] * 5 + [last_send]


def test_escrow_hijack_refuted_when_the_duplicate_id_reverts(ctx):
    """The headline honest negative: BASANOS flags caller-supplied channel ids; DOLOS drives the
    hijack, the depositor!=0 guard holds, and the flag is refuted rather than repeated."""
    _escrow_scene(ctx, last_send={"status": "0x0"})
    r = escrow_channel_hijack(ctx)
    assert not r.exploited and r.status_code == CODE_HELD
    assert "false positive" in r.detail


def test_escrow_hijack_refuted_when_the_duplicate_id_raises(ctx):
    _escrow_scene(ctx, last_send=RuntimeError("ChannelExists"))
    r = escrow_channel_hijack(ctx)
    assert not r.exploited and "hijack blocked" in r.title


def test_escrow_hijack_confirmed_when_a_second_caller_seizes_the_id(ctx):
    _escrow_scene(ctx, last_send={"status": "0x1"})
    r = escrow_channel_hijack(ctx)
    assert r.exploited and r.severity == "critical" and r.status_code == CODE_EXPLOITED
    assert "seize" in r.title


def test_escrow_hijack_reads_the_recorded_depositor_when_the_getter_exists(ctx):
    thief = "0x" + "ab" * 20
    _put(ctx, USDT, {"balanceOf": 10**12, "transfer": None, "approve": None})
    _put(ctx, ESCROW, {"openChannel": None, "getChannel": (thief, 1)})
    ctx.fork.send_results = [{"status": "0x1"}] * 6
    r = escrow_channel_hijack(ctx)
    assert r.exploited and thief[:12] in r.detail


def test_escrow_hijack_is_inconclusive_when_funding_fails(ctx):
    _put(ctx, USDT, {"balanceOf": 1, "transfer": None, "approve": None})
    _put(ctx, ESCROW, {"openChannel": None})
    r = escrow_channel_hijack(ctx)
    assert r.outcome == "inconclusive" and "fund" in r.title


def test_escrow_hijack_is_inconclusive_when_the_victim_cannot_open_a_channel(ctx):
    """If the setup move fails the attack was never attempted — that is not a passing grade."""
    _put(ctx, USDT, {"balanceOf": 10**12, "transfer": None, "approve": None})
    _put(ctx, ESCROW, {"openChannel": None})
    ctx.fork.send_results = [{"status": "0x1"}] * 4 + [RuntimeError("token not whitelisted")]
    r = escrow_channel_hijack(ctx)
    assert r.outcome == "inconclusive" and "attack N/A" in r.title


def test_escrow_hijack_is_inconclusive_without_a_token(ctx, monkeypatch):
    _put(ctx, ESCROW, {"openChannel": None})
    monkeypatch.setattr(abis, "load_abi",
                        lambda name, sol=None: None if "USD" in name else ABI)
    r = escrow_channel_hijack(ctx)
    assert r.outcome == "inconclusive" and "token" in r.title


def test_escrow_hijack_is_inconclusive_when_the_escrow_is_unreachable(ctx):
    ctx.fork.code_sizes[ctx.w3.to_checksum_address(ESCROW)] = 0
    r = escrow_channel_hijack(ctx)
    assert r.outcome == "inconclusive" and "unreachable" in r.title


# --------------------------------------------------------------------------- lottery_operator_bypass


def test_lottery_bypass_held_when_the_role_gate_reverts(ctx):
    _put(ctx, LOTTERY, {"openRound": None})
    ctx.fork.send_results = [RuntimeError("AccessControl: missing role")]
    r = lottery_operator_bypass(ctx)
    assert not r.exploited and "role gate holds" in r.title


def test_lottery_bypass_held_when_the_call_reverts_by_status(ctx):
    _put(ctx, LOTTERY, {"openRound": None})
    ctx.fork.send_results = [{"status": "0x0"}]
    r = lottery_operator_bypass(ctx)
    assert not r.exploited and r.status_code == CODE_HELD


def test_lottery_bypass_confirmed_when_a_no_role_address_opens_a_round(ctx):
    _put(ctx, LOTTERY, {"openRound": None})
    ctx.fork.send_results = [{"status": "0x1"}]
    r = lottery_operator_bypass(ctx)
    assert r.exploited and r.severity == "high" and "OPERATOR_ROLE gate is missing" in r.title


def test_lottery_bypass_is_inconclusive_when_the_lottery_is_unreachable(ctx):
    ctx.fork.code_sizes[ctx.w3.to_checksum_address(LOTTERY)] = 0
    r = lottery_operator_bypass(ctx)
    assert r.outcome == "inconclusive" and r.error


def test_every_attack_in_the_catalog_survives_a_dead_address_book(monkeypatch):
    """A scan against an empty book must degrade to inconclusive across the board, not raise."""
    monkeypatch.setattr(abis, "load_abi", lambda *a, **k: ABI)
    empty = AttackContext(fork=FakeFork(), w3=FakeW3(), book={})
    for _name, fn in catalog():
        assert fn(empty).outcome == "inconclusive"
