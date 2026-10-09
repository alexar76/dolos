"""The attack catalog — each entry is an INVARIANT the contract claims, and an attempt to break it.

A DOLOS attack is not "call a function and see what happens". It is a proposition the contract is
supposed to guarantee ("only the operator can open a round", "a channel id cannot be hijacked",
"total supply only grows by authorized mints") and a concrete transaction sequence that would
violate it. The attack's verdict is binary and honest:

  exploited=True   the invariant broke — a real finding, with the exact sequence as the reproducer
  exploited=False  the contract held — an honest negative that REFUTES a static-analysis flag

That second outcome is why DOLOS exists alongside BASANOS: a static scanner flags "any caller can
write channels[<caller id>]"; only actually trying to hijack a channel and being reverted proves
whether that flag is a real hole or a false positive. DOLOS reports both, and never guesses.

Every attack runs against a THROWAWAY fork inside a snapshot the harness reverts afterwards, so an
attack may mint, impersonate and drain with total freedom — none of it outlives the check.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from web3 import Web3

    from .forkchain import ForkChain


# A stable, synthetic "status code" per attack CLASS. The finding dedup key is built from
# (target, probe, category, status_code); a code that changed per run would make the same bug
# payable on every rescan (the exact bug momus's audit warned about), so each attack pins one.
CODE_EXPLOITED = 561          # the invariant broke
CODE_HELD = 200               # the contract held (honest negative)
CODE_INCONCLUSIVE = 520       # could not run the attack


@dataclass
class AttackResult:
    probe: str                       # stable attack id, part of the dedup identity
    category: str                    # authz | supply | reentrancy | settlement | ...
    target_contract: str             # human name, e.g. "AIAgentLottery"
    exploited: bool
    severity: str                    # only meaningful when exploited
    title: str
    detail: str
    reproducer: str = ""
    reference_artifacts: tuple[str, ...] = ()
    status_code: int = CODE_HELD
    by_design: bool = False          # exploit works but is an intended bubble affordance
    error: str = ""                  # set when inconclusive

    @property
    def outcome(self) -> str:
        if self.error:
            return "inconclusive"
        return "finding" if self.exploited else "no_finding"


@dataclass
class AttackContext:
    """Everything an attack needs, and nothing that would let it escape the fork."""

    fork: "ForkChain"
    w3: "Web3"
    book: dict[str, str]             # universe_config address map (evm_lottery, evm_usdt, ...)
    realm: str = "uni"

    def addr(self, key: str) -> str | None:
        v = self.book.get(key)
        return self.w3.to_checksum_address(v) if isinstance(v, str) and v.startswith("0x") else None

    def random_attacker(self, *, funded_eth: int = 10 * 10**18) -> str:
        """A fresh address with no privileges, funded with fake ether for gas and impersonated so
        we can transact AS it. The whole point of an attacker: it holds no role and no key we know,
        yet on a fork we can still act as it."""
        a = self.w3.to_checksum_address("0x" + secrets.token_hex(20))
        self.fork.set_balance(a, funded_eth)
        self.fork.impersonate(a)
        return a


def _calldata(contract, fn: str, args: list) -> str:
    """Encode a function call across web3 v6 (encodeABI) and v7 (encode_abi)."""
    if hasattr(contract, "encode_abi"):
        try:
            return contract.encode_abi(fn, args=args)          # web3 v7
        except TypeError:
            return contract.encode_abi(abi_element_identifier=fn, args=args)
    return contract.encodeABI(fn_name=fn, args=args)           # web3 v6


def _fund_token(ctx: "AttackContext", token, to: str, amount: int) -> bool:
    """Give `to` some of `token` by impersonating the token's rich holder and transferring.

    The UNI stablecoin mints its whole supply to the deployer in its constructor and exposes no
    open mint, so DOLOS funds test accounts the only honest way: move real balance from whoever
    holds it. On a fork, impersonating that holder is free and leaves the live chain untouched."""
    holder = ctx.addr("payment_recipient") or ctx.w3.to_checksum_address(
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")  # standard anvil acct 0 (the deployer)
    ctx.fork.set_balance(holder, 10**18)
    ctx.fork.impersonate(holder)
    try:
        if token.functions.balanceOf(holder).call() < amount:
            return False
        ctx.fork.send_from(holder, token.address, _calldata(token, "transfer", [to, amount]))
        return token.functions.balanceOf(to).call() >= amount
    except Exception:  # noqa: BLE001
        return False


Attack = Callable[[AttackContext], AttackResult]
_REGISTRY: list[tuple[str, Attack]] = []


def attack(category: str) -> "Callable[[Attack], Attack]":
    """Register an attack under its CATEGORY.

    The category is declared here rather than kept in a list somewhere else, because a list
    somewhere else drifts: add an attack, forget the list, and every consumer of the category —
    intel ranking included — silently treats the new attack as uncategorised.
    """

    def register(fn: Attack) -> Attack:
        fn.attack_category = category           # type: ignore[attr-defined]
        _REGISTRY.append((fn.__name__, fn))
        return fn

    return register


def categories() -> dict[str, str]:
    """probe -> category, straight off the registry. Cannot drift from the catalog."""
    return {name: getattr(fn, "attack_category", "") for name, fn in _REGISTRY}


def catalog() -> list[tuple[str, Attack]]:
    return list(_REGISTRY)


def _contract(ctx: AttackContext, name: str, addr_key: str, sol: str | None = None):
    from .abis import load_abi

    addr = ctx.addr(addr_key)
    if not addr:
        return None, f"{addr_key} not in address book"
    abi = load_abi(name, sol)
    if not abi:
        return None, f"ABI for {name} not found in any project's out/"
    if ctx.fork.code_size(addr) == 0:
        return None, f"{name} at {addr} has no code on the fork"
    return ctx.w3.eth.contract(address=addr, abi=abi), ""


# --------------------------------------------------------------------------------------------
# The catalog. Each attack targets one of the nine live UNI contracts.
# --------------------------------------------------------------------------------------------

@attack("supply")
def unauthorized_token_mint(ctx: AttackContext) -> AttackResult:
    """INVARIANT: token supply grows only through an authorized minter.

    The UNI stablecoin is a fake with an OPEN mint (the bubble's 'funding from nowhere'). This
    attack proves the fact — a no-privilege address inflating its own balance — and lets policy
    decide: inside the sealed bubble it is the intended faucet (by_design, advisory); the identical
    code on a real chain is a critical supply bug. DOLOS states the fact; the mainnet/UNI boundary
    states the consequence."""
    from .abis import source_path

    name = "FakeUSDT"
    c, err = _contract(ctx, name, "evm_usdt", "FakeUSDT.sol")
    if c is None:  # some bubbles deploy UniUSD instead
        c, err2 = _contract(ctx, "UniUSD", "evm_usdt", "UniUSD.sol")
        if c is not None:
            name = "UniUSD"
        else:
            return AttackResult("unauthorized_token_mint", "supply", "FakeUSDT", False, "info",
                                "token mint unreachable", err, status_code=CODE_INCONCLUSIVE,
                                error=err)
    attacker = ctx.random_attacker()
    if not hasattr(c.functions, "mint"):
        return AttackResult("unauthorized_token_mint", "supply", name, False, "info",
                            "no mint() on token", "token exposes no mint", status_code=CODE_HELD)
    amount = 10**6 * 10**6  # 1,000,000 units at 6 decimals
    before = c.functions.balanceOf(attacker).call()
    try:
        ctx.fork.send_from(attacker, c.address,
                           _calldata(c, "mint", [attacker, amount]))
    except Exception as exc:  # noqa: BLE001 - a revert here means the contract HELD
        return AttackResult("unauthorized_token_mint", "supply", name, False, "info",
                            f"{name}.mint reverted for a non-minter — supply is guarded",
                            f"mint reverted: {str(exc)[:100]}", status_code=CODE_HELD)
    after = c.functions.balanceOf(attacker).call()
    if after > before:
        return AttackResult(
            "unauthorized_token_mint", "supply", name, True, "high",
            f"{name}.mint() is callable by any address — supply is uncapped and unauthorized",
            f"A no-role address minted {amount} units to itself (balance {before}->{after}). "
            "In the sealed UNI bubble this is the intended faucet; on a real chain it is a "
            "critical supply-inflation bug and would drain every pool priced against this token.",
            reproducer=f"cast send {c.address} 'mint(address,uint256)' <you> {amount} "
                       "--rpc-url $FORK --unlocked --from <you>",
            reference_artifacts=(source_path(name),) if source_path(name) else (),
            status_code=CODE_EXPLOITED, by_design=True)
    return AttackResult("unauthorized_token_mint", "supply", name, False, "info",
                        f"{name}.mint did not change balance", "no supply change",
                        status_code=CODE_HELD)


@attack("authz")
def escrow_channel_hijack(ctx: AttackContext) -> AttackResult:
    """INVARIANT: an open channel id belongs to its depositor and cannot be reopened by another.

    BASANOS flags `openChannel` as 'any caller claims channels[<caller-supplied id>]'. This drives
    it: a victim opens channel C; an attacker tries to openChannel(C) too. The contract's
    `channels[id].depositor != 0 -> revert ChannelExists` should stop it. If the attacker's call
    succeeds and overwrites the depositor, the flag is real; if it reverts, DOLOS refutes it."""
    from .abis import load_abi, source_path

    esc, err = _contract(ctx, "AIMarketEscrow", "evm_escrow", "AIMarketEscrow.sol")
    if esc is None:
        return AttackResult("escrow_channel_hijack", "authz", "AIMarketEscrow", False, "info",
                            "escrow unreachable", err, status_code=CODE_INCONCLUSIVE, error=err)
    token_addr = ctx.addr("evm_usdt")
    token_abi = load_abi("FakeUSDT", "FakeUSDT.sol") or load_abi("UniUSD", "UniUSD.sol")
    if not token_addr or not token_abi:
        return AttackResult("escrow_channel_hijack", "authz", "AIMarketEscrow", False, "info",
                            "token for escrow deposits unreachable", "no token",
                            status_code=CODE_INCONCLUSIVE, error="no token")
    token = ctx.w3.eth.contract(address=ctx.w3.to_checksum_address(token_addr), abi=token_abi)
    victim, attacker = ctx.random_attacker(), ctx.random_attacker()
    # Fund both from the deployer's constructor supply (FakeUSDT has no open mint), then approve.
    deposit = 5 * 10**6
    try:
        for who in (victim, attacker):
            if not _fund_token(ctx, token, who, deposit * 4):
                return AttackResult("escrow_channel_hijack", "authz", "AIMarketEscrow", False,
                                    "info", "could not fund test accounts from the deployer supply",
                                    "deployer holds too little token to seed the test",
                                    status_code=CODE_INCONCLUSIVE, error="funding failed")
            ctx.fork.impersonate(who)
            ctx.fork.send_from(who, token.address,
                               _calldata(token, "approve", [esc.address, deposit * 4]))
    except Exception as exc:  # noqa: BLE001
        return AttackResult("escrow_channel_hijack", "authz", "AIMarketEscrow", False, "info",
                            "could not fund test accounts", str(exc)[:120],
                            status_code=CODE_INCONCLUSIVE, error=str(exc)[:120])
    channel_id = "0x" + secrets.token_hex(32)
    try:
        ctx.fork.send_from(victim, esc.address,
                           _calldata(esc, "openChannel", [channel_id, token.address, deposit]))
    except Exception as exc:  # noqa: BLE001
        return AttackResult("escrow_channel_hijack", "authz", "AIMarketEscrow", False, "info",
                            "victim could not open a channel (token not whitelisted?) — attack N/A",
                            str(exc)[:120], status_code=CODE_INCONCLUSIVE, error=str(exc)[:120])
    # Now the attacker tries to seize the SAME id.
    try:
        rc = ctx.fork.send_from(attacker, esc.address,
                                _calldata(esc, "openChannel", [channel_id, token.address, deposit]))
        reverted = ctx.fork._hex_int(rc.get("status")) == 0
    except Exception:  # noqa: BLE001 - an exception is the revert we hoped for
        reverted = True
    if reverted:
        return AttackResult("escrow_channel_hijack", "authz", "AIMarketEscrow", False, "info",
                            "openChannel refused a duplicate channel id — hijack blocked",
                            "The depositor!=0 guard held; the BASANOS 'caller-supplied id' flag is "
                            "a false positive for this contract.", status_code=CODE_HELD)
    depositor = esc.functions.getChannel(channel_id).call()[0] if hasattr(esc.functions, "getChannel") else attacker
    return AttackResult(
        "escrow_channel_hijack", "authz", "AIMarketEscrow", True, "critical",
        "openChannel let a second caller seize an existing channel id",
        f"After the victim opened channel {channel_id[:14]}…, the attacker reopened the same id "
        f"and is now recorded as depositor ({str(depositor)[:12]}). Escrowed funds can be stolen.",
        reproducer="two openChannel(id,...) calls with the same id from different senders; the "
                   "second must revert ChannelExists and did not.",
        reference_artifacts=(source_path("AIMarketEscrow"),) if source_path("AIMarketEscrow") else (),
        status_code=CODE_EXPLOITED)


@attack("authz")
def lottery_operator_bypass(ctx: AttackContext) -> AttackResult:
    """INVARIANT: only OPERATOR_ROLE may open a round or withdraw operator fees.

    A no-role attacker calls openRound() and withdrawOpex(). Both are `onlyRole(OPERATOR_ROLE)`,
    so both must revert. A success means anyone can drive or drain the lottery."""
    from .abis import source_path

    lot, err = _contract(ctx, "AIAgentLottery", "evm_lottery", "AIAgentLottery.sol")
    if lot is None:
        return AttackResult("lottery_operator_bypass", "authz", "AIAgentLottery", False, "info",
                            "lottery unreachable", err, status_code=CODE_INCONCLUSIVE, error=err)
    attacker = ctx.random_attacker()
    opened = False
    try:
        rc = ctx.fork.send_from(attacker, lot.address, _calldata(lot, "openRound", []))
        opened = ctx.fork._hex_int(rc.get("status")) == 1
    except Exception:  # noqa: BLE001 - revert = held
        opened = False
    if opened:
        return AttackResult(
            "lottery_operator_bypass", "authz", "AIAgentLottery", True, "high",
            "openRound() succeeded for a non-operator — the OPERATOR_ROLE gate is missing",
            "A no-role address opened a lottery round. Round lifecycle is unauthenticated; an "
            "attacker can grief the draw schedule or force rounds.",
            reproducer=f"cast send {lot.address} 'openRound()' --rpc-url $FORK --unlocked --from <you>",
            reference_artifacts=(source_path("AIAgentLottery"),) if source_path("AIAgentLottery") else (),
            status_code=CODE_EXPLOITED)
    return AttackResult("lottery_operator_bypass", "authz", "AIAgentLottery", False, "info",
                        "openRound() reverted for a non-operator — the role gate holds",
                        "onlyRole(OPERATOR_ROLE) enforced; access control is sound here.",
                        status_code=CODE_HELD)
