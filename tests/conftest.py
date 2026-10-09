"""Shared fakes.

DOLOS's real target is an Anvil fork, so most of its logic is only reachable through a chain.
These fakes stand in for the two objects an attack touches — the fork (cheat codes + raw sends)
and web3's contract handle — so the *decision* logic (which invariant broke, what the finding
says, what may be auto-fixed) is tested without Foundry. The integration tests in test_smoke.py
still drive the real thing where the toolchain is installed; these do not replace them.
"""

from __future__ import annotations

import os
import sys
from typing import Any

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class FakeFork:
    """A ForkChain stand-in that records cheat codes and answers from a scripted state.

    `send_results` maps a call-order index to either a receipt dict or an exception to raise, so
    a test can say "the first send succeeds, the second reverts" — which is exactly the shape of
    every attack (set the scene, then try the illegal move).
    """

    def __init__(self, *, code_sizes: dict[str, int] | None = None,
                 balances: dict[str, int] | None = None,
                 send_results: list[Any] | None = None) -> None:
        self.code_sizes = code_sizes or {}
        self.balances = balances or {}
        self.send_results = list(send_results or [])
        self.impersonated: list[str] = []
        self.funded: list[tuple[str, int]] = []
        self.sends: list[tuple[str, str, str, int]] = []
        self.snapshots = 0
        self.reverts = 0
        self.rpc_url = "http://127.0.0.1:0"
        self.chain_id = 31337
        self.fork_block = 1
        self.fork_url = "http://127.0.0.1:8545"
        self.stopped = False

    # -- cheat codes -----------------------------------------------------------------
    def set_balance(self, address: str, wei: int) -> None:
        self.funded.append((address, wei))
        self.balances[address] = wei

    def impersonate(self, address: str) -> None:
        self.impersonated.append(address)

    def snapshot(self) -> str:
        self.snapshots += 1
        return f"0x{self.snapshots:02x}"

    def revert(self, snap_id: str) -> bool:
        self.reverts += 1
        return True

    def stop(self) -> None:
        self.stopped = True

    # -- reads -----------------------------------------------------------------------
    def code_size(self, address: str) -> int:
        return self.code_sizes.get(address, 1)

    def balance(self, address: str) -> int:
        return self.balances.get(address, 0)

    # -- writes ----------------------------------------------------------------------
    def send_from(self, frm: str, to: str, data: str = "0x", value: int = 0,
                  **kw: Any) -> dict[str, Any]:
        self.sends.append((frm, to, data, value))
        if not self.send_results:
            return {"status": "0x1"}
        nxt = self.send_results.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt

    @staticmethod
    def _hex_int(value: Any, default: int = 0) -> int:
        from dolos.forkchain import ForkChain

        return ForkChain._hex_int(value, default)


class FakeCall:
    def __init__(self, value: Any) -> None:
        self._value = value

    def call(self) -> Any:
        return self._value() if callable(self._value) else self._value


class FakeFunctions:
    """`contract.functions.foo(args).call()` over a dict of scripted return values.

    Only the names present are exposed, because `hasattr(c.functions, "mint")` is load-bearing
    in the catalog: a token with no `mint` must be reported as held, not as unreachable.
    """

    def __init__(self, values: dict[str, Any]) -> None:
        self._values = values
        self.calls: list[tuple[str, tuple]] = []

    def __getattr__(self, name: str):
        if name.startswith("_") or name not in self._values:
            raise AttributeError(name)

        def _fn(*args: Any) -> FakeCall:
            self.calls.append((name, args))
            return FakeCall(self._values[name])

        return _fn


class FakeContract:
    def __init__(self, address: str, values: dict[str, Any] | None = None) -> None:
        self.address = address
        self.functions = FakeFunctions(values or {})
        self.encoded: list[tuple[str, list]] = []

    def encode_abi(self, fn: str | None = None, args: list | None = None,
                   abi_element_identifier: str | None = None) -> str:
        name = fn or abi_element_identifier or ""
        self.encoded.append((name, list(args or [])))
        return "0x" + name.encode().hex()


class FakeEth:
    def __init__(self, contracts: dict[str, FakeContract]) -> None:
        self._contracts = contracts

    def contract(self, address: str = "", abi: Any = None) -> FakeContract:
        return self._contracts.setdefault(address, FakeContract(address))


class FakeW3:
    """Enough web3 for the catalog: checksumming (the real, pure function) and `eth.contract`."""

    def __init__(self, contracts: dict[str, FakeContract] | None = None) -> None:
        self.contracts = contracts if contracts is not None else {}
        self.eth = FakeEth(self.contracts)

    @staticmethod
    def to_checksum_address(value: str) -> str:
        from web3 import Web3

        return Web3.to_checksum_address(value)


def held_result(**kw):
    """A canonical honest negative — the contract refused the attack."""
    from dolos.attacks import CODE_HELD, AttackResult

    base = dict(probe="lottery_operator_bypass", category="authz",
                target_contract="AIAgentLottery", exploited=False, severity="info",
                title="role gate holds", detail="onlyRole enforced", status_code=CODE_HELD)
    base.update(kw)
    return AttackResult(**base)


def exploit_result(**kw):
    """A canonical confirmed exploit, reproducer and all."""
    from dolos.attacks import CODE_EXPLOITED

    base = dict(exploited=True, severity="high", title="mint is open",
                detail="anyone can mint", probe="unauthorized_token_mint",
                target_contract="FakeUSDT", category="supply",
                status_code=CODE_EXPLOITED, reproducer="cast send ... mint")
    base.update(kw)
    return held_result(**base)


@pytest.fixture()
def book() -> dict[str, str]:
    """A minimal UNI address book — the same keys `AttackContext.addr` looks up."""
    return {
        "evm_usdt": "0x" + "11" * 20,
        "evm_escrow": "0x" + "22" * 20,
        "evm_lottery": "0x" + "33" * 20,
        "payment_recipient": "0x" + "44" * 20,
        "not_an_address": "uni",
    }
