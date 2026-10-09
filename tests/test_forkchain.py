"""ForkChain's RPC plumbing and cheat codes, against a stub JSON-RPC server.

test_smoke.py proves the real snapshot/revert property against Anvil. These tests cover what a
green Anvil run never shows: what the client does when the node answers with an error, a 500, or
nothing at all — because "could not run" must never be mistaken for "the contract is safe".

The stub is a ThreadingHTTPServer on purpose: a single-threaded one deadlocks on keep-alive.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from dolos.forkchain import ForkChain, ForkError, _free_port


class _Node:
    """A scripted JSON-RPC node. `answers` maps a method to a result, an Exception marker, or a
    callable taking the call index."""

    def __init__(self, answers: dict):
        self.answers = answers
        self.calls: list[tuple[str, list]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # keep the test output clean
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["content-length"])))
                method = body.get("method")
                outer.calls.append((method, body.get("params")))
                answer = outer.answers.get(method, "0x0")
                if answer == "HTTP500":
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(b"boom")
                    return
                if callable(answer):
                    answer = answer(len([c for c in outer.calls if c[0] == method]))
                payload = ({"jsonrpc": "2.0", "id": body.get("id"), "error": answer["error"]}
                           if isinstance(answer, dict) and "error" in answer
                           else {"jsonrpc": "2.0", "id": body.get("id"), "result": answer})
                raw = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        # 0.5s (the default poll interval) per shutdown would dominate this file's runtime.
        self.thread = threading.Thread(
            target=lambda: self.server.serve_forever(poll_interval=0.02), daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    def methods(self) -> list[str]:
        return [m for m, _ in self.calls]


@pytest.fixture()
def wired():
    """A ForkChain pointed at a stub node, with no anvil child process behind it."""
    def _make(answers):
        node = _Node(answers)
        node.__enter__()
        fork = ForkChain(fork_url="http://127.0.0.1:1", port=node.port)
        fork.rpc_url = f"http://127.0.0.1:{node.port}"
        return node, fork
    made = []

    def factory(answers):
        node, fork = _make(answers)
        made.append(node)
        return node, fork

    yield factory
    for node in made:
        node.__exit__()


# --------------------------------------------------------------------------- construction


def test_a_fork_needs_a_url_to_fork():
    """DOLOS forks a live chain; it does not invent one. An empty url is a config error."""
    with pytest.raises(ForkError):
        ForkChain(fork_url="")


def test_the_rpc_url_is_local_and_never_the_upstream():
    fork = ForkChain(fork_url="https://mainnet.example/rpc", port=12345)
    assert fork.rpc_url == "http://127.0.0.1:12345"
    assert fork.fork_url == "https://mainnet.example/rpc"


def test_start_refuses_without_foundry(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda *_a: None)
    fork = ForkChain(fork_url="http://127.0.0.1:8545", anvil_bin="/nonexistent/anvil")
    with pytest.raises(ForkError, match="anvil not found"):
        fork.start()


def test_stop_is_safe_when_nothing_was_started():
    ForkChain(fork_url="http://127.0.0.1:8545").stop()      # must not raise


def test_free_port_returns_the_preferred_port_when_it_is_free():
    port = _free_port()
    assert _free_port(port) == port


def test_free_port_falls_back_when_the_preferred_port_is_busy():
    with _Node({}) as node:
        assert _free_port(node.port) != node.port


# --------------------------------------------------------------------------- hex parsing


@pytest.mark.parametrize("raw,expected", [
    ("0x1f", 31), ("0x0", 0), ("42", 42), (7, 7),
    (None, 0), ("", 0), ("0xzz", 0), ("not a number", 0),
])
def test_hex_int_never_raises_on_junk(raw, expected):
    """A node that answers with junk must not crash a scan mid-catalog."""
    assert ForkChain._hex_int(raw) == expected


def test_hex_int_honours_the_default():
    assert ForkChain._hex_int(None, default=-1) == -1


# --------------------------------------------------------------------------- rpc


def test_rpc_returns_the_result(wired):
    _node, fork = wired({"eth_blockNumber": "0x2a"})
    assert fork.rpc("eth_blockNumber") == "0x2a"


def test_rpc_turns_a_json_rpc_error_into_a_fork_error(wired):
    _node, fork = wired({"evm_revert": {"error": {"code": -32602, "message": "bad snapshot id"}}})
    with pytest.raises(ForkError, match="bad snapshot id"):
        fork.rpc("evm_revert", ["0xdeadbeef"])


def test_rpc_turns_an_http_error_into_a_fork_error(wired):
    _node, fork = wired({"eth_chainId": "HTTP500"})
    with pytest.raises(ForkError, match="HTTP 500"):
        fork.rpc("eth_chainId")


def test_rpc_ids_increment_so_replies_are_attributable(wired):
    node, fork = wired({"eth_blockNumber": "0x1"})
    fork.rpc("eth_blockNumber")
    fork.rpc("eth_blockNumber")
    assert fork._id == 2


# --------------------------------------------------------------------------- cheat codes


def test_snapshot_and_revert_use_the_evm_cheats(wired):
    node, fork = wired({"evm_snapshot": "0x1", "evm_revert": True})
    snap = fork.snapshot()
    assert fork.revert(snap) is True
    assert node.methods() == ["evm_snapshot", "evm_revert"]


def test_impersonation_is_symmetric(wired):
    node, fork = wired({"anvil_impersonateAccount": None, "anvil_stopImpersonatingAccount": None})
    fork.impersonate("0xabc")
    fork.stop_impersonate("0xabc")
    assert node.methods() == ["anvil_impersonateAccount", "anvil_stopImpersonatingAccount"]


def test_set_balance_sends_hex_wei(wired):
    node, fork = wired({"anvil_setBalance": None})
    fork.set_balance("0xabc", 10**18)
    assert node.calls[0][1] == ["0xabc", hex(10**18)]


def test_mine_sends_a_hex_block_count(wired):
    node, fork = wired({"anvil_mine": None})
    fork.mine(3)
    assert node.calls[0][1] == ["0x3"]


# --------------------------------------------------------------------------- reads


def test_code_size_counts_bytes_not_hex_chars(wired):
    _node, fork = wired({"eth_getCode": "0x60806040"})
    assert fork.code_size("0xabc") == 4


def test_code_size_is_zero_for_an_address_with_no_contract(wired):
    """Zero is how every attack decides 'this target is not on the fork' — inconclusive, not held."""
    _node, fork = wired({"eth_getCode": "0x"})
    assert fork.code_size("0xabc") == 0


def test_balance_parses_hex(wired):
    _node, fork = wired({"eth_getBalance": hex(5 * 10**18)})
    assert fork.balance("0xabc") == 5 * 10**18


def test_call_passes_the_sender_when_given(wired):
    node, fork = wired({"eth_call": "0x01"})
    fork.call("0xto", "0xdata", frm="0xfrom")
    assert node.calls[0][1][0] == {"to": "0xto", "data": "0xdata", "from": "0xfrom"}


def test_call_omits_the_sender_when_not_given(wired):
    node, fork = wired({"eth_call": "0x01"})
    fork.call("0xto", "0xdata")
    assert "from" not in node.calls[0][1][0]


# --------------------------------------------------------------------------- sends


def test_send_from_returns_the_receipt(wired):
    _node, fork = wired({"eth_sendTransaction": "0xhash",
                         "eth_getTransactionReceipt": {"status": "0x1"}})
    assert fork.send_from("0xfrom", "0xto", "0xdata")["status"] == "0x1"


def test_send_from_encodes_value_and_gas_as_hex(wired):
    node, fork = wired({"eth_sendTransaction": "0xhash",
                        "eth_getTransactionReceipt": {"status": "0x1"}})
    fork.send_from("0xfrom", "0xto", value=10**18, gas=1_000_000)
    tx = node.calls[0][1][0]
    assert tx["value"] == hex(10**18) and tx["gas"] == hex(1_000_000)


def test_receipt_polls_until_the_transaction_is_mined(wired):
    _node, fork = wired({"eth_getTransactionReceipt":
                         lambda n: None if n < 3 else {"status": "0x1"}})
    assert fork.receipt("0xhash")["status"] == "0x1"


def test_receipt_gives_up_rather_than_hanging(wired):
    _node, fork = wired({"eth_getTransactionReceipt": None})
    with pytest.raises(ForkError, match="no receipt"):
        fork.receipt("0xhash", tries=2)
