"""A disposable fork of a running chain — the whole reason DOLOS is safe.

WHY A FORK, NOT THE LIVE CHAIN
------------------------------
The obvious way to attack a contract is to snapshot the live chain, throw an exploit at it, and
`evm_revert`. It is also wrong here: the UNI bubble's Anvil is SHARED — the lottery relayer and
the ACEX trader are transacting on it continuously. `evm_revert` discards *everything* after the
snapshot, so an attack that snapshots the live chain would silently roll back the bubble's real
economy the instant it reverted.

So DOLOS never touches the live chain. It spawns its OWN `anvil --fork-url <live>` on another
port: a copy-on-write clone of the live state at a block. Every deployed contract, every balance,
every storage slot is there to attack — and when the fork is torn down, nothing that happened on
it ever existed. Snapshot/revert inside the fork is then free and total, because the fork is the
disposable thing, not the bubble.

This is the property the user asked for: attack anything, risk nothing. It is true precisely
because the target is a fork, funded with fake ether via `anvil_setBalance`, drivable AS any
address via `anvil_impersonateAccount` — none of which is possible, or safe, on a real chain.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any


class ForkError(RuntimeError):
    """Raised when a fork cannot be created or reached. Callers treat this as 'could not run',
    never as 'the contract is safe' — an unreached fork is the absence of a test, not a pass."""


def _free_port(preferred: int = 0) -> int:
    """A port nothing is listening on. `preferred` is tried first so runs are reproducible when
    it is free, but a busy preferred port never blocks a scan — a second fork just gets another."""
    if preferred:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", preferred)) != 0:
                return preferred
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ForkChain:
    """A short-lived Anvil fork. Use as a context manager so the child process is always reaped,
    even when an attack raises:

        with ForkChain(fork_url="http://127.0.0.1:8545") as fork:
            fork.impersonate(victim)
            fork.rpc("eth_sendTransaction", [{...}])
    """

    def __init__(
        self,
        fork_url: str,
        *,
        port: int | None = None,
        anvil_bin: str = "",
        block_time: int = 0,
        boot_timeout: float = 30.0,
        silent: bool = True,
    ) -> None:
        if not fork_url:
            raise ForkError("no fork_url — DOLOS forks a live chain, it does not invent one")
        self.fork_url = fork_url.rstrip("/")
        self.anvil_bin = anvil_bin or os.getenv("DOLOS_ANVIL_BIN") or shutil.which("anvil") or "anvil"
        self.port = port or _free_port(int(os.getenv("DOLOS_FORK_PORT", "0") or 0))
        self.block_time = block_time
        self.boot_timeout = boot_timeout
        self.silent = silent
        self.rpc_url = f"http://127.0.0.1:{self.port}"
        self._proc: subprocess.Popen | None = None
        self._id = 0
        self.chain_id: int | None = None
        self.fork_block: int | None = None

    # -- lifecycle -----------------------------------------------------------------------

    def __enter__(self) -> "ForkChain":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    def start(self) -> "ForkChain":
        if shutil.which(self.anvil_bin) is None and not os.path.exists(self.anvil_bin):
            raise ForkError(f"anvil not found ({self.anvil_bin}) — DOLOS needs Foundry to fork")
        args = [
            self.anvil_bin,
            "--fork-url", self.fork_url,
            "--port", str(self.port),
            "--host", "127.0.0.1",
        ]
        if self.block_time:
            args += ["--block-time", str(self.block_time)]
        out = subprocess.DEVNULL if self.silent else None
        try:
            self._proc = subprocess.Popen(args, stdout=out, stderr=out)
        except OSError as exc:
            raise ForkError(f"could not spawn anvil: {exc}") from exc
        self._wait_ready()
        self.chain_id = self._hex_int(self.rpc("eth_chainId"))
        self.fork_block = self._hex_int(self.rpc("eth_blockNumber"))
        return self

    def stop(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None

    def _wait_ready(self) -> None:
        deadline = time.time() + self.boot_timeout
        last = ""
        while time.time() < deadline:
            if self._proc and self._proc.poll() is not None:
                raise ForkError("anvil exited during boot — is the fork_url reachable?")
            try:
                self.rpc("eth_blockNumber")
                return
            except (ForkError, urllib.error.URLError, OSError) as exc:
                last = str(exc)[:80]
                time.sleep(0.25)
        self.stop()
        raise ForkError(f"anvil fork did not become ready in {self.boot_timeout}s ({last})")

    # -- JSON-RPC ------------------------------------------------------------------------

    def rpc(self, method: str, params: list[Any] | None = None, *, timeout: float = 30.0) -> Any:
        self._id += 1
        payload = json.dumps({"jsonrpc": "2.0", "id": self._id,
                              "method": method, "params": params or []}).encode()
        req = urllib.request.Request(self.rpc_url, data=payload,
                                     headers={"content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            raise ForkError(f"{method} HTTP {exc.code}") from exc
        if isinstance(body, dict) and body.get("error"):
            raise ForkError(f"{method}: {str(body['error'])[:160]}")
        return (body or {}).get("result")

    @staticmethod
    def _hex_int(value: Any, default: int = 0) -> int:
        try:
            return int(str(value), 16) if str(value).startswith("0x") else int(value)
        except (TypeError, ValueError):
            return default

    # -- cheat codes — safe ONLY because this is a throwaway fork -------------------------

    def snapshot(self) -> str:
        """A point to rewind to. On a fork this is cheap and lossless: nothing else is writing."""
        return self.rpc("evm_snapshot")

    def revert(self, snap_id: str) -> bool:
        return bool(self.rpc("evm_revert", [snap_id]))

    def impersonate(self, address: str) -> None:
        """Send transactions AS `address` without its key — the move that makes 'attack as the
        owner' or 'attack as a victim' possible. Impossible on a real chain; that is the point."""
        self.rpc("anvil_impersonateAccount", [address])

    def stop_impersonate(self, address: str) -> None:
        self.rpc("anvil_stopImpersonatingAccount", [address])

    def set_balance(self, address: str, wei: int) -> None:
        self.rpc("anvil_setBalance", [address, hex(wei)])

    def mine(self, blocks: int = 1) -> None:
        self.rpc("anvil_mine", [hex(blocks)])

    # -- reads ---------------------------------------------------------------------------

    def code_size(self, address: str) -> int:
        code = str(self.rpc("eth_getCode", [address, "latest"]) or "0x")
        return max(0, (len(code) - 2) // 2)

    def balance(self, address: str) -> int:
        return self._hex_int(self.rpc("eth_getBalance", [address, "latest"]))

    def call(self, to: str, data: str, *, frm: str | None = None) -> str:
        tx = {"to": to, "data": data}
        if frm:
            tx["from"] = frm
        return str(self.rpc("eth_call", [tx, "latest"]) or "0x")

    def send_from(self, frm: str, to: str, data: str = "0x", value: int = 0,
                  *, gas: int = 3_000_000) -> dict[str, Any]:
        """Send an impersonated transaction and return its receipt. Callers snapshot before and
        revert after, so a send that mutates state leaves the fork exactly as it found it."""
        tx = {"from": frm, "to": to, "data": data, "value": hex(value), "gas": hex(gas)}
        tx_hash = self.rpc("eth_sendTransaction", [tx])
        return self.receipt(str(tx_hash))

    def receipt(self, tx_hash: str, *, tries: int = 40) -> dict[str, Any]:
        for _ in range(tries):
            rc = self.rpc("eth_getTransactionReceipt", [tx_hash])
            if rc:
                return rc
            time.sleep(0.05)
        raise ForkError(f"no receipt for {tx_hash}")
