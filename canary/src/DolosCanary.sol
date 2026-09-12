// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title DolosCanary — a vault built to be broken, so the fix loop can be PROVEN.
///
/// Like the MOMUS canary and PRAXIS, this contract exists to fail its own contract on purpose:
/// DOLOS attacks it, confirms the drain, an automated fixer patches the `withdraw` guard, the
/// contract is redeployed to a throwaway fork, and DOLOS re-attacks to prove the hole is closed.
/// Nothing here runs on a real chain; it lives only in the UNI sandbox.
///
/// THE BUG (deliberate): `withdraw` lets any caller take ANY amount, not just their own balance.
/// A depositor's funds can be drained by a stranger. The fixed version checks the caller's own
/// recorded balance before paying out.
contract DolosCanary {
    mapping(address => uint256) public balanceOf;
    uint256 public totalDeposited;

    event Deposited(address indexed who, uint256 amount);
    event Withdrawn(address indexed who, uint256 amount);

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
        totalDeposited += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice VULNERABLE: no check that msg.sender actually owns `amount`. Anyone can drain.
    function withdraw(uint256 amount) external {
        // DOLOS-FIX-ANCHOR
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    receive() external payable {
        balanceOf[msg.sender] += msg.value;
        totalDeposited += msg.value;
    }
}
