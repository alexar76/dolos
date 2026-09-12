// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import "../src/DolosCanary.sol";

/// The LEGITIMATE-behaviour suite. It must pass for BOTH the vulnerable and the fixed contract —
/// it asserts that an honest depositor can deposit and withdraw their own funds. The fix must not
/// break this (a fixer that just `revert()`s everything would close the hole and fail here). The
/// SECURITY property — that a stranger cannot drain — is proven by DOLOS's re-attack, not here.
contract DolosCanaryTest is Test {
    DolosCanary vault;
    address alice = address(0xA11CE);

    function setUp() public {
        vault = new DolosCanary();
        vm.deal(alice, 10 ether);
    }

    function test_owner_can_deposit_and_withdraw_their_own() public {
        vm.prank(alice);
        vault.deposit{value: 3 ether}();
        assertEq(vault.balanceOf(alice), 3 ether);

        uint256 before = alice.balance;
        vm.prank(alice);
        vault.withdraw(1 ether);
        assertEq(alice.balance, before + 1 ether);
    }

    function test_deposit_accounting() public {
        vm.prank(alice);
        vault.deposit{value: 2 ether}();
        assertEq(vault.totalDeposited(), 2 ether);
    }
}
