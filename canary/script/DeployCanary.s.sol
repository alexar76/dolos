// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Script.sol";
import "../src/DolosCanary.sol";

/// Deploys the canary to whatever RPC forge is pointed at (a throwaway fork, in DOLOS's loop).
contract DeployCanary is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);
        DolosCanary canary = new DolosCanary();
        vm.stopBroadcast();
        console.log("DolosCanary:", address(canary));
    }
}
