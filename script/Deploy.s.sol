// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {MerkleClaim} from "src/MerkleClaim.sol";

contract Deploy is Script {
    function run() public {
        vm.startBroadcast();
        new MerkleClaim(msg.sender);
        vm.stopBroadcast();
    }
}
