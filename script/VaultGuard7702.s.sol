// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script} from "forge-std/Script.sol";
import {VaultGuard7702} from "../src/VaultGuard7702.sol";

contract VaultGuard7702Script is Script {
    function run() public {
        vm.startBroadcast();

        new VaultGuard7702();

        vm.stopBroadcast();
    }
}
