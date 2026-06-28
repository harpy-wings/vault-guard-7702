// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {VaultGuard7702} from "../src/VaultGuard7702.sol";

contract VaultGuard7702Test is Test {
    VaultGuard7702 public vaultGuard7702;

    function setUp() public {
        vaultGuard7702 = new VaultGuard7702();
    }

    function test_DeploysImplementation() public view {
        assertTrue(address(vaultGuard7702).code.length > 0);
    }
}
