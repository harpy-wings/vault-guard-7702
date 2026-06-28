// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script, console2} from "forge-std/Script.sol";
import {StdConstants} from "forge-std/StdConstants.sol";
import {VaultGuard7702} from "../src/VaultGuard7702.sol";

/**
 * @title VaultGuard7702Script
 * @notice CREATE2 deployment script for the VaultGuard7702 implementation.
 * @dev Foundry routes `new Contract{salt:}` through the canonical CREATE2 deployer
 *      (`0x4e59b44847b379578588920cA78FbF26c0B4956C`). Address prediction and `cast create2`
 *      mining must therefore use the same deployer (defaulting to that factory).
 *
 *      If CREATE2_SALT is missing or does not resolve to CREATE2_TARGET_ADDRESS, the script logs
 *      `cast create2` mining commands and exits without deploying.
 *
 * Environment variables:
 *   CREATE2_SALT              (required) bytes32 hex salt for CREATE2 deployment
 *   CREATE2_DEPLOYER          (optional) CREATE2 deployer; defaults to Foundry's CREATE2 factory
 *   CREATE2_TARGET_ADDRESS    (optional) required predicted deployment address the salt must produce
 */
contract VaultGuard7702Script is Script {
    bytes32 internal constant ZERO_SALT = bytes32(0);

    function run() external {
        bytes32 initCodeHash = keccak256(type(VaultGuard7702).creationCode);
        address deployer = _resolveDeployer();
        bytes32 salt = _readSalt();
        address targetAddress = vm.envOr("CREATE2_TARGET_ADDRESS", address(0));

        if (salt == ZERO_SALT) {
            _logSaltUnavailable("CREATE2_SALT is not set.", initCodeHash, deployer, targetAddress);
            return;
        }

        address predicted = vm.computeCreate2Address(salt, initCodeHash, deployer);

        if (targetAddress != address(0) && predicted != targetAddress) {
            _logSaltUnavailable(
                "CREATE2_SALT does not produce CREATE2_TARGET_ADDRESS for the configured deployer.",
                initCodeHash,
                deployer,
                targetAddress
            );
            console2.log("Provided salt:", vm.toString(salt));
            console2.log("Predicted address:", predicted);
            console2.log("Msg.sender:", msg.sender);
            console2.log("Expected target:", targetAddress);
            return;
        }

        if (predicted.code.length != 0) {
            console2.log("VaultGuard7702 already deployed at predicted CREATE2 address.");
            console2.log("Address:", predicted);
            console2.log("Salt:", vm.toString(salt));
            console2.log("Deployer:", deployer);
            console2.log("Msg.sender:", msg.sender);
            return;
        }

        vm.startBroadcast();

        VaultGuard7702 implementation = new VaultGuard7702{salt: salt}();
        address deployed = address(implementation);

        vm.stopBroadcast();

        if (deployed != predicted) {
            revert("CREATE2 deployment address mismatch");
        }

        console2.log("VaultGuard7702 deployed via CREATE2.");
        console2.log("Address:", deployed);
        console2.log("Salt:", vm.toString(salt));
        console2.log("Deployer:", deployer);
        console2.log("Msg.sender:", msg.sender);
        console2.log("Init code hash:", vm.toString(initCodeHash));
    }

    function _resolveDeployer() internal view returns (address deployer) {
        return vm.envOr("CREATE2_DEPLOYER", StdConstants.CREATE2_FACTORY);
    }

    function _readSalt() internal view returns (bytes32 salt) {
        if (!vm.envExists("CREATE2_SALT")) {
            return ZERO_SALT;
        }

        return vm.envBytes32("CREATE2_SALT");
    }

    function _logSaltUnavailable(string memory reason, bytes32 initCodeHash, address deployer, address targetAddress)
        internal
        view
    {
        console2.log("");
        console2.log("=== CREATE2 salt unavailable ===");
        console2.log(reason);
        console2.log("");
        console2.log("Init code hash:", vm.toString(initCodeHash));
        console2.log("Deployer:", vm.toString(deployer));

        if (targetAddress != address(0)) {
            console2.log("Target address:", vm.toString(targetAddress));
        }

        console2.log("");
        console2.log("1) Inspect init code hash locally (must match before mining):");
        console2.log("   forge inspect VaultGuard7702 bytecode | xargs cast keccak");
        console2.log("");
        console2.log("2) Verify a candidate salt resolves to an address:");
        console2.log(
            string.concat(
                "   cast create2 --salt <SALT> --init-code-hash ",
                vm.toString(initCodeHash),
                " --deployer ",
                vm.toString(deployer)
            )
        );
        console2.log("");
        console2.log("3) Mine a salt with cast (pick one filter):");

        if (targetAddress != address(0)) {
            console2.log(
                string.concat(
                    "   cast create2 --init-code-hash ",
                    vm.toString(initCodeHash),
                    " --deployer ",
                    vm.toString(deployer),
                    " --matching ",
                    vm.toString(targetAddress)
                )
            );
        } else {
            console2.log(
                string.concat(
                    "   cast create2 --init-code-hash ",
                    vm.toString(initCodeHash),
                    " --deployer ",
                    vm.toString(deployer),
                    " --starts-with 0x000000000000000000000000"
                )
            );
            console2.log(
                string.concat(
                    "   cast create2 --init-code-hash ",
                    vm.toString(initCodeHash),
                    " --deployer ",
                    vm.toString(deployer),
                    " --ends-with 0000"
                )
            );
        }

        console2.log("");
        console2.log("4) Export the mined salt and re-run deployment:");
        console2.log(
            "   CREATE2_SALT=<mined_salt> forge script script/VaultGuard7702.s.sol:VaultGuard7702Script --rpc-url $RPC_URL --broadcast"
        );
        console2.log("");
    }
}
