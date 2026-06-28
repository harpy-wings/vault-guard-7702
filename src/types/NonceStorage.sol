// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/**
 * @title NonceStorage
 * @notice ERC-7201 namespaced storage layout for VaultGuard7702 replay protection.
 * @dev Isolated from the EOA's native storage and any future upgradeable logic by living
 *      at a deterministic ERC-7201 slot derived from the `walletguard7702` namespace.
 */
struct NonceStorage {
    /// @notice Reserved sequential nonce counter for future monotonic nonce schemes.
    uint256 nonce;
    /// @notice Maps a user-chosen nonce to a consumed flag to prevent signature replay.
    mapping(uint256 => bool) executed;
}
