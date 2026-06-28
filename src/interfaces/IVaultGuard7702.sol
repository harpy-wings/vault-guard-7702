// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/**
 * @title IVaultGuard7702
 * @notice External API for the VaultGuard7702 EIP-7702 delegated execution guard.
 * @dev Defines the typed errors, events, and overloaded `execute` entry points consumed by
 *      relayers and institutional integrations. Signature payloads follow EIP-712 typed data
 *      with a dynamically computed domain separator bound to the delegating EOA.
 */
interface IVaultGuard7702 {
    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    /**
     * @notice Thrown when a signed execution attempt reuses an already-consumed nonce.
     * @param nonce The replayed nonce value supplied by the caller.
     */
    error NonceAlreadyUsed(uint256 nonce);

    /**
     * @notice Thrown when the supplied EIP-712 signature does not recover to the delegating EOA.
     * @dev The expected signer is always `address(this)` at execution time, which under
     *      EIP-7702 equals the user's EOA rather than the implementation's deployment address.
     */
    error InvalidSignature();

    /**
     * @notice Thrown when the signed deadline has expired.
     * @param deadline The expired Unix timestamp that was supplied with the execution intent.
     */
    error DeadlineExpired(uint256 deadline);

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /**
     * @notice Emitted after a signed call succeeds and optional relayer compensation is settled.
     * @param target The contract or account invoked by the guarded execution.
     * @param data The calldata forwarded to `target`.
     * @param feeToken The ERC-20 token used to compensate the relayer; `address(0)` when no fee is paid.
     * @param feeAmount The quantity of `feeToken` transferred to the relayer.
     * @param feeRecipient The relayer address that submitted the transaction (`msg.sender`).
     * @param nonce The consumed replay-protection nonce for this execution.
     * @param result The returndata produced by the successful low-level call to `target`.
     */
    event Executed(
        address indexed target,
        bytes data,
        address indexed feeToken,
        uint256 feeAmount,
        address indexed feeRecipient,
        uint256 nonce,
        bytes result
    );

    // -------------------------------------------------------------------------
    // External Functions
    // -------------------------------------------------------------------------

    /**
     * @notice Executes a user-signed call through the delegated EOA, compensating the relayer in ERC-20.
     * @param target The destination address for the guarded call.
     * @param data The calldata to forward to `target`; also forwarded as event metadata.
     * @param feeToken The ERC-20 token pulled from the EOA to pay the relayer when `feeAmount > 0`.
     * @param feeAmount The ERC-20 amount transferred to `msg.sender` upon success.
     * @param nonce A caller-supplied replay-protection nonce; each value may be used once per EOA.
     * @param value Native ETH in wei authorized by the signature for the target call.
     * @param deadline Unix timestamp through which the signature remains valid (`block.timestamp <= deadline`).
     * @param signature The EIP-712 secp256k1 signature authorizing this exact execution payload.
     * @return result The returndata from the successful call to `target`.
     */
    function execute(
        address target,
        bytes memory data,
        address feeToken,
        uint256 feeAmount,
        uint256 nonce,
        uint256 value,
        uint256 deadline,
        bytes calldata signature
    ) external payable returns (bytes memory);

    /**
     * @notice Executes a user-signed call using an explicit `(v, r, s)` signature tuple.
     * @param target The destination address for the guarded call.
     * @param data The calldata to forward to `target`.
     * @param feeToken The ERC-20 token pulled from the EOA to pay the relayer when `feeAmount > 0`.
     * @param feeAmount The ERC-20 amount transferred to `msg.sender` upon success.
     * @param nonce A caller-supplied replay-protection nonce; each value may be used once per EOA.
     * @param value Native ETH in wei authorized by the signature for the target call.
     * @param deadline Unix timestamp through which the signature remains valid (`block.timestamp <= deadline`).
     * @param v The secp256k1 recovery id of the authorizing signature.
     * @param r The `r` component of the authorizing signature.
     * @param s The `s` component of the authorizing signature.
     * @return result The returndata from the successful call to `target`.
     */
    function execute(
        address target,
        bytes memory data,
        address feeToken,
        uint256 feeAmount,
        uint256 nonce,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external payable returns (bytes memory);
}
