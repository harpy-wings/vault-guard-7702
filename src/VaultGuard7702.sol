// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {NonceStorage} from "./types/NonceStorage.sol";
import {IVaultGuard7702} from "./interfaces/IVaultGuard7702.sol";

/**
 * @title VaultGuard7702
 * @notice Institutional-grade execution guard and gas-sponsorship gateway for EOAs under EIP-7702 delegation.
 * @dev When an EOA delegates to this implementation, relayers submit signed execution intents that
 *      atomically (1) perform an arbitrary call on behalf of the EOA and (2) optionally reimburse the
 *      relayer in an approved ERC-20 token. Signature verification uses a stateless, per-call EIP-712
 *      domain separator so `verifyingContract` always resolves to the delegating EOA at execution time.
 *
 *      Storage is namespaced via ERC-7201 to avoid collisions with native EOA storage or future modules.
 *      Reentrancy protection uses OpenZeppelin `ReentrancyGuardTransient` (EIP-1153 `TSTORE`) so guard
 *      state never occupies persistent EOA storage slots.
 */
contract VaultGuard7702 is ReentrancyGuardTransient, IVaultGuard7702 {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    /// @dev ERC-7201 slot: `keccak256(abi.encode(uint256(keccak256("vaultguard7702.storage.NonceStorage.v1")) - 1)) & ~bytes32(uint256(0xff))`.
    /// Namespacing under `vaultguard7702` isolates replay state from the EOA's own storage layout.
    bytes32 private constant STORAGE_LOCATION =
        keccak256(abi.encode(uint256(keccak256("vaultguard7702.storage.NonceStorage.v1")) - 1)) & ~bytes32(uint256(0xff));

    /// @dev EIP-712 `EIP712Domain` type hash per EIP-712 specification.
    bytes32 private constant TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @dev Pre-hashed EIP-712 domain `name` field for `VaultGuard7702`.
    bytes32 private constant HASHED_NAME = keccak256(bytes("VaultGuard7702"));

    /// @dev Pre-hashed EIP-712 domain `version` field.
    bytes32 private constant HASHED_VERSION = keccak256(bytes("1"));

    /// @dev EIP-712 type hash for the `Execute` struct signed by the delegating EOA.
    bytes32 private constant EXECUTE_TYPEHASH =
        keccak256("Execute(address target,bytes data,address feeToken,uint256 feeAmount,uint256 nonce,uint256 value,uint256 deadline)");

    /**
     * @notice Deploys the VaultGuard7702 implementation contract.
     * @dev The implementation is intended to be referenced by EOAs through EIP-7702 delegation rather
     *      than invoked directly as a standalone wallet. No initialization is required.
     */
    constructor() {}

    /**
     * @notice Ensures each nonce is consumed at most once before the guarded body executes.
     * @dev Nonces are tracked in ERC-7201 namespaced storage so replay state remains scoped to this module.
     * @param nonce The caller-supplied replay-protection nonce.
     */
    modifier validNonce(uint256 nonce) {
        NonceStorage storage s = _getStorage();
        if (s.executed[nonce]) {
            revert NonceAlreadyUsed(nonce);
        }
        s.executed[nonce] = true;
        _;
    }

    /**
     * @notice Rejects execution when the signed deadline has passed.
     * @dev A signature is valid while `block.timestamp <= deadline`. The check uses strict
     *      greater-than so a deadline equal to the current block timestamp remains executable.
     * @param deadline Unix timestamp through which the signed intent remains valid.
     */
    modifier validDeadline(uint256 deadline) {
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp > deadline) {
            revert DeadlineExpired(deadline);
        }
        _;
    }

    /**
     * @notice Validates an EIP-712 signature supplied as a compact byte array.
     * @param target The call destination encoded in the signed struct.
     * @param data The call calldata encoded in the signed struct.
     * @param feeToken The fee token address encoded in the signed struct.
     * @param feeAmount The fee amount encoded in the signed struct.
     * @param nonce The replay-protection nonce encoded in the signed struct.
     * @param value The native ETH amount in wei encoded in the signed struct.
     * @param deadline The Unix timestamp expiry encoded in the signed struct.
     * @param signature The secp256k1 signature over the typed data hash.
     */
    modifier validSignatureBytes(
        address target,
        bytes calldata data,
        address feeToken,
        uint256 feeAmount,
        uint256 nonce,
        uint256 value,
        uint256 deadline,
        bytes calldata signature
    ) {
        if (!_verifySignature(target, data, feeToken, feeAmount, nonce, value, deadline, signature)) {
            revert InvalidSignature();
        }
        _;
    }

    /**
     * @notice Validates an EIP-712 signature supplied as an explicit `(v, r, s)` tuple.
     * @param target The call destination encoded in the signed struct.
     * @param data The call calldata encoded in the signed struct.
     * @param feeToken The fee token address encoded in the signed struct.
     * @param feeAmount The fee amount encoded in the signed struct.
     * @param nonce The replay-protection nonce encoded in the signed struct.
     * @param value The native ETH amount in wei encoded in the signed struct.
     * @param deadline The Unix timestamp expiry encoded in the signed struct.
     * @param v The secp256k1 recovery id.
     * @param r The `r` component of the signature.
     * @param s The `s` component of the signature.
     */
    modifier validSignatureVRS(
        address target,
        bytes calldata data,
        address feeToken,
        uint256 feeAmount,
        uint256 nonce,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) {
        if (!_verifySignatureVRS(target, data, feeToken, feeAmount, nonce, value, deadline, v, r, s)) {
            revert InvalidSignature();
        }
        _;
    }

    // -------------------------------------------------------------------------
    // Receive & Fallback
    // -------------------------------------------------------------------------

    /**
     * @notice Accepts native asset transfers sent directly to the delegated EOA.
     * @dev Required so the EOA can hold ETH while operating under this implementation.
     */
    receive() external payable {}

    /**
     * @notice Accepts plain-value calls with empty calldata routed to the delegated EOA.
     */
    fallback() external payable {}

    // -------------------------------------------------------------------------
    // External Functions
    // -------------------------------------------------------------------------

    /**
     * @inheritdoc IVaultGuard7702
     */
    function execute(
        address target,
        bytes calldata data,
        address feeToken,
        uint256 feeAmount,
        uint256 nonce,
        uint256 value,
        uint256 deadline,
        bytes calldata signature
    )
        external
        payable
        validDeadline(deadline)
        validSignatureBytes(target, data, feeToken, feeAmount, nonce, value, deadline, signature)
        validNonce(nonce)
        nonReentrant
        returns (bytes memory)
    {
        return _execute(target, data, feeToken, feeAmount, nonce, value);
    }

    /**
     * @inheritdoc IVaultGuard7702
     */
    function execute(
        address target,
        bytes calldata data,
        address feeToken,
        uint256 feeAmount,
        uint256 nonce,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    )
        external
        payable
        validDeadline(deadline)
        validSignatureVRS(target, data, feeToken, feeAmount, nonce, value, deadline, v, r, s)
        validNonce(nonce)
        nonReentrant
        returns (bytes memory)
    {
        return _execute(target, data, feeToken, feeAmount, nonce, value);
    }

    // -------------------------------------------------------------------------
    // Internal Functions — state-changing
    // -------------------------------------------------------------------------

    /**
     * @notice Performs the guarded call and optional relayer fee settlement.
     * @dev Execution order is call-first, fee-second so a reverting target aborts before any ERC-20
     *      transfer. The low-level call forwards the EIP-712-authorized `value` from the delegated EOA
     *      balance rather than `msg.value`, binding native ETH outflow to the signed intent. Failed calls
     *      bubble the callee revert data through inline assembly so relayers observe the original error.
     * @param target The destination address for the low-level call.
     * @param data The calldata forwarded to `target`.
     * @param feeToken The ERC-20 token used to compensate the relayer.
     * @param feeAmount The amount of `feeToken` sent to `msg.sender` when non-zero.
     * @param nonce The replay-protection nonce consumed for this execution.
     * @param value The native ETH amount in wei authorized by the EIP-712 signature for the target call.
     * @return result The returndata returned by the successful call to `target`.
     */
    function _execute(address target, bytes calldata data, address feeToken, uint256 feeAmount, uint256 nonce, uint256 value)
        internal
        returns (bytes memory)
    {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            // Bubble the callee revert payload verbatim: copy returndata into memory and re-revert with it.
            assembly {
                let size := returndatasize()
                returndatacopy(0, 0, size)
                revert(0, size)
            }
        }

        if (feeAmount > 0) {
            IERC20(feeToken).safeTransfer(msg.sender, feeAmount);
        }

        emit Executed(target, data, feeToken, feeAmount, msg.sender, nonce, result);
        return result;
    }

    // -------------------------------------------------------------------------
    // Internal Functions — view / pure
    // -------------------------------------------------------------------------

    /**
     * @notice Returns a storage pointer to the ERC-7201 namespaced `NonceStorage` struct.
     * @dev ERC-7201 assigns a fixed, collision-resistant slot so this module's replay map never
     *      overlaps native EOA storage or storage used by other delegated implementations.
     * @return s The namespaced `NonceStorage` reference bound to `STORAGE_LOCATION`.
     */
    function _getStorage() internal pure returns (NonceStorage storage s) {
        bytes32 slot = STORAGE_LOCATION;
        assembly {
            s.slot := slot
        }
    }

    /**
     * @notice Computes the EIP-712 domain separator at execution time.
     * @dev Unlike OpenZeppelin's static `EIP712` base, this rebuilds the separator on every call using
     *      the live `address(this)`. Under EIP-7702 delegation, `address(this)` equals the user's EOA,
     *      binding signatures to that EOA and preventing cross-user replay across delegated accounts.
     * @return domainSeparator The EIP-712 domain separator for the current chain and verifying contract.
     */
    function _buildDomainSeparator() internal view returns (bytes32 domainSeparator) {
        return keccak256(abi.encode(TYPE_HASH, HASHED_NAME, HASHED_VERSION, block.chainid, address(this)));
    }

    /**
     * @notice Applies the EIP-712 `\x19\x01` prefix to a struct hash using the dynamic domain separator.
     * @param structHash The keccak256 hash of the typed `Execute` struct per EIP-712 encoding rules.
     * @return digest The final EIP-712 digest presented to `ECDSA.recover`.
     */
    function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32 digest) {
        return keccak256(abi.encodePacked("\x19\x01", _buildDomainSeparator(), structHash));
    }

    /**
     * @notice Recovers the signer from a compact byte-encoded secp256k1 signature.
     * @dev Dynamic `bytes` fields in EIP-712 are hashed in the struct encoding; `keccak256(data)` is
     *      therefore applied to `data` before it is combined with the type hash and static fields.
     * @param target The signed call destination.
     * @param data The signed call calldata.
     * @param feeToken The signed fee token address.
     * @param feeAmount The signed fee amount.
     * @param nonce The signed replay-protection nonce.
     * @param value The signed native ETH amount in wei authorized for the target call.
     * @param deadline The signed Unix timestamp expiry for the intent.
     * @param signature The compact ECDSA signature bytes.
     * @return isValid True when recovery yields the delegating EOA (`address(this)`).
     */
    function _verifySignature(
        address target,
        bytes calldata data,
        address feeToken,
        uint256 feeAmount,
        uint256 nonce,
        uint256 value,
        uint256 deadline,
        bytes calldata signature
    ) internal view returns (bool isValid) {
        bytes32 structHash = keccak256(
            abi.encode(
                EXECUTE_TYPEHASH,
                target,
                keccak256(data),
                feeToken,
                feeAmount,
                nonce,
                value,
                deadline
            )
        );

        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(hash, signature);

        return signer == address(this);
    }

    /**
     * @notice Recovers the signer from an explicit `(v, r, s)` secp256k1 signature tuple.
     * @dev Dynamic `bytes` fields in EIP-712 are hashed in the struct encoding; `keccak256(data)` is
     *      therefore applied to `data` before it is combined with the type hash and static fields.
     * @param target The signed call destination.
     * @param data The signed call calldata.
     * @param feeToken The signed fee token address.
     * @param feeAmount The signed fee amount.
     * @param nonce The signed replay-protection nonce.
     * @param value The signed native ETH amount in wei authorized for the target call.
     * @param deadline The signed Unix timestamp expiry for the intent.
     * @param v The secp256k1 recovery id.
     * @param r The `r` component of the signature.
     * @param s The `s` component of the signature.
     * @return isValid True when recovery yields the delegating EOA (`address(this)`).
     */
    function _verifySignatureVRS(
        address target,
        bytes calldata data,
        address feeToken,
        uint256 feeAmount,
        uint256 nonce,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal view returns (bool isValid) {
        bytes32 structHash = keccak256(
            abi.encode(
                EXECUTE_TYPEHASH,
                target,
                keccak256(data),
                feeToken,
                feeAmount,
                nonce,
                value,
                deadline
            )
        );

        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(hash, v, r, s);

        return signer == address(this);
    }
}
