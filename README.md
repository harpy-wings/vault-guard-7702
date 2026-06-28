# VaultGuard7702

[![CI](https://github.com/harpy-wings/vault-guard-7702/actions/workflows/test.yml/badge.svg)](https://github.com/harpy-wings/vault-guard-7702/actions/workflows/test.yml)

An institutional-grade, EIP-7702–native execution guard and gas-sponsorship gateway that transforms standard Externally Owned Accounts (EOAs) into programmable, policy-enforceable smart wallets through **persistent delegation**—without migrating user funds to a separate contract wallet.

---

## Project Overview

`VaultGuard7702` is a single, auditable implementation contract designed for financial institutions, custodians, and non-custodial platforms that need to inject compliance controls, multi-party authorization, and flexible fee settlement directly into user EOAs.

When a user signs an [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) delegation, their EOA's code pointer references this implementation. From that moment, the EOA can:

1. **Authorize arbitrary calls** via off-chain EIP-712 signatures rather than on-chain EOAs signing every transaction directly.
2. **Compensate relayers in ERC-20** (USDC, EURC, tokenized deposits, etc.) instead of requiring users to hold native gas tokens.
3. **Enforce replay protection** through per-EOA nonce tracking stored in an ERC-7201 namespaced slot that cannot collide with native EOA storage.
4. **Bind native ETH outflow** by including an explicit `value` field in the signed payload, preventing relayers from attaching unauthorized ETH to guarded calls.
5. **Expire stale intents** through a signed `deadline` timestamp checked on-chain before execution.

Relayers (or institutional broadcasters) submit signed intents to `execute`. The contract validates the deadline, verifies cryptography, consumes the nonce, performs the target call atomically, and optionally transfers a pre-agreed ERC-20 fee to `msg.sender`.

---

## The Core Architectural Challenge & Solution

### Why OpenZeppelin's Static `EIP712` Base Cannot Be Used

OpenZeppelin's standard `EIP712` contract computes and **caches** the domain separator at construction (or initialization) time:

```solidity
// Simplified OZ pattern — unsuitable for EIP-7702 delegation
_cachedDomainSeparator = keccak256(
    abi.encode(TYPE_HASH, _hashedName, _hashedVersion, block.chainid, address(this))
);
```

At deployment, `address(this)` is the **implementation contract's address**—for example `0xImpl…`.

Under **EIP-7702 persistent delegation**, the same bytecode executes in the **context of the user's EOA**. Every external call, every `address(this)` reference, and every storage read/write operates as if the implementation logic lived at the EOA address—for example `0xAlice…`.

If the domain separator were cached at deployment:

| Phase | `address(this)` | Cached `verifyingContract` |
|---|---|---|
| Implementation deploy | `0xImpl…` | `0xImpl…` |
| Delegated execution on Alice's EOA | `0xAlice…` | still `0xImpl…` (stale) |

Signature verification would compare against a domain bound to `0xImpl…` while the user signed expecting `0xAlice…`. **Every signature would fail.** Worse, if verification were accidentally loosened, a signature crafted for one delegated EOA could become replayable across others sharing the same implementation address.

This is not a minor integration detail—it is a fundamental mismatch between **singleton implementation deployment** and **per-EOA execution context**.

### Our Solution: Stateless / Dynamic On-the-Fly EIP-712 Domain Calculation

`VaultGuard7702` **never caches** the domain separator. On every verification path it recomputes:

```solidity
keccak256(abi.encode(
    TYPE_HASH,
    HASHED_NAME,
    HASHED_VERSION,
    block.chainid,
    address(this)   // resolves to the delegating EOA at execution time
));
```

Because `address(this)` is evaluated at call time under EIP-7702, `verifyingContract` in the EIP-712 domain always equals the **user's EOA address**.

#### Security properties this enables

**Cross-user replay protection.** A signature authorizing `target`, `data`, `feeToken`, `feeAmount`, `nonce`, `value`, and `deadline` is cryptographically bound to exactly one EOA. Even if two users delegate to the same implementation, identical struct fields produce different EIP-712 digests because `verifyingContract` differs. Alice cannot replay Bob's signed intent and vice versa.

**Chain isolation.** `block.chainid` is included in the domain, preventing cross-chain replay of otherwise identical payloads.

**Time-bounded intents.** The signed `deadline` prevents delayed submission of stale approvals after market, policy, or session conditions have changed.

**Native-value authorization.** The signed `value` field binds the exact wei amount forwarded to `target`, preventing relayers from altering ETH outflow independently of the user's signature.

**Implementation agnosticism.** Users sign against their own address as verifying contract, which is the semantically correct EIP-712 model for "I, this EOA, authorize this action."

**Off-chain / on-chain parity.** Wallets and relayers derive the same domain separator by supplying the user's EOA as `verifyingContract` and the known domain `name` (`VaultGuard7702`), `version` (`1`), and chain ID—matching on-chain recomputation exactly.

### EIP-712 Struct Encoding Note

The signed `Execute` struct includes a dynamic `bytes data` field. Per EIP-712, dynamic types are hashed before struct encoding:

```
structHash = keccak256(abi.encode(
    EXECUTE_TYPEHASH,
    target,
    keccak256(data),   // not keccak256(abi.encodePacked(data)) in struct position
    feeToken,
    feeAmount,
    nonce,
    value,
    deadline
));
```

Off-chain signers must mirror this encoding precisely.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         User EOA (0xAlice…)                     │
│  EIP-7702 delegation → VaultGuard7702 implementation code       │
│  Holds ETH + ERC-20 balances natively at 0xAlice…               │
└───────────────────────────────┬─────────────────────────────────┘
                                │
        1. User signs EIP-712 Execute struct off-chain
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Relayer / Institution (msg.sender)           │
│  Submits execute(..., nonce, value, deadline, sig)              │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     VaultGuard7702 logic @ 0xAlice…             │
│  • Reject if block.timestamp > deadline                         │
│  • Recompute domain separator (verifyingContract = 0xAlice…)    │
│  • Verify signature recovers to 0xAlice…                        │
│  • Consume nonce in ERC-7201 namespaced storage                 │
│  • CALL target with data and signed value (from EOA balance)    │
│  • safeTransfer feeToken to relayer if feeAmount > 0            │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
                        Target protocol / counterparty
```

---

## Security Features

### ReentrancyGuardTransient (EIP-1153 TSTORE)

Reentrancy protection uses OpenZeppelin's `ReentrancyGuardTransient`, which stores the guard flag in **transient storage** (`TSTORE` / `TLOAD`) introduced by EIP-1153 rather than a persistent EOA storage slot.

This matters for EIP-7702 because persistent storage on a delegated EOA is shared with anything else the EOA might store. Transient storage is scoped to the current transaction and cleared afterward, giving robust reentrancy protection without consuming permanent storage footprint or risking collision with user data.

### ERC-7201 Namespaced Storage

Replay-protection state (`executed[nonce]`) lives at a deterministic slot derived from the namespace:

```
vaultguard7702.storage.NonceStorage.v1
```

ERC-7201 prevents storage collision with:

- Native EOA storage (nonce, balance, code delegation fields).
- Future upgrade modules or additional delegated logic.
- Other namespaced libraries that follow the same standard.

Access is performed through `_getStorage()`, which binds a `NonceStorage` struct to the fixed slot via inline assembly.

### Low-Level Revert Bubbling

When the guarded `target.call` fails, the contract does not swallow the error. Inline assembly copies the callee's returndata and reverts with it verbatim:

```solidity
assembly {
    let size := returndatasize()
    returndatacopy(0, 0, size)
    revert(0, size)
}
```

Relayers, simulation tooling, and indexers therefore observe the **original revert reason** from the target contract, which is essential for production debugging and user-facing error reporting.

### Additional Properties

| Control | Mechanism |
|---|---|
| Replay protection | Single-use `nonce` mapping in namespaced storage |
| Signature binding | EIP-712 with dynamic per-EOA domain separator |
| Intent expiry | Signed `deadline` checked before signature and nonce validation |
| Native value binding | Signed `value` forwarded to `target` from the EOA balance |
| Fee settlement ordering | Target call executes before ERC-20 fee transfer |
| Token safety | OpenZeppelin `SafeERC20` for fee transfers |
| Validation ordering | Deadline and signature checked before nonce consumption |

---

## EIP-712 Domain & Types

**Domain**

| Field | Value |
|---|---|
| `name` | `VaultGuard7702` |
| `version` | `1` |
| `chainId` | Current chain ID |
| `verifyingContract` | User's delegated EOA address |

**Primary type: `Execute`**

```solidity
Execute(
    address target,
    bytes data,
    address feeToken,
    uint256 feeAmount,
    uint256 nonce,
    uint256 value,
    uint256 deadline
)
```

**Type hash**

```
keccak256("Execute(address target,bytes data,address feeToken,uint256 feeAmount,uint256 nonce,uint256 value,uint256 deadline)")
```

---

## Contract API

Both overloads share identical semantics; they differ only in signature encoding.

```solidity
function execute(
    address target,
    bytes calldata data,
    address feeToken,
    uint256 feeAmount,
    uint256 nonce,
    uint256 value,
    uint256 deadline,
    bytes calldata signature
) external payable returns (bytes memory result);

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
) external payable returns (bytes memory result);
```

**Errors**

- `NonceAlreadyUsed(uint256 nonce)` — the supplied nonce was already consumed for this EOA.
- `InvalidSignature()` — recovered signer is not the delegating EOA.
- `DeadlineExpired(uint256 deadline)` — `block.timestamp` exceeds the signed deadline.

**Events**

- `Executed(target, data, feeToken, feeAmount, feeRecipient, nonce, result)` — emitted after successful execution and optional fee transfer.

---

## Repository Layout

```
.github/workflows/
└── test.yml                    # CI: fmt, build, test, coverage
src/
├── VaultGuard7702.sol          # Core implementation
├── interfaces/
│   └── IVaultGuard7702.sol     # External API, errors, and events
└── types/
    └── NonceStorage.sol        # ERC-7201 namespaced storage struct
test/
└── VaultGuard7702.t.sol        # Foundry test suite (23 tests + fuzz)
script/
└── VaultGuard7702.s.sol        # Deployment script
lib/
├── forge-std/                  # Foundry standard library (submodule)
└── openzeppelin-contracts/     # OpenZeppelin Contracts (submodule)
```

---

## Getting Started

### Prerequisites

| Tool | Version |
|---|---|
| [Foundry](https://book.getfoundry.sh/getting-started/installation) | latest stable |
| Solidity | `0.8.26` (pinned in `foundry.toml`) |
| EVM | `cancun` (EIP-1153 transient storage, EIP-7702 test helpers) |

### Clone & install

```bash
git clone --recursive https://github.com/harpy-wings/vault-guard-7702.git
cd vault-guard-7702
```

If you already cloned without submodules:

```bash
git submodule update --init --recursive
```

Install or update Foundry dependencies:

```bash
forge install
```

### Build

```bash
forge build
```

### Test

```bash
# Run the full suite (23 unit/integration tests + 256 fuzz runs)
forge test

# Verbose output
forge test -vvv

# Match a naming pattern
forge test --match-test test_RevertIf_
```

### Coverage

```bash
forge coverage --ir-minimum --report summary
```

The `--ir-minimum` flag is required because production builds enable `via_ir`; it avoids stack-depth issues during coverage instrumentation.

### Format

```bash
# Apply formatting
forge fmt

# CI check (no writes)
forge fmt --check
```

### Gas snapshots

```bash
forge snapshot
```

---

## Test Suite

`test/VaultGuard7702.t.sol` provides production-grade coverage of the guard's security boundaries:

| Category | Examples |
|---|---|
| EIP-7702 context | `vm.signAndAttachDelegation`, `vm.etch` delegation simulation |
| EIP-712 signing | Bytes and `(v, r, s)` `execute` success paths |
| Cross-user replay | Signature for User A rejected on User B's EOA |
| Nonce replay | Second call with same nonce reverts `NonceAlreadyUsed` |
| Deadline | Expired and boundary (`deadline == block.timestamp`) cases |
| Fee settlement | ERC-20 relayer compensation and zero-fee gas sponsorship |
| Revert bubbling | Custom errors and string reverts propagated verbatim |
| Reentrancy | Transient guard blocks nested `execute` mid-flight |
| Fuzz | Randomized `feeAmount`, `nonce`, `value`, and calldata |

**Coverage targets (`VaultGuard7702.sol`):** 100% branches, 100% functions, ~89% lines (inline assembly blocks are not fully instrumented by Foundry's coverage tool).

---

## Continuous Integration

Every push and pull request triggers [`.github/workflows/test.yml`](.github/workflows/test.yml), which runs:

1. `forge fmt --check` — Solidity formatting
2. `forge build --sizes` — compilation and contract size report
3. `forge test -vvv` — full test suite
4. `forge coverage --ir-minimum --report summary` — coverage summary

Submodules are fetched recursively so CI matches local development.

---

## Deployment

`VaultGuard7702` is deployed via **CREATE2** so the implementation address is deterministic across chains (same init code hash, salt, and deployer).

Foundry routes `new VaultGuard7702{salt:}` through the canonical CREATE2 deployer `0x4e59b44847b379578588920cA78FbF26c0B4956C`. The script defaults to that address for prediction and for `cast create2` mining instructions.

### Canonical deployment — Ethereum Mainnet

The implementation is **live and verified** on Ethereum mainnet:

| Field | Value |
|---|---|
| **Network** | Ethereum Mainnet |
| **Address** | [`0x00000000484FB1DF9c6682ac252c103b23707c26`](https://etherscan.io/address/0x00000000484FB1DF9c6682ac252c103b23707c26#code) |
| **Etherscan** | [Verified source](https://etherscan.io/address/0x00000000484FB1DF9c6682ac252c103b23707c26#code) |
| **CREATE2 salt** | `0x200122f1f542c361b453b886778c2118b0b91c69bf51b645645e8168ac0a8819` |
| **CREATE2 deployer** | `0x4e59b44847b379578588920cA78FbF26c0B4956C` (Foundry / `cast` default) |

To reproduce **the same contract address on any other EVM chain**, deploy with the **exact same** init code (this repository's `VaultGuard7702` bytecode), **salt**, and **CREATE2 deployer** above. Set in `.env`:

```bash
CREATE2_SALT=0x200122f1f542c361b453b886778c2118b0b91c69bf51b645645e8168ac0a8819
CREATE2_TARGET_ADDRESS=0x00000000484FB1DF9c6682ac252c103b23707c26
```

Verify before broadcasting:

```bash
cast create2 \
  --salt 0x200122f1f542c361b453b886778c2118b0b91c69bf51b645645e8168ac0a8819 \
  --init-code-hash $(forge inspect VaultGuard7702 bytecode | xargs cast keccak) \
  --deployer 0x4e59b44847b379578588920cA78FbF26c0B4956C
# Expected: 0x00000000484FB1DF9c6682ac252c103b23707c26
```

> **Note:** The address is only guaranteed to match if the compiled init code hash is identical to mainnet (same Solidity version, optimizer settings, and source). Use `foundry.toml` from this repo without changes.

### Step 1 — Dry-run (no salt yet)

```bash
cp .env.example .env
# Optional: CREATE2_TARGET_ADDRESS=0x...  (vanity or fixed address you require)

forge script script/VaultGuard7702.s.sol:VaultGuard7702Script -vv
```

If `CREATE2_SALT` is missing (or does not match `CREATE2_TARGET_ADDRESS`), the script prints `cast create2` commands and **exits without deploying**.

### Step 2 — Mine a salt with `cast`

Use the init code hash and deployer printed by the script:

```bash
# Verify a candidate salt
cast create2 \
  --salt 0x<YOUR_SALT> \
  --init-code-hash $(forge inspect VaultGuard7702 bytecode | xargs cast keccak) \
  --deployer 0x4e59b44847b379578588920cA78FbF26c0B4956C

# Mine toward a prefix (example)
cast create2 \
  --init-code-hash $(forge inspect VaultGuard7702 bytecode | xargs cast keccak) \
  --deployer 0x4e59b44847b379578588920cA78FbF26c0B4956C \
  --starts-with 0x000000000000000000000000

# Mine toward an exact target address
cast create2 \
  --init-code-hash $(forge inspect VaultGuard7702 bytecode | xargs cast keccak) \
  --deployer 0x4e59b44847b379578588920cA78FbF26c0B4956C \
  --matching 0x<TARGET_ADDRESS>
```

Export the mined salt:

```bash
CREATE2_SALT=0x<MINED_SALT>
```

### Step 3 — Broadcast

```bash
source .env

forge script script/VaultGuard7702.s.sol:VaultGuard7702Script \
  --rpc-url "$RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  --broadcast \
  --verify \
  -vvvv
```

When the predicted CREATE2 address already holds bytecode, the script logs the existing deployment and skips broadcasting.

### Deployment model

1. Deploy `VaultGuard7702` once as a **shared implementation** at the CREATE2 address.
2. Users sign EIP-7702 authorization tuples pointing their EOA code to the implementation.
3. Relayers call `execute` **on the user's EOA address** (not the implementation address) with signed payloads.

The implementation address is public and reusable; security is derived from per-EOA signature domains and nonce state, not from hiding the bytecode.

---

## Dependencies

| Package | Purpose |
|---|---|
| [forge-std](https://github.com/foundry-rs/forge-std) | Foundry testing utilities and cheatcodes |
| [OpenZeppelin Contracts](https://github.com/OpenZeppelin/openzeppelin-contracts) | `ReentrancyGuardTransient`, `ECDSA`, `SafeERC20` |

Managed as Git submodules under `lib/` and remapped in `remappings.txt`.

---

## Environment Variables

Copy `.env.example` to `.env`:

| Variable | Purpose |
|---|---|
| `ETHERSCAN_API_KEY` | Contract verification on Etherscan |
| `RPC_URL` | Mainnet (or target chain) RPC for broadcast |
| `SRPC_URL` | Sepolia RPC (optional) |
| `PRIVATE_KEY` | Broadcaster key for `forge script --broadcast` |
| `CREATE2_SALT` | bytes32 hex salt (canonical mainnet: `0x200122f1f542c361b453b886778c2118b0b91c69bf51b645645e8168ac0a8819`) |
| `CREATE2_DEPLOYER` | CREATE2 deployer override (default: `0x4e59b44847b379578588920cA78FbF26c0B4956C`) |
| `CREATE2_TARGET_ADDRESS` | Optional required CREATE2 address (`0x00000000484FB1DF9c6682ac252c103b23707c26` on mainnet) |

---

## License

MIT
