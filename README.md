# vault-guard-7702

An enterprise-grade, highly secure Solidity implementation contract designed to transform standard Externally Owned Accounts (EOAs) into programmable, compliant smart wallets using **EIP-7702 persistent delegation**.

## 🚀 Overview

`vault-guard-7702` provides a robust architecture for financial institutions and non-custodial digital asset platforms to inject institutional guards (such as multi-signature compliance, transaction limits, and sponsored or alternative gas mechanics) directly into traditional EOAs without requiring complex contract wallet migrations.

By signing a persistent EIP-7702 delegation, a user's EOA points to this implementation, gaining immediate access to secure, meta-transaction-driven execution.

## 🔑 Key Mechanism: Signed Multi-Call & Flexible Gas Abstraction

The core execution vector of this vault relies on custom cryptographic signature verification (`signedMessage`) to abstract transaction execution and native gas requirements. 

Instead of executing raw EVM calls directly, the user signs a standard cryptographic message containing the complete intent of the execution pipeline. This allows completely **gas-less UX** where users can pay transaction fees using any approved ERC-20 token (e.g., USDC, EURC, or tokenized deposits).

### Execution Payload Structure

Every execution request evaluates a cryptographic signature over the following parameters:

*   **`target`**: The recipient address of the intended transaction (e.g., a DeFi vault, payment gateway, or clearing house).
*   **`calldata`**: The raw hex-encoded data payload to be executed at the target address.
*   **`feeToken`**: The address of the designated ERC-20 token used to settle the execution fee.
*   **`fee`**: The exact amount of `feeToken` dedicated to compensating the execution relayer.
*   **`nonce`**: A monotonic transaction replay-protection counter tied to the delegated EOA.
*   **`deadline`**: A Unix timestamp marking the strict expiration threshold of the signature.

### Protocol Flow
```
[User EOA]
│
│ 1. Signs Intent (Target, Calldata, FeeToken, Fee, Nonce)
▼
[Relayer / Message Sender]
│
│ 2. Broadcasts Transaction via executeSigned()
▼
[vault-guard-7702 (As EOA Code)]
│
│ 3. Verifies EIP-712 Signature & Nonce
│ 4. Transfers fee of feeToken to msg.sender (Relayer)
│ 5. Executes low-level atomic CALL to target with calldata
▼
[Target Contract / Ecosystem]
```
1. **Signature Creation**: The user generates an off-chain EIP-712 signature over the execution payload.
2. **Relay & Fee Settlement**: Any authorized relayer (`msg.sender`) submits this signature to the vault. Upon successful cryptographic verification, the contract automatically extracts the specified `fee` in `feeToken` from the user's balances and transfers it directly to the `msg.sender` to reimburse gas overhead.
3. **Atomic Execution**: The contract utilizes low-level assembly or secure call structures to execute the `calldata` against the `target` address within the same atomic transaction block.

## 🛡️ Enterprise Security Features

*   **EIP-712 Compliance**: Secure structured data hashing preventing malicious front-running and cross-domain signature replays.
*   **Strict Nonce Tracking**: Custom sequential mapping guarding against transaction double-execution or out-of-order execution states.
*   **Decoupled Gas Architecture**: Completely isolates end-user compliance from the immediate availability of native base-chain gas tokens ($ETH$).

## 🛠️ Development & Testing

This project is built using **Foundry**.

```bash
# Clone the repository
git clone [https://github.com/harpy-wings/vault-guard-7702.git](https://github.com/harpy-wings/vault-guard-7702.git)

# Install dependencies
forge install

# Run the test suite (including EIP-7702 simulation tests)
forge test