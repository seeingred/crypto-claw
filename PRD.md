# PRD: MPC-TSS Crypto Signing Service

## Context

A crypto prediction market bot runs on an internet-exposed server considered vulnerable to compromise. The bot needs to sign transactions across multiple blockchains (both ECDSA and EdDSA curves). Private keys stored on the exposed machine can be stolen.

This system eliminates that risk by splitting signing capability across two independent servers using Multi Party Computation Threshold Signature Scheme (MPC-TSS). Neither server alone can produce a valid signature. The secure server enforces transaction validation before co-signing.

The AI bot is **out of scope** — it is a consumer of this system via a local API.

---

## System Overview

```
                          ┌────────────────────────────────────┐
                          │         AI SERVER (exposed)         │
  ┌──────────┐   REST     │                                    │
  │  AI Bot  │───────────►│   TSS Signer Service (Party A)     │
  │          │            │   - Stores public keys & paths     │
  │ (out of  │  localhost │   - Receives sign requests         │
  │  scope)  │◄───────────│   - Constructs chain-specific txs  │
  └──────────┘            │   - Initiates TSS protocol         │
       │                  │   - Returns signed tx to bot       │
       │                  └───────────────┬────────────────────┘
       │                                  │ mutual TLS
       │                                  │
       │                  ┌───────────────┴────────────────────┐
       │                  │      SECURE SERVER (hardened)        │
       │                  │                                     │
       │                  │   TSS Co-signer Service (Party B)   │
       │                  │   - Receives signing requests       │
       │                  │   - Runs TX analyzer AI             │
       │                  │   - Co-signs or rejects             │
       │                  │   - Escalates uncertain txs to user │
       │                  └─────────────────────────────────────┘
       │
       │  Bot broadcasts signed tx to chain RPC
       ▼
  ┌──────────┐
  │Blockchain│
  └──────────┘
```

---

## Components

### 1. TSS Signer Service (Party A) — runs on AI server

**Purpose**: Accept signing requests from the bot, handle chain-specific transaction construction, initiate TSS signing with the secure server, return the signed transaction to the bot. Store public keys, derived paths, and addresses.

**API** (localhost only, not exposed to network):

```
POST /sign
{
  "vm": "evm" | "solana" | "tendermint",
  "chain": "<ticker of the chain>",
  "unsignedTx": "<base64 encoded unsigned transaction>",
  "to": ["<address>"],
  "derivationPath": "m/44'/60'/0'/0/0"
}
→ { "signedTx": "<base64 encoded signed transaction>", "status": "signed" }

GET /keys
→ { "chains": { "eth": { "address": "0x...", "pubKey": "0x..." }, "sol": { "address": "So1...", "pubKey": "..." }, ... } }

GET /health
→ { "status": "ok", "secureServerConnected": true }
```

**Responsibilities**:
- Expose localhost-only REST API
- VM adapters: construct unsigned transactions per VM
- Manage nonces and sequence numbers
- Derive child key shares for requested chain (HD derivation via tss-lib)
- Initiate TSS signing protocol with Party B
- Assemble final signed transaction
- Return signed transaction to the bot (bot decides whether and when to broadcast)
- Store and serve public key / address / derivation path info
- Serve web UI for viewing keys and transaction history

**Does NOT do**:
- Transaction validation (that's Party B)
- Store full private keys (only its share)
- Expose API to the network
- Broadcast transactions (that's the bot's responsibility)

---

### 2. TSS Co-signer Service (Party B) — runs on secure server

**Purpose**: Participate in TSS signing only after validating the transaction using AI-driven analysis and deterministic ABI checks.

**Inbound interface** (mutual TLS, accepts connections only from Party A):

```
// TSS protocol messages (binary, tss-lib wire format)
// Validation request before signing begins:

SIGN_REQUEST:
{
  "to": "<address>",
  "value": "<amount>",
  "data": "<calldata hex, if contract call>",
  "derivationPath": "m/44'/60'/0'/0/0",
  "unsignedTxBytes": "<base64>"
}

RESPONSE:
{ "decision": "approve" | "reject" | "escalate", "reason": "..." }
```

**TX Analyzer AI**:

The TX analyzer is the sole validation layer on Party B. It combines deterministic checks with LLM-based reasoning:

- **Deterministic checks** (always run first):
  - Decodes calldata against known contract ABIs (configured on secure server)
  - Verifies function selectors match known methods on the target contract
  - Validates parameter encoding and types
  - Checks destination addresses against known contracts/wallets
  - Verifies derivation path is expected

- **LLM-based analysis** (run after deterministic checks pass):
  - Connects to an LLM API (OpenAI, Anthropic, or a locally-hosted model — configurable, model runtime itself is out of scope)
  - Provides decoded transaction context to the LLM for intent classification
  - Outputs confidence score and classification
  - Decision matrix:
    - High confidence + expected pattern → auto-approve → co-sign
    - Low confidence or unusual pattern → escalate to user
    - Clearly malicious or nonsensical → reject

- **Configuration**: known contract ABIs, trusted addresses, and LLM connection settings stored as config files on the secure server, editable only with direct access.

**User Escalation**:

- When TX analyzer is uncertain, notification sent to user via Telegram bot
- User can approve or reject via Telegram
- Escalated transactions are queued, not dropped
- Configurable timeout: if user doesn't respond within X minutes, default to reject

**Responsibilities**:
- Accept connections only from Party A (mutual TLS, certificate pinning)
- Run TX analyzer (deterministic ABI checks + LLM analysis)
- Participate in TSS signing protocol (co-sign) only on approved requests
- Log all requests (approved, rejected, escalated) for audit
- Expose no other network services

---

### 3. Shared Library / Core

Code shared between both services:

**TSS Core** (wrapper around tss-lib):
- DKG (Distributed Key Generation) — run once during initial setup
- HD key derivation — derive child shares per chain/path
- ECDSA signing (secp256k1) — GG20 protocol via tss-lib
- EdDSA signing (ed25519) — via tss-lib
- Key resharing — rotate shares without changing the public key

**Transport Layer**:
- Mutual TLS setup and certificate management
- Message framing for TSS protocol rounds
- Reliable delivery (TSS protocols are multi-round, messages must not be lost)
- Reconnection logic

**VM Adapters** (used by Party A for tx construction, shared with Party B for tx decoding):

| Adapter | Curve | Covers |
|---------|-------|--------|
| EVM | secp256k1 (ECDSA) | Ethereum, BSC, Polygon, Arbitrum, Base, etc. |
| Solana | ed25519 (EdDSA) | SOL + SPL tokens |
| Tendermint | secp256k1 (ECDSA) | Cosmos SDK chains |

---

## Setup Flow (one-time)

The setup is driven by the **Installer** (see below) running on a local machine.

```
1. Generate TLS certificates for both parties
   - Party A cert + key
   - Party B cert + key
   - Both parties get each other's CA/cert for pinning

2. Run DKG ceremony
   - Both services start in "setup mode"
   - They run tss-lib DKG protocol together
   - Two master keys generated:
     a. ECDSA master (secp256k1) — for ETH, EVM chains, Cosmos
     b. EdDSA master (ed25519) — for SOL, etc.
   - Seed phrases are displayed for backup (copy and save)
   - Each party stores its share + auxiliary data in Postgres (encrypted)
   - Public keys are output for on-chain wallet registration

3. Configure TX analyzer on secure server
   - Add known contract ABIs
   - Set trusted addresses
   - Configure LLM connection (API key + endpoint)
   - Configure escalation channel (Telegram bot token + chat ID)

4. Deploy via SSH
   - Installer deploys Party A to AI server
   - Installer deploys Party B to secure server
   - Both services configured to run on boot


5. Both services switch to "operational mode"
```

---

## Signing Flow (per transaction)

```
1.  Bot → Party A:  POST /sign { ... }
2.  Party A:        VM adapter builds unsigned tx
3.  Party A:        Extracts signable bytes
4.  Party A → B:    Sends SIGN_REQUEST with tx details
5.  Party B:        TX analyzer runs deterministic ABI checks
6.  Party B:        TX analyzer runs LLM analysis (if checks pass)
7.  Party B:        Decision: approve / reject / escalate
8.  If rejected:    Party A returns error to bot
9.  If escalated:   Party B notifies user via Telegram, waits for response
10. If approved:    Both parties run TSS signing protocol
11. Party A:        Assembles signed transaction
12. Party A → Bot:  Returns signed transaction
13. Bot:            Validates, decides whether to broadcast to chain
```

---

## Security Model

**What a compromised AI server attacker gets**:
- Party A's key share (useless alone — cannot produce signatures)
- Ability to send signing requests to Party B
- Trading strategy / bot logic (out of scope for this system)

**What the attacker CANNOT do**:
- Sign transactions without Party B's approval
- Bypass TX analyzer (runs on secure server)
- Extract Party B's share (never leaves secure server)

**Worst case**: Attacker sends valid-looking requests that pass the TX analyzer. The LLM analysis + deterministic ABI checks + user escalation for uncertain transactions limit the blast radius.

---

## Technology

| Component | Choice | Reason |
|-----------|--------|--------|
| Language | Go | tss-lib is Go, chain libraries (go-ethereum) are Go |
| TSS library | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | Supports ECDSA + EdDSA, most battle-tested, patched for known vulns |
| Transport | mutual TLS over TCP | Authenticated, encrypted, no middleware needed |
| API (Party A) | HTTP REST on localhost | Simple for bot integration |
| TX analyzer config | YAML/JSON files | ABIs, trusted addresses, version-controllable |
| Chain RPCs | Configurable endpoints | Each adapter gets its own RPC URL config |
| Key storage | Encrypted in Postgres | Each party's share + aux data, encrypted at rest |
| LLM (TX analyzer) | OpenAI / Anthropic / local model API | Configurable endpoint, model runtime out of scope |

---

## Installer

A setup wizard that runs on a local machine (not on either server). Provides a step-by-step web UI to bootstrap the entire system.

- **Local web UI** with a guided wizard flow
- **SSH connection** to both servers (supports password and pubkey auth)
- **DKG ceremony orchestration**:
  - Generates ECDSA master (secp256k1) for EVM and Cosmos chains
  - Generates EdDSA master (ed25519) for Solana etc.
  - Displays seed phrases for user to copy and save securely
- LLM setup for tx analyzer
- **Telegram bot se>tup**: provides instructions, prompts for bot token, authorizes one recipient user

- **Deployment**: installs Party A and Party B software on configured servers via SSH
- **Service management**: configures both services to run on boot (systemd)
- **Stack**: Tailwind CSS
- **Design**: clean, modern UI with dark and light mode (defaults to system preference)

---

## Web UI for AI Server

A web dashboard served by Party A for operational visibility.

- **Keys & addresses**: view all generated addresses, public keys, and derivation paths
- **Transaction history**: view all signing request history with statuses (signed, rejected, escalated, pending)
- **Stack**: Tailwind CSS
- **Design**: clean, modern UI with dark and light mode (defaults to system preference)

---

## Tests

### Case 1: Wallet creation and restoration
- Generate new master keys via DKG:
  - ECDSA master (secp256k1) for EVM, Cosmos
  - EdDSA master (ed25519) for Solana
- Spin up Party A and Party B locally
- Derive EVM and Solana addresses
- Restore from the same seed/master keys
- Derive EVM and Solana addresses using the same paths — verify they match

### Test preparation (shared setup for cases 2-4)
- Generate new master keys via DKG:
  - ECDSA master (secp256k1) for EVM, Cosmos
  - EdDSA master (ed25519) for Solana
- Spin up Party A and Party B locally
- Derive two EVM keypairs/addresses on testnet: `eth-1`, `eth-2`
- Derive two Solana keypairs/addresses on testnet: `sol-1`, `sol-2`
- Spin up local testnet blockchains (EVM + Solana)
- Deploy a simple CCLAW ERC-20 token contract on EVM testnet
- Deploy a simple CCLAW SPL token on Solana testnet
- Deploy a simple staking contract (deposit + claim CCLAW) on each: `eth-s` (EVM), `sol-s` (Solana)

### Case 2: Native coin transfers
- Fund `eth-1` and `sol-1` with native testnet coins (mine/airdrop blocks)
- Request native transfer via Party A: `eth-1` → `eth-2`, `sol-1` → `sol-2`
- Party B approves the transactions
- TSS signing produces signed transactions
- Bot broadcasts to testnet
- Advance blocks
- Verify transactions landed on-chain and balances updated correctly

### Case 3: Token transfers
- Give CCLAW tokens to `eth-1` and `sol-1`
- Request token transfer via Party A: `eth-1` → `eth-2`, `sol-1` → `sol-2`
- Party B approves the transactions
- TSS signing produces signed transactions
- Bot broadcasts to testnet
- Advance blocks
- Verify transactions landed on-chain and token balances updated correctly

### Case 4: Contract interactions (staking)
- Deposit CCLAW tokens into staking contracts: `eth-1` → `eth-s`, `sol-1` → `sol-s`
- Advance blocks, verify deposits recorded on-chain
- Claim funds back from both staking contracts
- Advance blocks, verify claims processed and balances restored

---

## Out of Scope

- AI bot logic (prediction markets, trading strategy)
- On-chain smart contract development (test contracts are minimal stubs)
- Secure server OS hardening (operational concern)
- Multi-party (3+ parties) — designed for 2-of-2, can extend later
- Fiat on/off ramp integration
- LLM model hosting/runtime (TX analyzer connects to an API)

---

## Decisions

1. **Launch chains**: EVM (Ethereum + compatible) + Solana + Tendermint (Cosmos)
2. **Escalation channel**: Telegram bot
3. **Key resharing**: Yes, included from start
4. **Party setup**: 2-of-2 (Party A on AI server, Party B on secure server)
5. **Broadcasting**: Bot's responsibility (Party A returns signed tx, bot decides to broadcast)
6. **Transaction validation**: AI-driven TX analyzer with deterministic ABI checks (no separate policy engine)
