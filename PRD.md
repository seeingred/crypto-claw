# PRD: MPC-TSS Crypto Signing Service

## Context

A crypto prediction market bot runs on an internet-exposed server considered vulnerable to compromise. The bot needs to sign transactions across multiple blockchains (both ECDSA and EdDSA curves). Private keys stored on the exposed machine can be stolen.

This system eliminates that risk by splitting signing capability across two independent servers using Multi Party Computation Threshold Signature Scheme (MPC-TSS). Neither server alone can produce a valid signature. The secure server enforces transaction policy before co-signing.

The AI bot is **out of scope** — it is a consumer of this system via a local API.

---

## System Overview

```
                          ┌───────────────────────────────-───┐
                          │         AI SERVER (exposed)       │
  ┌──────────┐   REST     │                                   │
  │  AI Bot  │───────────►│   TSS Signer Service (Party A)  
  │          │            |   - Stores public keys and derived paths
  │ (out of  │  localhost │   - Receives sign requests        │
  │  scope)  │◄───────────│   - Constructs chain-specific txs │
  └──────────┘            │   - Initiates TSS protocol        │
                          │   - Broadcasts signed txs         │
                          └───────────────┬───────────────────┘
                                          │ mutual TLS
                                          │
                          ┌───────────────┴───────────────────┐
                          │      SECURE SERVER (hardened)       │
                          │                                     │
                          │   TSS Co-signer Service (Party B)   │
                          │   - Receives signing requests       │
                          │   - Runs policy engine (hard rules) │
                          │   - Runs TX analyzer AI tool        │
                          │   - Co-signs or rejects             │
                          │   - Escalates uncertain txs to user │
                          └─────────────────────────────────────┘
```

---

## Components

### 1. TSS Signer Service (Party A) — runs on AI server

**Purpose**: Accept simple signing requests from the bot, handle all chain-specific transaction construction, initiate TSS signing with the secure server, broadcast result, store public keys info, derived paths and addresses

**API** (localhost only, not exposed to network):

```
POST /sign
{
  "vm": "evm" | "solana" | "tendermint" ...,
  "chain": <ticker of the chain>
  "unsignedTx": "<base64 encoded unsigned transaction>",
  "to": ["<address>"],
  "derivationPath": "m/44'/60'/0'/0/0",
}
→ { "txHash": "...", "status": "broadcast" }

GET /keys
→ { "chains": { "eth": { "address": "0x...", pubKey: "" }, "sol": { "address": "bc1q...", pubKey: "" }, ... } }

GET /health
→ { "status": "ok", "secureServerConnected": true }
```

**Responsibilities**:
- Expose localhost-only REST API
- VM adapters: construct unsigned transactions per vm
- Manage nonces and sequence numbers
- Derive child key shares for requested chain (HD derivation via tss-lib)
- Initiate TSS signing protocol with Party B
- Assemble final signed transaction
- Broadcast to chain RPC
- Return tx hash to caller

**Does NOT do**:
- Policy decisions (that's Party B)
- Store full private keys (only its share)
- Expose API to the network

---

### 2. TSS Co-signer Service (Party B) — runs on secure server

**Purpose**: Participate in TSS signing only after validating the transaction against policy rules and AI analysis.

**Inbound interface** (mutual TLS, accepts connections only from Party A):

```
// TSS protocol messages (binary, tss-lib wire format)
// Policy check request before signing begins:

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

**Policy Engine** (deterministic, checked first):

Configuration stored as a local config file on the secure server. Editable only with direct access to the secure server.

**TX Analyzer AI** (soft rules, checked second — only if hard rules pass):

- Decodes calldata against known contract
- Local LLM connection, oen ai key or anthropic key to make a descisions
- Classifies transaction intent
- Outputs confidence score and classification
- Decision matrix:
  - High confidence + expected pattern → auto-approve → co-sign
  - Low confidence or unusual pattern → escalate to user
  - Clearly malicious or nonsensical → reject

**User Escalation**:

- When TX analyzer is uncertain, notification sent to user (Telegram bot — configurable)
- User can approve or reject
- Escalated transactions are queued, not dropped

**Responsibilities**:
- Accept connections only from Party A (mutual TLS, certificate pinning)
- Run TX analyzer
- Participate in TSS signing protocol (co-sign) only on approved requests
- Log all requests (approved, rejected, escalated) for audit
- Expose no other network services beside admin panel

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

**Chain Adapters** (used by Party A, shared for potential use by Party B for tx decoding):

| Adapter | Curve | Covers |
|---------|-------|--------|
| EVM | secp256k1 (ECDSA) | Ethereum, BSC, Polygon, Arbitrum, Base, etc. |
| Solana | ed25519 (EdDSA) | SOL + SPL tokens |
| Tendermint | secp256k1 (ECDSA) | Cosmos SDK chains |

---

## Setup Flow (one-time)

```
1. Generate TLS certificates for both parties
   - Party A cert + key
   - Party B cert + key
   - Both parties get each other's CA/cert for pinning

2. Run DKG ceremony
   - Both services start in "setup mode"
   - They run tss-lib DKG protocol together
   - Two master keys generated:
     a. ECDSA master (secp256k1) — for BTC, ETH, EVM, Cosmos
     b. EdDSA master (ed25519) — for SOL, DOT, etc.
   - Each party stores its share + auxiliary data locally
   - Public keys are output for on-chain wallet registration

3. Configure policy on secure server
   - Set destination allowlists
   - Set function selector allowlists
   - Set spend limits and rate limits
   - Configure escalation channel (Telegram, email, etc.)

4. Fund the wallets
   - Send funds to the derived addresses

5. Both services switch to "operational mode"
```

---

## Signing Flow (per transaction)

```
1.  Bot → Party A:  POST /sign { ... }
2.  Party A:        Chain adapter builds unsigned tx
3.  Party A:        Extracts signable bytes
4.  Party A → B:    Sends SIGN_REQUEST with tx details
5.  Party B:        TX analyzer AI checks soft rules
6.  Party B:        Decision: approve / reject / escalate
7.  If rejected:    Party A returns error to bot
8.  If escalated:   Party B notifies user, waits for response
9. If approved:    Both parties run TSS signing protocol
10. Party A:        Assembles signed transaction
12. Bot:        Broadcasts to chain
```

---

## Security Model

**What a compromised AI server attacker gets**:
- Party A's key share (useless alone — cannot produce signatures)
- Ability to send signing requests to Party B
- Trading strategy / bot logic (out of scope for this system)

**What the attacker CANNOT do**:
- Sign transactions without Party B's approval
- Bypass policy engine (runs on secure server)
- Extract Party B's share (never leaves secure server)
---

## Technology

| Component | Choice | Reason |
|-----------|--------|--------|
| Language | Go | tss-lib is Go, chain libraries (btcsuite, go-ethereum) are Go |
| TSS library | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | Supports ECDSA + EdDSA, most battle-tested, patched for known vulns |
| Transport | mutual TLS over TCP | Authenticated, encrypted, no middleware needed |
| API (Party A) | HTTP REST on localhost | Simple for bot integration |
| Policy config | YAML/JSON file | No database needed, version-controllable |
| Chain RPCs | Configurable endpoints | Each adapter gets its own RPC URL config |
| Key storage | Encrypted in postgres | Each party's share + aux data, encrypted at rest |


## Installer
- Should be run on local machine (not at any of the servers)
- Requires ssh connection to both servers (password, pubkey auth)
- Should have master type installation web ui guide, where you are able to generate 
  a. ECDSA master (secp256k1) — for BTC, ETH, EVM, Cosmos
  b. EdDSA master (ed25519) — for SOL, DOT, etc
  Including seed prhareses. Should be able to copy and save them
- Should provide instruction for setting up telegram bot for secure server, prompt for bot key and authorize 1 recipient (user)
- Should install ai-server software and secure-server software on configured servers via ssh
- Should make the servers run on boot
- have nice design
- support dark and light mode defaults to system


## Web-ui for ai-server
- view all addresses and public keys generated + deriviation paths, 
- view transactions requests history with the statuses
- use tailwind
- have nice design
- support dark and light mode defaults to system

## Tests
- case 1: create and restore the wallets from private keys
  - create new priv keys via master:
    a. ECDSA master (secp256k1) — for BTC, ETH, EVM, Cosmos
    b. EdDSA master (ed25519) — for SOL, DOT, etc
  - spin ai server and secure server locally
  - derive evm and sol address
  - import priv keys via master:
  - derive  evm and sol address using the same path and check if they are the same
- preparation for other cases:
  - create new priv keys via master:
    a. ECDSA master (secp256k1) — for BTC, ETH, EVM, Cosmos
    b. EdDSA master (ed25519) — for SOL, DOT, etc
  - spin ai server and secure server locally
  - derive evm and sol chain keypair and addresses on testnet (call them address eth-1, eth-2, sol-1 and sol-2)
  - spin a testnet blockchains
  - deploy simple CCLAW token contract on both blockchains
  - deploy the simple staking contract that allows deposit and claim CCLAW token (let's call it eth-s and sol-s)
- case 2: sign and send trasactions on blockchain
  - generate blocks to deposit chain coins to address eth-1 and sol-1
  - use ai-server to request crypto transer transactions from eth-1 to eth-2 and sol-1 to sol2
  - approve the transaction with secure-server
  - sign the transaction
  - send the transactions
  - add blocks to blockchain
  - check if transaction was correct and sit in blockchain and balances being updated
- case 3:
  - give CCLAW tokens to eth-1 and sol-1 addess
  - use ai-server to request token transfer transactions from eth-1 to eth-2 and sol-1 to sol2
  - approve the transaction with secure-server
  - sign the transaction
  - send the transactions
  - add blocks to blockchain
  - check if transaction was correct and sit in blockchain and balances being updated
- case 4:
  - deposit CCLAW token using eth-s and sol-s contract from eth-1 and sol-1 correspondingly
  - add blocks to blockchain
  - check if transaction was correct and sit in blockchain and balances being updated
  - claim funds back from both contracts
  - add blocks to blockchain
  - check if transaction was correct and sit in blockchain and balances being updated
  




---

## Out of Scope

- AI bot logic (prediction markets, trading strategy)
- On-chain smart contract development
- Secure server OS hardening (operational concern)
- Multi-party (3+ parties) — designed for 2-of-2, can extend later
- Fiat on/off ramp integration

---

## Decisions

1. **Launch chains**: EVM (Ethereum + compatible) + Bitcoin + Solana
2. **Escalation channel**: Telegram bot
3. **Key resharing**: Yes, included from start
4. **Party setup**: 2-of-2 (Party A on AI server, Party B on secure server)
