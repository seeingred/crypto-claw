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
POST /derive
{
  "derivationPath": "m/44'/60'/0'/0/0",
  "label": "<optional, human-readable label>"
}
→ { "address": "0x...", "pubKey": "0x..." }

PUT /keys/:derivationPath/label
{
  "label": "My ETH trading wallet"
}
→ { "ok": true }

POST /sign
{
  "unsignedTx": "<base64 encoded unsigned transaction>",
  "to": ["<address>"],
  "derivationPath": "m/44'/60'/0'/0/0"
}
→ { "signedTx": "<base64>", "status": "signed" }
   // If escalated to user for review:
→ { "txId": "<uuid>", "status": "pending_review" }

GET /sign/:txId
→ { "txId": "...", "status": "pending_review" | "approved" | "rejected", "signedTx": "<base64, if approved>", "derivationPath": "m/44'/60'/0'/0/0" }
   // Once the bot retrieves an approved transaction, it is deleted from memory

GET /keys
→ { "keys": { "m/44'/60'/0'/0/0": { "address": "0x...", "pubKey": "0x...", "label": "My ETH trading wallet" }, "m/44'/501'/0'/0'": { "address": "So1...", "pubKey": "...", "label": "" }, ... } }

GET /health
→ { "status": "ok", "secureServerConnected": true }
```

**Responsibilities**:
- Expose localhost-only REST API
- VM adapters: construct unsigned transactions per VM
- Manage nonces and sequence numbers
- Derive child key shares for requested chain (HD derivation via tss-lib)
- On-demand key derivation via `/derive` endpoint
- Initiate TSS signing protocol with Party B
- Assemble final signed transaction
- Return signed transaction to the bot (bot decides whether and when to broadcast)
- Queue escalated transactions, serve status via `/sign/:txId`, delete after bot retrieval
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

**TX Analyzer**:

The TX analyzer is the sole validation layer on Party B. It independently verifies transactions using a multi-stage pipeline:

- **Transaction decoding** (always run first):
  - Party B has its own VM adapter registry (EVM, Solana, Tendermint) and independently decodes the unsigned transaction from raw bytes
  - Extracts actual to/value/data from the decoded transaction rather than trusting claimed fields from Party A
  - Verifies signable bytes: recomputes the hash from the decoded transaction and rejects if it doesn't match what Party A sent (prevents signing tampered data)
  - Checks for field mismatches between claimed and decoded values (to, value)

- **Address whitelist**:
  - Maintains a persistent whitelist of trusted destination addresses in PostgreSQL
  - Addresses can be seeded from config, added via "Approve & Whitelist" in Telegram, or managed via the store
  - When autoMode=true and the destination is whitelisted: auto-approve with a non-interactive Telegram notification
  - When autoMode=false or the address is not whitelisted: escalate to user

- **Deterministic checks**:
  - Rejects transactions to zero addresses
  - Rejects transactions with no recipients
  - Flags high-value transactions for escalation
  - Decodes calldata using ABI resolver (contract function calls)
  - If ABI cannot be fetched (unverified contract), flags as higher risk

- **LLM-based analysis** (optional, run after deterministic checks):
  - Can be fully disabled via `disableAI` config flag (installer offers a "Skip LLM" option)
  - When enabled, connects to an LLM API (OpenAI, Anthropic, or a locally-hosted model)
  - Receives rich context: decoded transaction details, chain info, whitelist status, method calls, warnings, field mismatches
  - Outputs confidence score and classification
  - Decision matrix:
    - High confidence + expected pattern → approve
    - Low confidence, unusual pattern, or unverified contract → escalate to user
    - Clearly malicious or nonsensical → reject

- **Manual confirmation mode**: TX analyzer can be fully disabled via a toggle button in the Telegram bot settings menu. When disabled, all transactions are routed directly to the user for manual approval via Telegram.

- **Configuration**: LLM connection settings stored as config files on the secure server. LLM is optional — the system works with deterministic checks + whitelist alone.

**User Escalation**:

- When TX analyzer is uncertain (or manual mode is enabled), notification sent to user via Telegram bot
- Telegram notification includes decoded transaction details: chain, destination, value, method call, warnings, AI verdict (if enabled)
- User can: **Approve**, **Approve & Whitelist** (adds destination to trusted list for future auto-approval), or **Reject**
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
   - Configure LLM connection (API key + endpoint)
   - Configure block explorer API keys (Etherscan, Solscan, etc.)
   - Configure escalation channel (Telegram bot token + chat ID)

4. Deploy via SSH
   - Installer deploys Party A as a Docker container to AI server
   - Installer deploys Party B as a Docker container to secure server
   - Both containers configured to restart on boot


5. Both services switch to "operational mode"
```

---

## Signing Flow (per transaction)

```
1.  Bot → Party A:  POST /sign { ... }
2.  Party A:        VM adapter builds unsigned tx
3.  Party A:        Extracts signable bytes
4.  Party A → B:    Sends SIGN_REQUEST with unsigned tx, signable bytes, and claimed fields
5.  Party B:        Decodes unsigned tx independently via VM adapter
6.  Party B:        Verifies signable bytes match decoded tx (rejects on mismatch)
7.  Party B:        Checks destination against address whitelist
8.  Party B:        Runs deterministic checks (zero address, high value, etc.)
9.  Party B:        Optionally runs LLM analysis with decoded tx context
10. Party B:        Decision: approve / reject / escalate
11. If rejected:    Party A returns error to bot
12. If whitelisted  Party B auto-approves, sends notification, starts TSS signing
    + autoMode:
13. If escalated:   Party B sends Telegram notification with decoded tx details
                    + Approve / Approve & Whitelist / Reject buttons
                    Party A returns { txId, status: "pending_review" } to bot
                    Bot polls GET /sign/:txId until resolved
                    User approves/rejects/whitelists via Telegram
                    On approval: TSS signing proceeds, signed tx stored for bot retrieval
                    On rejection or timeout: status updated to "rejected"
14. If approved:    Both parties run TSS signing protocol
15. Party A:        Assembles signed transaction
16. Party A → Bot:  Returns signed transaction (or stores for poll retrieval if escalated)
17. Bot:            Validates, decides whether to broadcast to chain
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
| TX analyzer config | YAML/JSON files | LLM settings, block explorer API keys, version-controllable |
| Chain RPCs | Configurable endpoints | Each adapter gets its own RPC URL config |
| Key storage | Encrypted in Postgres | Each party's share + aux data, encrypted at rest |
| LLM (TX analyzer) | OpenAI / Anthropic / local model API | Configurable endpoint, model runtime out of scope |
| Deployment | Docker | Both services run as Docker containers on their respective servers |
| Frontend | Svelte + Tailwind CSS | Installer wizard and AI server web UI |

---

## Installer

A setup wizard that runs on a local machine (not on either server). Launched via a bash script that works on macOS, Linux, and WSL. Distributable as a one-liner install from GitHub (e.g. `curl -fsSL https://raw.githubusercontent.com/.../install.sh | bash`). Opens a step-by-step web UI in the user's default browser.

**Wizard steps**:
1. **Welcome & explanation**: describes the two-server architecture (AI server + secure server) and what each does
2. **Server configuration**: prompts for SSH access to both servers (supports password and pubkey auth). Offers optional localhost installation for testing
3. **Key generation (DKG)**: generates ECDSA master (secp256k1) for EVM/Cosmos and EdDSA master (ed25519) for Solana. Displays seed phrases for user to copy and save. Warns that keys cannot be recovered without them before proceeding
4. **LLM setup**: prompts for OpenAI key, Anthropic key, or locally-hosted model endpoint. Allows model selection for OpenAI/Anthropic
5. **Telegram bot setup**: provides BotFather instructions, prompts for bot token
6. **Telegram user authorization**: waits for the first message to the bot, then authorizes that user as the sole authorized recipient
7. **Review & confirm**: displays all configured settings for review before proceeding
8. **Deployment**: installs Party A and Party B as Docker containers on servers via SSH, with live installation logs and progress bar. Configures both as Docker services to run on boot
9. **Done**: shows completion status and link to the AI server web UI

**Uninstaller**: a separate bash script (also distributable via `curl | bash`) that connects to the servers via SSH, stops and removes Docker containers, removes images, cleans up volumes, and deletes key shares from Postgres. Prompts for confirmation before proceeding.

- **Stack**: Svelte + Tailwind CSS
- **Design**: clean, modern UI with dark and light mode (defaults to system preference)

---

## Web UI for AI Server

A web dashboard served by Party A for operational visibility.

- **Keys & addresses**: view all generated addresses, public keys, and derivation paths. Derivation paths are mapped to human-readable chain names (e.g. `m/44'/60'/...` → "Ethereum", `m/44'/501'/...` → "Solana")
- **Transaction history**: view all signing request history with statuses (signed, rejected, escalated, pending)
- **Stack**: Svelte + Tailwind CSS
- **Design**: clean, modern UI with dark and light mode (defaults to system preference)

---

## Tests

### Case 1: Wallet creation and restoration
- Generate new master keys via DKG:
  - ECDSA master (secp256k1) for EVM, Cosmos
  - EdDSA master (ed25519) for Solana
- Spin up Party A and Party B locally
- Derive EVM, Solana, and Cosmos addresses
- Restore from the same seed/master keys
- Derive EVM, Solana, and Cosmos addresses using the same paths — verify they match

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


## User Stories

### User installs the software
- I run the installer via a bash script that works on macOS, Linux, and WSL
- It opens a web UI in my default browser
- It explains that I need two servers: an AI server (where I'll run OpenClaw or a similar AI bot) and a secure server (which should run nothing else but the co-signer software)
- When I proceed, it prompts me for SSH access to both servers, where I can provide SSH credentials and/or keys (it also offers an optional localhost installation for testing purposes)
- When I proceed, it generates two master extended private keys (ECDSA + EdDSA), displays seed phrases, and prompts me to copy and save them in a secure location. Before moving to the next step, it warns me that without the private keys I cannot recover the wallets
- Next step asks me to provide an OpenAI key, Anthropic key, or a locally-hosted model endpoint, and select a model in case of OpenAI or Anthropic (via API). I can also skip this step to use deterministic checks + whitelist only (no LLM dependency)
- Next step provides instructions for creating a Telegram bot via BotFather, and prompts me for the bot token
- Next step waits for the first message to this Telegram bot, then authorizes that Telegram user as the sole actor authorized to send messages to the bot
- After all settings are configured, I review them and press OK to proceed with installation
- After installation completes (with clear installation logs and a progress bar), both servers are set up and functional. The installer provides a link to the web UI of the AI server

### Bot communicates with AI server
- As a bot, I can derive a public key and address for any supported chain, optionally attaching a label (e.g. "Main trading wallet")
- As a bot, I can update labels on existing derivation paths and addresses
- As a bot, I can view all derived public keys, addresses, and their labels
- As a bot, I can request a raw transaction to be signed and receive the signed transaction in return
- If a transaction is escalated to the user for review, I receive a transaction ID and can poll later to check if it's been approved or rejected. Once approved, the AI server returns the signed transaction and then deletes it from memory
- As a bot, I can check the health of the AI server

### User communicates with secure server via Telegram
- I receive a message with decoded transaction details (chain, destination address, value, method call if contract interaction, warnings, AI verdict if enabled) and three inline buttons: **Approve**, **Approve & Whitelist**, and **Reject**
- I tap Approve to approve signing, Approve & Whitelist to approve and add the destination to my trusted addresses for future auto-approval, or Reject to reject the transaction
- I can open a **Settings** menu (via a persistent menu button) which has a toggle button to switch between **Auto mode** (TX analyzer decides, escalates uncertain txs) and **Manual mode** (all transactions sent to me for approval)

### Documentation
- As a user, I can read a comprehensive README in the repo that explains the system architecture, setup instructions, and API reference

