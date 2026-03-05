# Crypto Claw — MPC-TSS Crypto Signing Service

A 2-of-2 Multi-Party Computation Threshold Signature Scheme (MPC-TSS) service that splits signing capability across two independent servers. Neither server alone can produce a valid signature, protecting against key theft even if one server is compromised.

## Architecture

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

**Party A** (AI server) exposes a localhost REST API for the bot. It builds chain-specific transactions, initiates TSS signing with Party B, and returns signed transactions.

**Party B** (secure server) validates transactions using an AI-driven analyzer (deterministic ABI checks + LLM analysis) before co-signing. Uncertain transactions are escalated to the user via Telegram.

## Supported Chains

| Adapter | Curve | Chains |
|---------|-------|--------|
| EVM | secp256k1 (ECDSA) | Ethereum, BSC, Polygon, Arbitrum, Base, etc. |
| Solana | ed25519 (EdDSA) | SOL + SPL tokens |
| Tendermint | secp256k1 (ECDSA) | Cosmos SDK chains |

## Project Structure

```
cmd/
  party-a/          Party A entry point
  party-b/          Party B entry point
  installer/        Setup wizard entry point
internal/
  config/           Configuration loading
  partya/           Party A service + REST API
  partyb/           Party B service (analyzer, Telegram bot)
  store/            Encrypted key share storage (PostgreSQL)
  transport/        Mutual TLS transport layer
  tss/              TSS protocol (DKG, signing, derivation, resharing)
  vm/               VM adapter interface
    evm/            EVM adapter (go-ethereum)
    solana/         Solana adapter (gagliardetto/solana-go)
    tendermint/     Tendermint/Cosmos adapter
contracts/
  evm/              Solidity contracts for integration tests
tests/
  testutil/         Test infrastructure (cluster, router, Hardhat, Solana helpers)
  case1_*           Wallet creation and restoration tests
  case2_*           Native transfer tests (ETH, SOL)
  case3_*           Token transfer tests (ERC-20, SPL)
  case4_*           Staking tests (deposit, claim)
```

## Prerequisites

- Go 1.21+
- PostgreSQL (for encrypted key share storage)
- Node.js 18+ (for Hardhat integration tests)

## Configuration

Both services are configured via a JSON file (`config.json`). See `internal/config/config.go` for the full schema.

### Party A (config-a.json)

```json
{
  "party": "a",
  "dataDir": "/var/lib/crypto-claw/party-a",
  "database": {
    "host": "localhost",
    "port": 5432,
    "user": "cclaw",
    "password": "secret",
    "dbName": "cclaw_a",
    "sslMode": "disable"
  },
  "api": {
    "listenAddr": "127.0.0.1:8080"
  },
  "transport": {
    "remoteAddr": "secure-server:9443",
    "certFile": "/etc/crypto-claw/cert.pem",
    "keyFile": "/etc/crypto-claw/key.pem",
    "caCertFile": "/etc/crypto-claw/ca.pem"
  },
  "chains": {
    "evm": [
      { "name": "ethereum", "chainId": 1, "rpcUrl": "https://eth.llamarpc.com" }
    ],
    "solana": [
      { "name": "solana-mainnet", "rpcUrl": "https://api.mainnet-beta.solana.com" }
    ]
  }
}
```

### Party B (config-b.json)

```json
{
  "party": "b",
  "dataDir": "/var/lib/crypto-claw/party-b",
  "database": {
    "host": "localhost",
    "port": 5432,
    "user": "cclaw",
    "password": "secret",
    "dbName": "cclaw_b",
    "sslMode": "disable"
  },
  "transport": {
    "listenAddr": "0.0.0.0:9443",
    "certFile": "/etc/crypto-claw/cert.pem",
    "keyFile": "/etc/crypto-claw/key.pem",
    "caCertFile": "/etc/crypto-claw/ca.pem"
  },
  "analyzer": {
    "autoMode": true,
    "llm": {
      "provider": "anthropic",
      "apiKey": "sk-ant-...",
      "model": "claude-sonnet-4-20250514"
    }
  },
  "telegram": {
    "botToken": "123456:ABC-DEF...",
    "authorizedUserId": 12345678,
    "escalationTimeout": "5m"
  }
}
```

## Running

```bash
# Party A
go run ./cmd/party-a -config config-a.json -passphrase "your-encryption-passphrase"

# Party B
go run ./cmd/party-b -config config-b.json -passphrase "your-encryption-passphrase"
```

## API Reference

Party A exposes a localhost-only REST API.

### `POST /derive`

Derive a new child key for a blockchain.

```json
// Request
{ "derivationPath": "m/44'/60'/0'/0/0", "label": "My ETH wallet" }

// Response
{ "address": "0x...", "pubKey": "0x..." }
```

### `POST /sign`

Request a transaction to be signed.

```json
// Request
{
  "derivationPath": "m/44'/60'/0'/0/0",
  "to": ["0x..."],
  "value": "1000000000000000000",
  "chainId": "1",
  "gasLimit": 21000,
  "nonce": 0
}

// Response (approved)
{ "signedTx": "<base64>", "status": "signed" }

// Response (escalated for review)
{ "txId": "<uuid>", "status": "pending_review" }

// Response (rejected)
{ "status": "rejected", "reason": "..." }
```

### `GET /sign/:txId`

Poll status of an escalated transaction.

```json
{
  "txId": "...",
  "status": "pending_review",  // or "approved", "rejected"
  "signedTx": "<base64>"       // present when approved
}
```

Once an approved transaction is retrieved, it is deleted from memory.

### `GET /keys`

List all derived keys.

```json
{
  "keys": {
    "m/44'/60'/0'/0/0": {
      "address": "0x...",
      "pubKey": "0x...",
      "label": "My ETH wallet"
    }
  }
}
```

### `PUT /keys/:derivationPath/label`

Update the label for a derived key.

```json
// Request
{ "label": "Updated label" }

// Response
{ "ok": true }
```

### `GET /health`

Check service health.

```json
{ "status": "ok", "secureServerConnected": true }
```

## Signing Flow

1. Bot sends `POST /sign` to Party A
2. Party A builds unsigned transaction via the appropriate VM adapter
3. Party A sends sign request to Party B over mutual TLS
4. Party B runs the TX analyzer (deterministic ABI checks + LLM analysis)
5. Party B decides: **approve**, **reject**, or **escalate**
6. If rejected → Party A returns error to bot
7. If escalated → Party B notifies user via Telegram; bot polls `GET /sign/:txId`
8. If approved → both parties run TSS signing protocol
9. Party A assembles the signed transaction
10. Party A returns signed transaction to bot
11. Bot broadcasts to the blockchain

## Security Model

- **Compromised AI server**: attacker gets Party A's key share (useless alone), can send signing requests but cannot bypass Party B's validation
- **Protection layers**: deterministic ABI checks, LLM-based analysis, user escalation via Telegram, mutual TLS transport
- **Key storage**: shares encrypted with AES-256-GCM in PostgreSQL

## TSS Technical Details

- **DKG**: Distributed Key Generation via bnb-chain/tss-lib (GG20 protocol for ECDSA, EdDSA native)
- **HD Derivation**: BIP-32 style using compressed public key for all derivation levels (standard non-hardened approach for TSS — hardened derivation requires the full private key which no single party holds)
- **Signing**: Multi-round threshold signing protocol with in-order message delivery
- **Resharing**: Key share rotation without changing the public key

## Testing

```bash
# Unit tests (fast, no external dependencies)
go test ./internal/... -short

# Case 1: Wallet creation and restoration (real DKG, ~30s)
go test ./tests/ -run TestWallet -timeout 30m -v

# Cases 2-4: Integration tests (require Hardhat)
cd contracts/evm && npm install && cd ../..
go test ./tests/ -run TestNativeTransfer -timeout 30m -v
go test ./tests/ -run TestTokenTransfer -timeout 30m -v
go test ./tests/ -run TestStaking -timeout 30m -v

# All tests
go test ./... -timeout 30m
```

Integration tests (Cases 2-4) require Hardhat and will skip automatically if it's not installed. Solana tests require `solana-test-validator` and skip otherwise.

## License

Proprietary.
