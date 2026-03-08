# Bot Integration Guide

This document describes how to integrate an AI bot (or any client) with the Crypto Claw signing service via Party A's localhost REST API.

## Overview

Party A runs on the same machine as your bot and exposes a localhost-only HTTP API (default `127.0.0.1:8080`). Your bot uses this API to:

1. Derive blockchain addresses from the master keys
2. Request transaction signing
3. Poll for escalated transaction results
4. List all derived keys and addresses

Party A handles transaction construction, TSS signing with Party B, and returns the signed transaction. Your bot is responsible for broadcasting it to the chain.

```
┌──────────┐  localhost   ┌──────────────────────┐  mutual TLS  ┌──────────────────────┐
│  Your    │  REST API    │  Party A              │              │  Party B              │
│  Bot     │◄────────────►│  (AI server)          │◄────────────►│  (secure server)      │
│          │              │  Builds txs, signs    │              │  Validates, co-signs  │
└────┬─────┘              └──────────────────────┘              └──────────────────────┘
     │
     │  broadcast signed tx
     ▼
┌──────────┐
│Blockchain│
└──────────┘
```

## Base URL

```
http://127.0.0.1:8080
```

The port is configurable via `api.listenAddr` in Party A's config.

## Derivation Paths

Crypto Claw uses BIP-44 derivation paths. The coin type determines which chain adapter handles the request:

| Coin Type | Path Pattern | Chain | Curve |
|-----------|-------------|-------|-------|
| 60 | `m/44'/60'/0'/0/N` | Ethereum / EVM | secp256k1 (ECDSA) |
| 501 | `m/44'/501'/0'/0'` | Solana | ed25519 (EdDSA) |
| 118 | `m/44'/118'/0'/0/N` | Cosmos / Tendermint | secp256k1 (ECDSA) |

Increment `N` (the address index) to generate multiple wallets on the same chain.

## Endpoints

### Derive a new address

```
POST /derive
```

Derives a child key from the master key and returns the chain-specific address. Both Party A and Party B derive their respective shares. The key is stored for future signing.

**Request:**

```json
{
  "derivationPath": "m/44'/60'/0'/0/0",
  "label": "Main ETH wallet"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `derivationPath` | string | yes | BIP-44 path |
| `label` | string | no | Human-readable label |

**Response** `200 OK`:

```json
{
  "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
  "pubKey": "0x04a1b2c3..."
}
```

**Example — derive wallets for multiple chains:**

```bash
# Ethereum wallet
curl -s http://127.0.0.1:8080/derive \
  -d '{"derivationPath":"m/44'\''/60'\''/0'\''/0/0","label":"ETH trading"}' | jq

# Solana wallet
curl -s http://127.0.0.1:8080/derive \
  -d '{"derivationPath":"m/44'\''/501'\''/0'\''/0'\''","label":"SOL trading"}' | jq

# Second ETH wallet
curl -s http://127.0.0.1:8080/derive \
  -d '{"derivationPath":"m/44'\''/60'\''/0'\''/0/1","label":"ETH vault"}' | jq
```

### Sign a transaction

```
POST /sign
```

Constructs an unsigned transaction, sends it to Party B for validation, and if approved, runs the TSS signing protocol. Returns the signed transaction as `0x`-prefixed hex.

**Request:**

```json
{
  "derivationPath": "m/44'/60'/0'/0/0",
  "to": ["0xRecipientAddress"],
  "value": "1000000000000000000",
  "chainId": "1",
  "gasLimit": 21000,
  "gasPrice": "20000000000",
  "nonce": 5
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `derivationPath` | string | yes | BIP-44 path of the sender key |
| `to` | string[] | yes | Recipient address(es) |
| `value` | string | no | Amount in smallest unit (wei, lamports) |
| `data` | string | no | Hex-encoded calldata for contract calls (with or without `0x` prefix) |
| `chainId` | string | no | Chain ID (required for EVM) |
| `gasLimit` | number | no | Gas limit (EVM) |
| `gasPrice` | string | no | Gas price in wei (EVM) |
| `nonce` | number | no | Transaction nonce (EVM) |
| `rpcUrl` | string | no | Solana RPC URL — fresh blockhash is fetched right before signing to avoid expiry during approval. SSRF-protected (private IPs blocked in production) |

**Response — signed** `200 OK`:

```json
{
  "status": "signed",
  "signedTx": "0x..."
}
```

**Response — rejected** `200 OK`:

```json
{
  "status": "rejected",
  "reason": "Transaction to unverified contract with high value"
}
```

**Response — escalated** `202 Accepted`:

```json
{
  "txId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "pending_review",
  "reason": "Unusual transaction pattern, escalated to user"
}
```

Party B decides the outcome based on its TX analyzer:
- **Approved** — deterministic ABI checks pass and LLM classifies as safe
- **Rejected** — clearly malicious or nonsensical
- **Escalated** — uncertain; the user will approve/reject via Telegram

**Example — send 1 ETH:**

```bash
curl -s http://127.0.0.1:8080/sign -d '{
  "derivationPath": "m/44'\''/60'\''/0'\''/0/0",
  "to": ["0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18"],
  "value": "1000000000000000000",
  "chainId": "1",
  "gasLimit": 21000,
  "gasPrice": "20000000000",
  "nonce": 0
}' | jq
```

**Example — ERC-20 transfer (contract call):**

```bash
curl -s http://127.0.0.1:8080/sign -d '{
  "derivationPath": "m/44'\''/60'\''/0'\''/0/0",
  "to": ["0xTokenContractAddress"],
  "data": "0xa9059cbb000000000000000000000000RecipientAddress0000000000000000000000000000000000000000000000000de0b6b3a7640000",
  "chainId": "1",
  "gasLimit": 65000,
  "gasPrice": "20000000000",
  "nonce": 1
}' | jq
```

**Example — send SOL:**

```bash
curl -s http://127.0.0.1:8080/sign -d '{
  "derivationPath": "m/44'\''/501'\''/0'\''/0'\''",
  "to": ["RecipientBase58Address"],
  "value": "1000000000",
  "rpcUrl": "https://api.mainnet-beta.solana.com"
}' | jq
```

**Example — send ATOM (Cosmos):**

```bash
curl -s http://127.0.0.1:8080/sign -d '{
  "derivationPath": "m/44'\''/118'\''/0'\''/0/0",
  "to": ["cosmos1..."],
  "value": "1000000",
  "chainId": "cosmoshub-4",
  "data": "uatom"
}' | jq
```

### Poll escalated transaction status

```
GET /sign/{txId}
```

Check whether an escalated transaction has been approved or rejected by the user via Telegram.

**Response** `200 OK`:

```json
{
  "txId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "pending_review",
  "reason": "Unusual transaction pattern, escalated to user"
}
```

Possible `status` values:
- `pending_review` — waiting for user decision via Telegram
- `signed` — user approved; `signedTx` field contains the signed transaction
- `rejected` — user rejected or escalation timed out

Once you retrieve a `signed` transaction, it is **deleted from memory**. Subsequent requests for the same `txId` will return 404.

**Response — approved** `200 OK`:

```json
{
  "txId": "a1b2c3d4-...",
  "status": "signed",
  "signedTx": "0x..."
}
```

**Response — not found** `404 Not Found`:

```json
{
  "error": "transaction not found"
}
```

**Example — poll loop:**

```bash
TX_ID="a1b2c3d4-e5f6-7890-abcd-ef1234567890"

while true; do
  RESULT=$(curl -s http://127.0.0.1:8080/sign/$TX_ID)
  STATUS=$(echo "$RESULT" | jq -r .status)

  case "$STATUS" in
    signed)
      echo "Approved! Signed TX:"
      echo "$RESULT" | jq -r .signedTx
      break
      ;;
    rejected)
      echo "Rejected: $(echo "$RESULT" | jq -r .reason)"
      break
      ;;
    pending_review)
      echo "Waiting for user approval..."
      sleep 5
      ;;
    *)
      echo "Error: $RESULT"
      break
      ;;
  esac
done
```

### List all derived keys

```
GET /keys
```

Returns all derived keys with their addresses, public keys, and labels.

**Response** `200 OK`:

```json
{
  "keys": {
    "m/44'/60'/0'/0/0": {
      "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
      "pubKey": "0x04a1b2c3...",
      "label": "Main ETH wallet"
    },
    "m/44'/501'/0'/0'": {
      "address": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
      "pubKey": "0x01ab23...",
      "label": "SOL trading"
    }
  }
}
```

### Update a key label

```
PUT /keys/{derivationPath}/label
```

**Request:**

```json
{
  "label": "Updated label"
}
```

**Response** `200 OK`:

```json
{
  "ok": true
}
```

### Health check

```
GET /health
```

**Response** `200 OK`:

```json
{
  "status": "ok",
  "secureServerConnected": true
}
```

| Field | Description |
|-------|-------------|
| `status` | `"ok"` if Party A is running |
| `secureServerConnected` | `true` if Party B is reachable over mutual TLS |

If `secureServerConnected` is `false`, signing requests will fail. Check that Party B is running and the network path between servers is open.

**Response** `503 Service Unavailable` — returned if Party A itself is unhealthy.

## Error Format

All errors return JSON:

```json
{
  "error": "description of what went wrong"
}
```

Common HTTP status codes:

| Code | Meaning |
|------|---------|
| 200 | Success |
| 202 | Transaction escalated for review (poll `/sign/{txId}`) |
| 400 | Invalid request (missing fields, bad hex data) |
| 404 | Transaction ID not found |
| 500 | Server error |
| 503 | Service unavailable (health check failed) |

## Typical Bot Workflow

```
1. On startup:
   GET /health              → verify Party A and B are connected

2. Setup wallets (once):
   POST /derive             → derive ETH address (m/44'/60'/0'/0/0)
   POST /derive             → derive SOL address (m/44'/501'/0'/0')
   GET /keys                → confirm addresses

3. Per transaction:
   POST /sign               → request signing

   if status == "signed":
     → broadcast signedTx to blockchain RPC

   if status == "pending_review":
     → poll GET /sign/{txId} every 5s
     → broadcast when status becomes "signed"

   if status == "rejected":
     → log reason, skip transaction

4. Ongoing:
   GET /keys                → list wallets for display
   PUT /keys/{path}/label   → organize with labels
   GET /health              → periodic health monitoring
```

## Notes

- **Localhost only** — the API binds to `127.0.0.1`. It is not accessible from the network.
- **Broadcasting** — Party A returns the signed transaction. Your bot decides whether and when to broadcast it.
- **Nonce management** — your bot is responsible for tracking nonces. Party A does not auto-increment.
- **Gas estimation** — provide `gasLimit` and `gasPrice` explicitly. Party A does not estimate gas.
- **Escalation timeout** — if the user doesn't respond via Telegram within the configured timeout (default 5 minutes), the transaction is rejected.
- **One-time retrieval** — signed escalated transactions are deleted after the first `GET /sign/{txId}` retrieval. Store the `signedTx` on your end.
