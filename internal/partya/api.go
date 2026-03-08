package partya

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/seeingred/crypto-claw/internal/vm"
)

// NewRouter creates the chi router with all Party A REST endpoints.
func NewRouter(svc *Service) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.SetHeader("Content-Type", "application/json"))

	api := &apiHandler{svc: svc}

	r.Post("/derive", api.handleDerive)
	r.Post("/sign", api.handleSign)
	r.Get("/sign/{txId}", api.handleGetSignStatus)
	r.Get("/keys", api.handleListKeys)
	r.Put("/keys/{path}/label", api.handleUpdateLabel)
	r.Get("/health", api.handleHealth)
	r.Get("/api", api.handleAPIDocs)

	return r
}

type apiHandler struct {
	svc *Service
}

type deriveRequest struct {
	DerivationPath string `json:"derivationPath"`
	Label          string `json:"label"`
	Prefix         string `json:"prefix,omitempty"` // optional bech32 prefix for Cosmos app chains
}

func (h *apiHandler) handleDerive(w http.ResponseWriter, r *http.Request) {
	var req deriveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.DerivationPath == "" {
		writeError(w, http.StatusBadRequest, "derivationPath is required")
		return
	}

	result, err := h.svc.Derive(r.Context(), req.DerivationPath, req.Label, req.Prefix)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

type signAPIRequest struct {
	DerivationPath  string                  `json:"derivationPath"`
	To              []string                `json:"to"`
	Value           string                  `json:"value,omitempty"`
	Data            string                  `json:"data,omitempty"` // hex-encoded
	ChainID         string                  `json:"chainId,omitempty"`
	GasLimit        uint64                  `json:"gasLimit,omitempty"`
	GasPrice        string                  `json:"gasPrice,omitempty"`
	Nonce           uint64                  `json:"nonce,omitempty"`
	RpcURL          string                  `json:"rpcUrl,omitempty"`   // Solana RPC URL for fetching blockhash at sign time
	Mint            string                  `json:"mint,omitempty"`     // Solana SPL token mint address (base58)
	Instructions    []vm.SolanaInstruction  `json:"instructions,omitempty"` // Solana: raw program instructions
	Program         string                  `json:"program,omitempty"`      // Solana: Anchor program ID
	Method          string                  `json:"method,omitempty"`       // Solana: Anchor instruction name
	Args            map[string]string       `json:"args,omitempty"`         // Solana: Anchor instruction args
	Prefix          string                  `json:"prefix,omitempty"`       // Cosmos: bech32 prefix for app chains
	Denom           string                  `json:"denom,omitempty"`        // Cosmos: token denomination
	AccountNumber   uint64                  `json:"accountNumber,omitempty"` // Cosmos: account number
	Sequence        uint64                  `json:"sequence,omitempty"`     // Cosmos: account sequence
	Fee             string                  `json:"fee,omitempty"`          // Cosmos: fee amount
	Gas             uint64                  `json:"gas,omitempty"`          // Cosmos: gas limit
	Memo            string                  `json:"memo,omitempty"`         // Cosmos: memo
}

func (h *apiHandler) handleSign(w http.ResponseWriter, r *http.Request) {
	var req signAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.DerivationPath == "" {
		writeError(w, http.StatusBadRequest, "derivationPath is required")
		return
	}
	if len(req.To) == 0 && len(req.Instructions) == 0 && req.Program == "" {
		writeError(w, http.StatusBadRequest, "to, instructions, or program required")
		return
	}

	var data []byte
	if req.Data != "" {
		// Strip 0x prefix if present
		hexData := req.Data
		if len(hexData) >= 2 && hexData[:2] == "0x" {
			hexData = hexData[2:]
		}
		var err error
		data, err = hexDecode(hexData)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid hex data")
			return
		}
	}

	result, err := h.svc.Sign(r.Context(), &SignRequest{
		DerivationPath:  req.DerivationPath,
		To:              req.To,
		Value:           req.Value,
		Data:            data,
		ChainID:         req.ChainID,
		GasLimit:        req.GasLimit,
		GasPrice:        req.GasPrice,
		Nonce:           req.Nonce,
		RpcURL:          req.RpcURL,
		Mint:            req.Mint,
		Instructions:    req.Instructions,
		Program:         req.Program,
		Method:          req.Method,
		Args:            req.Args,
		Prefix:          req.Prefix,
		Denom:           req.Denom,
		AccountNumber:   req.AccountNumber,
		Sequence:        req.Sequence,
		Fee:             req.Fee,
		Gas:             req.Gas,
		Memo:            req.Memo,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	status := http.StatusOK
	if result.Status == "pending_review" {
		status = http.StatusAccepted
	}
	writeJSON(w, status, result)
}

func (h *apiHandler) handleGetSignStatus(w http.ResponseWriter, r *http.Request) {
	txID := chi.URLParam(r, "txId")
	if txID == "" {
		writeError(w, http.StatusBadRequest, "txId is required")
		return
	}

	result, err := h.svc.GetSignStatus(r.Context(), txID)
	if err != nil {
		writeError(w, http.StatusNotFound, "transaction not found")
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (h *apiHandler) handleListKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := h.svc.ListKeys(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	keysMap := make(map[string]KeyInfo, len(keys))
	for _, k := range keys {
		keysMap[k.DerivationPath] = k
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"keys": keysMap})
}

type updateLabelRequest struct {
	Label string `json:"label"`
}

func (h *apiHandler) handleUpdateLabel(w http.ResponseWriter, r *http.Request) {
	path := chi.URLParam(r, "path")
	if path == "" {
		writeError(w, http.StatusBadRequest, "path is required")
		return
	}

	var req updateLabelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.svc.store.UpdateLabel(r.Context(), path, req.Label); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *apiHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := h.svc.Health(r.Context())
	status := http.StatusOK
	if health.Status != "ok" {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, health)
}

func (h *apiHandler) handleAPIDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Write([]byte(apiDocsMarkdown))
}

const apiDocsMarkdown = `# Crypto Claw — MPC-TSS Signing Service

You are interacting with Crypto Claw, an MPC-TSS signing service running on localhost.
This service holds one share of a 2-of-2 threshold signature scheme. It cannot sign
transactions alone — every signing request is forwarded to a secure co-signer (Party B)
that runs an AI-powered transaction analyzer. Transactions may be auto-approved,
rejected, or escalated to the owner for manual approval via Telegram.

**You (the bot) are responsible for**: constructing transaction parameters, calling the
signing API, handling pending/escalated states, and broadcasting signed transactions
to the blockchain. This service handles key derivation, TSS signing, and returns the
signed transaction bytes.

Base URL: http://localhost:8080

---

## Quick Start

1. Check connectivity: GET /health
2. Derive a wallet: POST /derive with a BIP-44 path
3. Fund the wallet (wallet funding is the caller's responsibility)
4. Sign a transaction: POST /sign
5. If status is "pending_review", poll GET /sign/{txId} until resolved
6. Broadcast the signed transaction to the chain RPC

---

## Endpoints

### GET /health

Check service health and connectivity to the secure co-signer.

**Response:**
` + "```json" + `
{"status": "ok", "secureServerConnected": true}
` + "```" + `

Always check health before starting operations. If secureServerConnected is false,
signing will fail.

---

### POST /derive

Derive a new wallet address from the master key using a BIP-44 derivation path.
Each unique path produces a unique address. Derivation is deterministic — the same
path always produces the same address.

**Request:**
` + "```json" + `
{
  "derivationPath": "m/44'/60'/0'/0/0",
  "label": "My ETH Wallet"
}
` + "```" + `

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| derivationPath | string | yes | BIP-44 path (see derivation paths below) |
| label | string | no | Human-readable name for this wallet |
| prefix | string | no | Bech32 prefix for Cosmos app chains (e.g. "osmo", "juno", "inj"). Defaults to "cosmos" |

**Response:**
` + "```json" + `
{
  "address": "0x...",
  "derivationPath": "m/44'/60'/0'/0/0",
  "publicKey": "04..."
}
` + "```" + `

**Derivation path format:** m/44'/{coin_type}'/{account}'/{change}/{index}

| Chain | Coin Type | Example Path | Address Format |
|-------|-----------|-------------|----------------|
| Ethereum / EVM | 60 | m/44'/60'/0'/0/0 | 0x... (20 bytes) |
| Solana | 501 | m/44'/501'/0'/0' | Base58 (32 bytes) |
| Cosmos | 118 | m/44'/118'/0'/0/0 | cosmos1... (bech32). Pass prefix for app chains (osmo1..., juno1...) |

To derive multiple wallets for the same chain, increment the last index:
- m/44'/60'/0'/0/0 → first ETH wallet
- m/44'/60'/0'/0/1 → second ETH wallet

---

### POST /sign

Request a transaction to be signed. The transaction is sent to the secure co-signer
for analysis before signing. There are three possible outcomes:

1. **Approved** → signed transaction returned immediately (HTTP 200)
2. **Pending review** → escalated to owner via Telegram (HTTP 202). Poll /sign/{txId}
3. **Rejected** → transaction denied by the analyzer (HTTP 200, status: "rejected")

The endpoint is chain-agnostic. The derivationPath determines which VM adapter
handles the request. Only derivationPath and to are required — all other fields
are chain-specific and ignored by adapters that don't use them.

**Request fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| derivationPath | string | yes | BIP-44 path of the signing key |
| to | string[] | yes | Recipient address(es) |
| value | string | no | Value in smallest unit (wei, lamports, uatom) |
| data | string | no | Hex-encoded calldata (EVM only) |
| mint | string | no | Solana SPL token mint address (base58) |
| instructions | array | no | Solana raw program instructions (advanced) |
| program | string | no | Solana Anchor program ID (base58). Use with method/args |
| method | string | no | Anchor instruction name (e.g. "stake", "redeem") |
| args | object | no | Anchor instruction arguments as key-value strings |
| chainId | string | no | EVM chain ID (1=Ethereum, 56=BSC, 137=Polygon) or Cosmos chain ID |
| gasLimit | number | no | EVM gas limit |
| gasPrice | string | no | EVM gas price in wei |
| nonce | number | no | EVM transaction nonce |
| rpcUrl | string | no | Solana RPC endpoint URL. The service fetches a fresh blockhash right before signing. **Required for Solana** |
| prefix | string | no | Cosmos: bech32 prefix for app chains (e.g. "osmo"). Defaults to config value |
| denom | string | no | Cosmos: token denomination (e.g. "uosmo"). Defaults to config value |
| accountNumber | number | no | Cosmos: account number (query from chain) |
| sequence | number | no | Cosmos: account sequence / nonce (query from chain) |
| fee | string | no | Cosmos: fee amount in denom units (default: "5000") |
| gas | number | no | Cosmos: gas limit (default: 200000) |
| memo | string | no | Cosmos: transaction memo |

**EVM example** (ETH transfer):
` + "```json" + `
{
  "derivationPath": "m/44'/60'/0'/0/0",
  "to": ["0xRecipientAddress"],
  "value": "1000000000000000000",
  "chainId": "1",
  "gasLimit": 21000,
  "gasPrice": "20000000000",
  "nonce": 0
}
` + "```" + `

**Solana example** (SOL transfer):
` + "```json" + `
{
  "derivationPath": "m/44'/501'/0'/0'",
  "to": ["RecipientBase58Address"],
  "value": "1000000000",
  "rpcUrl": "https://api.mainnet-beta.solana.com"
}
` + "```" + `

**Solana example** (SPL token transfer):
` + "```json" + `
{
  "derivationPath": "m/44'/501'/0'/0'",
  "to": ["RecipientBase58Address"],
  "value": "1000000",
  "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  "rpcUrl": "https://api.mainnet-beta.solana.com"
}
` + "```" + `

The mint field is the SPL token mint address in base58.
The service automatically resolves Associated Token Accounts (ATAs) for sender and recipient.

**Solana example** (Anchor program call):
` + "```json" + `
{
  "derivationPath": "m/44'/501'/0'/0'",
  "program": "YourProgramId...",
  "method": "stake",
  "args": {"amount": "1000000000"},
  "mint": "TokenMintAddress...",
  "rpcUrl": "https://api.mainnet-beta.solana.com"
}
` + "```" + `

When using program/method/args, the service fetches the Anchor IDL from chain and
automatically resolves all accounts (PDAs, ATAs, system programs). The bot only needs
to specify the program, method name, arguments, and optionally the token mint.

**Solana example** (arbitrary program instruction — advanced):
` + "```json" + `
{
  "derivationPath": "m/44'/501'/0'/0'",
  "instructions": [
    {
      "programId": "YourProgramId...",
      "accounts": [
        {"pubkey": "Account1...", "isSigner": true, "isWritable": true},
        {"pubkey": "Account2...", "isSigner": false, "isWritable": true}
      ],
      "data": "base64EncodedInstructionData"
    }
  ],
  "rpcUrl": "https://api.mainnet-beta.solana.com"
}
` + "```" + `

When using instructions, the to field is optional. Each instruction specifies its own
programId, accounts, and data (base64-encoded). The payer is always the derived key
address (from derivationPath). Multiple instructions can be included in a single
transaction.

**Cosmos example** (ATOM transfer):
` + "```json" + `
{
  "derivationPath": "m/44'/118'/0'/0/0",
  "to": ["cosmos1recipient..."],
  "value": "1000000",
  "chainId": "cosmoshub-4",
  "accountNumber": 12345,
  "sequence": 0,
  "fee": "5000",
  "gas": 200000
}
` + "```" + `

**Cosmos app chain example** (OSMO transfer on Osmosis):
` + "```json" + `
{
  "derivationPath": "m/44'/118'/0'/0/0",
  "to": ["osmo1recipient..."],
  "value": "1000000",
  "chainId": "osmosis-1",
  "prefix": "osmo",
  "denom": "uosmo",
  "accountNumber": 67890,
  "sequence": 3,
  "fee": "2500",
  "gas": 100000
}
` + "```" + `

The signed transaction is returned as protobuf-encoded TxRaw (hex). Broadcast it via
the chain's REST endpoint: POST /cosmos/tx/v1beta1/txs with mode BROADCAST_MODE_SYNC.
Query accountNumber and sequence from /cosmos/auth/v1beta1/accounts/{address} before signing.

**Notes:**
- Solana: pass rpcUrl so the service fetches a fresh blockhash right before signing.
  This avoids blockhash expiry during Telegram approval flow (~60-90s validity).
- Solana SPL: pass the token mint address in the mint field (base58).
- EVM: if gasLimit/gasPrice/nonce are omitted, defaults are used. For production,
  fetch these from the chain RPC before signing.
- signedTx is returned as 0x-prefixed hex for all chains.

**Response (signed):** HTTP 200
` + "```json" + `
{
  "txId": "uuid",
  "status": "signed",
  "signedTx": "0x..."
}
` + "```" + `

**Response (pending review):** HTTP 202
` + "```json" + `
{
  "txId": "uuid",
  "status": "pending_review",
  "reason": "Large transfer flagged for manual approval"
}
` + "```" + `

**Response (rejected):** HTTP 200
` + "```json" + `
{
  "txId": "uuid",
  "status": "rejected",
  "reason": "Transaction to unverified contract"
}
` + "```" + `

**When you receive "pending_review":**
- Save the txId
- Poll GET /sign/{txId} periodically (every 5-10 seconds)
- The owner will approve or reject via Telegram
- Once approved, the response will include the signedTx
- Default timeout is 5 minutes — if the owner doesn't respond, status becomes "rejected"

---

### GET /sign/{txId}

Check the status of a previously submitted signing request.

**Response:**
` + "```json" + `
{
  "txId": "uuid",
  "status": "signed",
  "signedTx": "0x..."
}
` + "```" + `

Possible status values:
- "signed" — approved and signed, signedTx contains the signed transaction bytes
- "pending_review" — waiting for owner approval via Telegram
- "rejected" — denied by analyzer or owner

**Important:** Once you retrieve a signed transaction, it is deleted from memory.
Store it on your side if you need it later.

---

### GET /keys

List all derived keys and their addresses.

**Response:**
` + "```json" + `
{
  "keys": {
    "m/44'/60'/0'/0/0": {
      "derivationPath": "m/44'/60'/0'/0/0",
      "address": "0x...",
      "publicKey": "04...",
      "label": "My ETH Wallet"
    }
  }
}
` + "```" + `

Use this to check what wallets have already been derived before creating new ones.

---

### PUT /keys/{path}/label

Update the label of a derived key.

**Request:**
` + "```json" + `
{"label": "New Label"}
` + "```" + `

**Response:**
` + "```json" + `
{"ok": true}
` + "```" + `

---

## Error Handling

All errors return JSON:
` + "```json" + `
{"error": "description of what went wrong"}
` + "```" + `

Common errors:
- 400: Invalid request (missing fields, bad derivation path)
- 404: Transaction ID not found
- 500: Internal error (check /health for connectivity issues)
- 503: Secure co-signer not connected (secureServerConnected: false)

---

## Signing Flow Summary

` + "```" + `
Bot                    Party A (this API)           Party B (secure co-signer)
 |                          |                              |
 |-- POST /sign ----------->|                              |
 |                          |-- forwards tx for analysis ->|
 |                          |                              |-- TX analyzer runs
 |                          |                              |-- Decision: approve/reject/escalate
 |                          |<-- decision ----------------|
 |                          |                              |
 | If approved:             |                              |
 |<-- {status: "signed"} ---|                              |
 |                          |                              |
 | If escalated:            |                              |
 |<-- {status: "pending_review", txId} -|                  |
 |                          |           |-- Telegram notification to owner
 |-- GET /sign/{txId} ----->|           |
 |<-- {status: "pending_review"} -------|
 |   ... poll ...           |           |-- Owner approves via Telegram
 |-- GET /sign/{txId} ----->|           |
 |<-- {status: "signed", signedTx} ----|
 |                          |                              |
 | Bot broadcasts signedTx to blockchain RPC               |
` + "```" + `
`

// Helper functions

type apiError struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(apiError{Error: msg})
}

func hexDecode(s string) ([]byte, error) {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		high := hexVal(s[i])
		low := hexVal(s[i+1])
		if high == 0xFF || low == 0xFF {
			return nil, &json.InvalidUnmarshalError{}
		}
		b[i/2] = high<<4 | low
	}
	return b, nil
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0xFF
	}
}
