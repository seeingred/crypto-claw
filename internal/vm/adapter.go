package vm

import (
	"context"

	"github.com/seeingred/crypto-claw/internal/tss"
)

// Adapter defines the interface for chain-specific transaction handling.
type Adapter interface {
	// Name returns the chain/VM name (e.g. "evm", "solana", "tendermint").
	Name() string

	// Curve returns the elliptic curve used by this chain.
	Curve() tss.Curve

	// DeriveAddress computes the chain-specific address from a public key.
	// Options (e.g. bech32 prefix for Cosmos) can be passed via opts.
	DeriveAddress(pubKey []byte, opts ...DeriveOption) (string, error)

	// BuildUnsignedTx constructs an unsigned transaction from the request parameters.
	BuildUnsignedTx(ctx context.Context, req *TxRequest) (*UnsignedTx, error)

	// ExtractSignableBytes extracts the bytes that need to be signed from an unsigned tx.
	ExtractSignableBytes(unsignedTx []byte) ([]byte, error)

	// AssembleSignedTx combines the unsigned tx with a signature to produce a signed tx.
	AssembleSignedTx(unsignedTx []byte, sig *tss.Signature) ([]byte, error)

	// DecodeTx decodes raw transaction bytes into human-readable form.
	DecodeTx(txBytes []byte) (*DecodedTx, error)
}

// SolanaAccountMeta describes an account input for a Solana instruction.
type SolanaAccountMeta struct {
	Pubkey     string `json:"pubkey"`
	IsSigner   bool   `json:"isSigner"`
	IsWritable bool   `json:"isWritable"`
}

// SolanaInstruction describes a single Solana program instruction.
type SolanaInstruction struct {
	ProgramID string              `json:"programId"`
	Accounts  []SolanaAccountMeta `json:"accounts"`
	Data      string              `json:"data"` // base64-encoded instruction data
}

// TxRequest represents a transaction construction request.
type TxRequest struct {
	From           string   `json:"from"`           // sender address
	To             []string `json:"to"`              // recipient address(es)
	Value          string   `json:"value,omitempty"` // native value (in smallest unit)
	Data           []byte   `json:"data,omitempty"`  // calldata for contract calls
	DerivationPath string   `json:"derivationPath"`

	// Chain-specific fields
	Prefix          string `json:"prefix,omitempty"`         // bech32 prefix for Cosmos app chains (e.g. "osmo")
	Denom           string `json:"denom,omitempty"`          // token denomination for Cosmos (e.g. "uosmo")
	ChainID         string `json:"chainId,omitempty"`
	AccountNumber   uint64 `json:"accountNumber,omitempty"`  // Cosmos account number
	Sequence        uint64 `json:"sequence,omitempty"`       // Cosmos account sequence (like EVM nonce)
	Fee             string `json:"fee,omitempty"`            // Cosmos fee amount in denom units
	Gas             uint64 `json:"gas,omitempty"`            // Cosmos gas limit
	Memo            string `json:"memo,omitempty"`           // Cosmos memo field
	PubKey          []byte `json:"-"`                        // signer public key (set internally)
	GasLimit        uint64 `json:"gasLimit,omitempty"`
	GasPrice        string `json:"gasPrice,omitempty"`
	Nonce           uint64 `json:"nonce,omitempty"`
	AutoNonce       bool   `json:"autoNonce,omitempty"`       // fetch nonce from chain
	RpcURL          string `json:"rpcUrl,omitempty"` // Solana RPC URL for fetching blockhash at sign time
	Mint            string `json:"mint,omitempty"`   // Solana SPL token mint (base58)

	// Solana: raw instructions for arbitrary program calls
	Instructions []SolanaInstruction `json:"instructions,omitempty"`

	// Solana: Anchor program call (IDL-based, auto-resolves accounts/PDAs)
	Program string            `json:"program,omitempty"` // program ID (base58)
	Method  string            `json:"method,omitempty"`  // instruction name
	Args    map[string]string `json:"args,omitempty"`    // instruction arguments
}

// UnsignedTx wraps a constructed unsigned transaction.
type UnsignedTx struct {
	RawBytes    []byte   `json:"rawBytes"` // serialized unsigned tx
	Hash        []byte   `json:"hash"`     // signable hash
	To          []string `json:"to"`
	Value       string   `json:"value,omitempty"`
	Data        string   `json:"data,omitempty"` // hex calldata
	// Solana: ephemeral private keys for additional signers (e.g. new account keypairs).
	// These sign the final message after blockhash injection, alongside the TSS signature.
	ExtraSignerKeys [][]byte `json:"-"` // each is a 64-byte ed25519 private key
}

// DecodedTx holds human-readable transaction info.
type DecodedTx struct {
	From     string            `json:"from,omitempty"`
	To       []string          `json:"to"`
	Value    string            `json:"value,omitempty"`
	Data     string            `json:"data,omitempty"`
	Method   string            `json:"method,omitempty"` // decoded function name
	Args     map[string]string `json:"args,omitempty"`   // decoded function args
	ChainID  string            `json:"chainId,omitempty"`
	GasLimit uint64            `json:"gasLimit,omitempty"`
}

// DeriveOption configures address derivation.
type DeriveOption func(*deriveOpts)

type deriveOpts struct {
	Prefix string
}

// WithPrefix sets the bech32 prefix for Cosmos address derivation.
func WithPrefix(prefix string) DeriveOption {
	return func(o *deriveOpts) { o.Prefix = prefix }
}

// ApplyDeriveOpts applies options and returns the resolved config.
func ApplyDeriveOpts(opts []DeriveOption) deriveOpts {
	var o deriveOpts
	for _, fn := range opts {
		fn(&o)
	}
	return o
}

// Registry holds available VM adapters keyed by derivation path prefix.
type Registry struct {
	adapters map[string]Adapter // derivation path prefix -> adapter
}

// NewRegistry creates a new adapter registry.
func NewRegistry() *Registry {
	return &Registry{adapters: make(map[string]Adapter)}
}

// Register adds an adapter for the given derivation path prefixes.
func (r *Registry) Register(prefixes []string, adapter Adapter) {
	for _, p := range prefixes {
		r.adapters[p] = adapter
	}
}

// ForPath returns the adapter matching the given derivation path.
// It matches by the coin type component (e.g. "60" for EVM from m/44'/60'/...).
func (r *Registry) ForPath(derivationPath string) (Adapter, bool) {
	coinType := extractCoinType(derivationPath)
	if coinType == "" {
		return nil, false
	}
	a, ok := r.adapters[coinType]
	return a, ok
}

// extractCoinType pulls the coin type from a BIP-44 path like m/44'/60'/0'/0/0.
func extractCoinType(path string) string {
	// Simple parser: split by '/' and get the 3rd component (index 2), strip trailing '
	parts := splitPath(path)
	if len(parts) < 3 {
		return ""
	}
	ct := parts[2]
	// Strip trailing apostrophe for hardened derivation
	if len(ct) > 0 && ct[len(ct)-1] == '\'' {
		ct = ct[:len(ct)-1]
	}
	return ct
}

func splitPath(path string) []string {
	var parts []string
	current := ""
	for _, c := range path {
		if c == '/' {
			if current != "" {
				parts = append(parts, current)
			}
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
