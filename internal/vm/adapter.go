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
	DeriveAddress(pubKey []byte) (string, error)

	// BuildUnsignedTx constructs an unsigned transaction from the request parameters.
	BuildUnsignedTx(ctx context.Context, req *TxRequest) (*UnsignedTx, error)

	// ExtractSignableBytes extracts the bytes that need to be signed from an unsigned tx.
	ExtractSignableBytes(unsignedTx []byte) ([]byte, error)

	// AssembleSignedTx combines the unsigned tx with a signature to produce a signed tx.
	AssembleSignedTx(unsignedTx []byte, sig *tss.Signature) ([]byte, error)

	// DecodeTx decodes raw transaction bytes into human-readable form.
	DecodeTx(txBytes []byte) (*DecodedTx, error)
}

// TxRequest represents a transaction construction request.
type TxRequest struct {
	From           string   `json:"from"`           // sender address
	To             []string `json:"to"`              // recipient address(es)
	Value          string   `json:"value,omitempty"` // native value (in smallest unit)
	Data           []byte   `json:"data,omitempty"`  // calldata for contract calls
	DerivationPath string   `json:"derivationPath"`

	// Chain-specific fields
	ChainID         string `json:"chainId,omitempty"`
	GasLimit        uint64 `json:"gasLimit,omitempty"`
	GasPrice        string `json:"gasPrice,omitempty"`
	Nonce           uint64 `json:"nonce,omitempty"`
	AutoNonce       bool   `json:"autoNonce,omitempty"`       // fetch nonce from chain
	RpcURL          string `json:"rpcUrl,omitempty"` // Solana RPC URL for fetching blockhash at sign time
	Mint            string `json:"mint,omitempty"`   // Solana SPL token mint (base58)
}

// UnsignedTx wraps a constructed unsigned transaction.
type UnsignedTx struct {
	RawBytes []byte   `json:"rawBytes"` // serialized unsigned tx
	Hash     []byte   `json:"hash"`     // signable hash
	To       []string `json:"to"`
	Value    string   `json:"value,omitempty"`
	Data     string   `json:"data,omitempty"` // hex calldata
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
