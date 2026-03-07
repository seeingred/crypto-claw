package tendermint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/bech32"

	"github.com/seeingred/crypto-claw/internal/tss"
	"github.com/seeingred/crypto-claw/internal/vm"
)

// Adapter implements the vm.Adapter interface for Cosmos/Tendermint chains.
type Adapter struct {
	Prefix string // bech32 prefix, e.g. "cosmos"
	Denom  string // native denom, e.g. "uatom"
}

var _ vm.Adapter = (*Adapter)(nil)

func New(prefix, denom string) *Adapter {
	if prefix == "" {
		prefix = "cosmos"
	}
	if denom == "" {
		denom = "uatom"
	}
	return &Adapter{Prefix: prefix, Denom: denom}
}

func (a *Adapter) Name() string     { return "tendermint" }
func (a *Adapter) Curve() tss.Curve { return tss.CurveSecp256k1 }

// DeriveAddress derives a bech32 Cosmos address from an uncompressed secp256k1 public key.
// It compresses the key, hashes it (sha256 + ripemd160), then bech32-encodes.
func (a *Adapter) DeriveAddress(pubKey []byte) (string, error) {
	var compressed []byte
	switch len(pubKey) {
	case 65:
		if pubKey[0] != 0x04 {
			return "", fmt.Errorf("tendermint: invalid uncompressed key prefix")
		}
		// Compress: take x-coord, set prefix based on y parity
		compressed = make([]byte, 33)
		if pubKey[64]%2 == 0 {
			compressed[0] = 0x02
		} else {
			compressed[0] = 0x03
		}
		copy(compressed[1:], pubKey[1:33])
	case 33:
		compressed = pubKey
	default:
		return "", fmt.Errorf("tendermint: expected 33 or 65-byte public key, got %d bytes", len(pubKey))
	}

	pk := &secp256k1.PubKey{Key: compressed}
	addr := pk.Address()

	bech, err := bech32.ConvertAndEncode(a.Prefix, addr)
	if err != nil {
		return "", fmt.Errorf("tendermint: bech32 encode: %w", err)
	}
	return bech, nil
}

// txEnvelope is the serialization wrapper for Tendermint transactions.
type txEnvelope struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Amount  string `json:"amount"`
	Denom   string `json:"denom"`
	ChainID string `json:"chainId"`
	Memo    string `json:"memo,omitempty"`
}

// BuildUnsignedTx constructs a simple Cosmos bank send message as a JSON envelope.
func (a *Adapter) BuildUnsignedTx(_ context.Context, req *vm.TxRequest) (*vm.UnsignedTx, error) {
	if len(req.To) == 0 {
		return nil, fmt.Errorf("tendermint: at least one recipient required")
	}

	env := txEnvelope{
		From:    req.From,
		To:      req.To[0],
		Amount:  req.Value,
		Denom:   a.Denom,
		ChainID: req.ChainID,
	}

	rawBytes, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("tendermint: marshal tx: %w", err)
	}

	// Cosmos SDK sign bytes are the JSON-sorted canonical encoding.
	// ECDSA signs a 32-byte hash, so we sha256 the canonical sign bytes.
	signBytes, err := sdk.SortJSON(rawBytes)
	if err != nil {
		signBytes = rawBytes
	}
	hash := sha256.Sum256(signBytes)

	return &vm.UnsignedTx{
		RawBytes: rawBytes,
		Hash:     hash[:],
		To:       req.To,
		Value:    req.Value,
	}, nil
}

// ExtractSignableBytes returns the sha256 hash of the canonical sign bytes.
func (a *Adapter) ExtractSignableBytes(unsignedTx []byte) ([]byte, error) {
	signBytes, err := sdk.SortJSON(unsignedTx)
	if err != nil {
		signBytes = unsignedTx
	}
	hash := sha256.Sum256(signBytes)
	return hash[:], nil
}

// AssembleSignedTx wraps the unsigned tx and signature into a signed envelope.
func (a *Adapter) AssembleSignedTx(unsignedTx []byte, sig *tss.Signature) ([]byte, error) {
	type signedEnvelope struct {
		Tx        json.RawMessage `json:"tx"`
		Signature string          `json:"signature"`
	}

	// Zero-pad R and S to 32 bytes each.
	rBytes := make([]byte, 32)
	sBytes := make([]byte, 32)
	rB := sig.R.Bytes()
	sB := sig.S.Bytes()
	copy(rBytes[32-len(rB):], rB)
	copy(sBytes[32-len(sB):], sB)

	env := signedEnvelope{
		Tx:        unsignedTx,
		Signature: hex.EncodeToString(rBytes) + hex.EncodeToString(sBytes),
	}

	raw, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("tendermint: marshal signed tx: %w", err)
	}
	return raw, nil
}

// DecodeTx decodes a JSON-encoded Tendermint transaction.
func (a *Adapter) DecodeTx(txBytes []byte) (*vm.DecodedTx, error) {
	var env txEnvelope
	if err := json.Unmarshal(txBytes, &env); err != nil {
		return nil, fmt.Errorf("tendermint: decode tx: %w", err)
	}
	return &vm.DecodedTx{
		From:    env.From,
		To:      []string{env.To},
		Value:   env.Amount,
		ChainID: env.ChainID,
	}, nil
}
