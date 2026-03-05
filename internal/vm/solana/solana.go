package solana

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"

	"github.com/seeingred/crypto-claw/internal/tss"
	"github.com/seeingred/crypto-claw/internal/vm"
)

// Adapter implements the vm.Adapter interface for Solana.
type Adapter struct{}

var _ vm.Adapter = (*Adapter)(nil)

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string     { return "solana" }
func (a *Adapter) Curve() tss.Curve { return tss.CurveEd25519 }

// DeriveAddress returns the base58-encoded address from a 32-byte ed25519 public key.
func (a *Adapter) DeriveAddress(pubKey []byte) (string, error) {
	if len(pubKey) != 32 {
		return "", fmt.Errorf("solana: expected 32-byte ed25519 public key, got %d bytes", len(pubKey))
	}
	pk := solana.PublicKeyFromBytes(pubKey)
	return pk.String(), nil
}

// txEnvelope is the serialization wrapper for Solana unsigned transactions.
type txEnvelope struct {
	Type       string `json:"type"`       // "sol_transfer" or "spl_transfer"
	From       string `json:"from"`
	To         string `json:"to"`
	Amount     uint64 `json:"amount"`
	Mint       string `json:"mint,omitempty"`       // SPL token mint
	RecentHash string `json:"recentHash,omitempty"` // recent blockhash
}

// BuildUnsignedTx constructs a Solana transaction for SOL or SPL token transfers.
func (a *Adapter) BuildUnsignedTx(_ context.Context, req *vm.TxRequest) (*vm.UnsignedTx, error) {
	if len(req.To) == 0 {
		return nil, fmt.Errorf("solana: at least one recipient required")
	}

	from := solana.MustPublicKeyFromBase58(req.From)
	to := solana.MustPublicKeyFromBase58(req.To[0])

	var amount uint64
	if req.Value != "" {
		if _, err := fmt.Sscanf(req.Value, "%d", &amount); err != nil {
			return nil, fmt.Errorf("solana: invalid value %q: %w", req.Value, err)
		}
	}

	var instructions []solana.Instruction

	if len(req.Data) > 0 {
		// SPL token transfer: Data contains the mint address as raw bytes (base58 encoded in the envelope).
		mint := solana.PublicKeyFromBytes(req.Data[:32])
		fromATA, _, err := solana.FindAssociatedTokenAddress(from, mint)
		if err != nil {
			return nil, fmt.Errorf("solana: find from ATA: %w", err)
		}
		toATA, _, err := solana.FindAssociatedTokenAddress(to, mint)
		if err != nil {
			return nil, fmt.Errorf("solana: find to ATA: %w", err)
		}

		instructions = append(instructions,
			token.NewTransferInstruction(amount, fromATA, toATA, from, nil).Build(),
		)
	} else {
		// Simple SOL transfer
		instructions = append(instructions,
			system.NewTransferInstruction(amount, from, to).Build(),
		)
	}

	tx, err := solana.NewTransaction(
		instructions,
		solana.Hash{}, // placeholder blockhash; set at broadcast time
		solana.TransactionPayer(from),
	)
	if err != nil {
		return nil, fmt.Errorf("solana: build tx: %w", err)
	}

	msgBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("solana: serialize message: %w", err)
	}

	rawBytes, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("solana: serialize tx: %w", err)
	}

	return &vm.UnsignedTx{
		RawBytes: rawBytes,
		Hash:     msgBytes, // Solana signs the message bytes directly
		To:       req.To,
		Value:    req.Value,
	}, nil
}

// ExtractSignableBytes returns the transaction message bytes to be signed.
func (a *Adapter) ExtractSignableBytes(unsignedTx []byte) ([]byte, error) {
	tx, err := solana.TransactionFromBytes(unsignedTx)
	if err != nil {
		return nil, fmt.Errorf("solana: decode tx: %w", err)
	}
	msgBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("solana: serialize message: %w", err)
	}
	return msgBytes, nil
}

// AssembleSignedTx places the ed25519 signature into the transaction.
func (a *Adapter) AssembleSignedTx(unsignedTx []byte, sig *tss.Signature) ([]byte, error) {
	tx, err := solana.TransactionFromBytes(unsignedTx)
	if err != nil {
		return nil, fmt.Errorf("solana: decode tx: %w", err)
	}

	if len(sig.Bytes) != 64 {
		return nil, fmt.Errorf("solana: expected 64-byte ed25519 signature, got %d", len(sig.Bytes))
	}

	var solSig solana.Signature
	copy(solSig[:], sig.Bytes)
	tx.Signatures = []solana.Signature{solSig}

	raw, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("solana: serialize signed tx: %w", err)
	}
	return raw, nil
}

// DecodeTx decodes a serialized Solana transaction into human-readable form.
func (a *Adapter) DecodeTx(txBytes []byte) (*vm.DecodedTx, error) {
	tx, err := solana.TransactionFromBytes(txBytes)
	if err != nil {
		// Try as JSON envelope
		var env txEnvelope
		if jsonErr := json.Unmarshal(txBytes, &env); jsonErr == nil {
			return &vm.DecodedTx{
				From:  env.From,
				To:    []string{env.To},
				Value: fmt.Sprintf("%d", env.Amount),
			}, nil
		}
		return nil, fmt.Errorf("solana: decode tx: %w", err)
	}

	decoded := &vm.DecodedTx{}
	if len(tx.Message.AccountKeys) > 0 {
		decoded.From = tx.Message.AccountKeys[0].String()
	}
	if len(tx.Message.AccountKeys) > 1 {
		decoded.To = []string{tx.Message.AccountKeys[1].String()}
	}
	return decoded, nil
}
