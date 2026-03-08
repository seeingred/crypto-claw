package evm

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/seeingred/crypto-claw/internal/tss"
	"github.com/seeingred/crypto-claw/internal/vm"
)

// Adapter implements the vm.Adapter interface for EVM-compatible chains.
type Adapter struct{}

var _ vm.Adapter = (*Adapter)(nil)

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string       { return "evm" }
func (a *Adapter) Curve() tss.Curve   { return tss.CurveSecp256k1 }

// DeriveAddress computes an Ethereum address from an uncompressed secp256k1 public key.
// Address = last 20 bytes of keccak256(pubkey[1:]).
func (a *Adapter) DeriveAddress(pubKey []byte, _ ...vm.DeriveOption) (string, error) {
	if len(pubKey) != 65 || pubKey[0] != 0x04 {
		return "", fmt.Errorf("evm: expected 65-byte uncompressed public key, got %d bytes", len(pubKey))
	}
	hash := crypto.Keccak256(pubKey[1:])
	addr := common.BytesToAddress(hash[12:])
	return addr.Hex(), nil
}

// BuildUnsignedTx constructs an unsigned EVM transaction.
func (a *Adapter) BuildUnsignedTx(_ context.Context, req *vm.TxRequest) (*vm.UnsignedTx, error) {
	if len(req.To) == 0 {
		return nil, fmt.Errorf("evm: at least one recipient required")
	}

	value := new(big.Int)
	if req.Value != "" {
		if _, ok := value.SetString(req.Value, 10); !ok {
			return nil, fmt.Errorf("evm: invalid value %q", req.Value)
		}
	}

	gasPrice := new(big.Int)
	if req.GasPrice != "" {
		if _, ok := gasPrice.SetString(req.GasPrice, 10); !ok {
			return nil, fmt.Errorf("evm: invalid gas price %q", req.GasPrice)
		}
	}

	gasLimit := req.GasLimit
	if gasLimit == 0 {
		gasLimit = 21000 // default for simple transfers
		if len(req.Data) > 0 {
			gasLimit = 100000
		}
	}

	chainID := new(big.Int)
	if req.ChainID != "" {
		if _, ok := chainID.SetString(req.ChainID, 10); !ok {
			return nil, fmt.Errorf("evm: invalid chain ID %q", req.ChainID)
		}
	} else {
		chainID.SetInt64(1) // default to Ethereum mainnet
	}

	to := common.HexToAddress(req.To[0])

	// Set V = chainId*2 + 35 (EIP-155 unsigned convention) so that
	// tx.ChainId() correctly recovers the chainId when decoding later.
	eip155V := new(big.Int).Add(
		new(big.Int).Mul(chainID, big.NewInt(2)),
		big.NewInt(35),
	)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    req.Nonce,
		To:       &to,
		Value:    value,
		Gas:      gasLimit,
		GasPrice: gasPrice,
		Data:     req.Data,
		V:        eip155V,
		R:        new(big.Int),
		S:        new(big.Int),
	})

	signer := types.NewEIP155Signer(chainID)
	hash := signer.Hash(tx)

	rawBytes, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return nil, fmt.Errorf("evm: encode tx: %w", err)
	}

	var dataHex string
	if len(req.Data) > 0 {
		dataHex = "0x" + hex.EncodeToString(req.Data)
	}

	return &vm.UnsignedTx{
		RawBytes: rawBytes,
		Hash:     hash[:],
		To:       req.To,
		Value:    req.Value,
		Data:     dataHex,
	}, nil
}

// ExtractSignableBytes extracts the transaction hash from RLP-encoded unsigned tx bytes.
func (a *Adapter) ExtractSignableBytes(unsignedTx []byte) ([]byte, error) {
	var tx types.Transaction
	if err := rlp.DecodeBytes(unsignedTx, &tx); err != nil {
		return nil, fmt.Errorf("evm: decode unsigned tx: %w", err)
	}
	// Default to chain ID 1 for signer; in production the chain ID comes from the tx itself.
	signer := types.NewEIP155Signer(tx.ChainId())
	hash := signer.Hash(&tx)
	return hash[:], nil
}

// AssembleSignedTx combines an unsigned tx with a TSS signature to produce a signed tx.
func (a *Adapter) AssembleSignedTx(unsignedTx []byte, sig *tss.Signature) ([]byte, error) {
	var tx types.Transaction
	if err := rlp.DecodeBytes(unsignedTx, &tx); err != nil {
		return nil, fmt.Errorf("evm: decode unsigned tx: %w", err)
	}

	chainID := tx.ChainId()
	signer := types.NewEIP155Signer(chainID)

	// Build 65-byte signature: R (32 bytes) || S (32 bytes) || V (1 byte).
	// R and S must be zero-padded to 32 bytes each.
	// V is the recovery ID (0 or 1) from tss-lib; go-ethereum's WithSignature
	// converts it to EIP-155 format (chainId*2 + 35 + V) internally.
	sigBytes := make([]byte, 65)
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)
	sigBytes[64] = sig.V

	signedTx, err := tx.WithSignature(signer, sigBytes)
	if err != nil {
		return nil, fmt.Errorf("evm: apply signature: %w", err)
	}

	raw, err := rlp.EncodeToBytes(signedTx)
	if err != nil {
		return nil, fmt.Errorf("evm: encode signed tx: %w", err)
	}
	return raw, nil
}

// DecodeTx decodes a raw RLP-encoded transaction into human-readable form.
func (a *Adapter) DecodeTx(txBytes []byte) (*vm.DecodedTx, error) {
	var tx types.Transaction
	if err := rlp.DecodeBytes(txBytes, &tx); err != nil {
		return nil, fmt.Errorf("evm: decode tx: %w", err)
	}

	decoded := &vm.DecodedTx{
		Value:    tx.Value().String(),
		ChainID:  tx.ChainId().String(),
		GasLimit: tx.Gas(),
	}
	if tx.To() != nil {
		decoded.To = []string{tx.To().Hex()}
	}
	if len(tx.Data()) > 0 {
		decoded.Data = "0x" + hex.EncodeToString(tx.Data())
		if len(tx.Data()) >= 4 {
			decoded.Method = "0x" + hex.EncodeToString(tx.Data()[:4])
		}
	}

	// Try to recover sender
	signer := types.LatestSignerForChainID(tx.ChainId())
	if sender, err := types.Sender(signer, &tx); err == nil {
		decoded.From = sender.Hex()
	}

	return decoded, nil
}

// PubKeyToECDSA converts an uncompressed 65-byte public key to an ecdsa.PublicKey
// on the secp256k1 curve.
func PubKeyToECDSA(pubKey []byte) (*ecdsa.PublicKey, error) {
	if len(pubKey) != 65 || pubKey[0] != 0x04 {
		return nil, fmt.Errorf("evm: expected 65-byte uncompressed public key")
	}
	x := new(big.Int).SetBytes(pubKey[1:33])
	y := new(big.Int).SetBytes(pubKey[33:65])
	return &ecdsa.PublicKey{
		Curve: crypto.S256(),
		X:     x,
		Y:     y,
	}, nil
}
