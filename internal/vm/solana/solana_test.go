package solana

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/seeingred/crypto-claw/internal/vm"
)

func TestDeriveAddress(t *testing.T) {
	a := New()

	// A known ed25519 public key (32 bytes of zeros should produce a valid base58 address).
	pubKey := make([]byte, 32)
	addr, err := a.DeriveAddress(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	// base58 of 32 zero bytes
	expected := "11111111111111111111111111111111"
	if addr != expected {
		t.Errorf("DeriveAddress mismatch: got %s, want %s", addr, expected)
	}
}

func TestDeriveAddressRealKey(t *testing.T) {
	a := New()

	// Specific 32-byte key
	pubHex := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	pubKey, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatal(err)
	}

	addr, err := a.DeriveAddress(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	if addr == "" {
		t.Error("expected non-empty address")
	}
	t.Logf("Derived Solana address: %s", addr)
}

func TestDeriveAddressInvalidKey(t *testing.T) {
	a := New()

	_, err := a.DeriveAddress([]byte{0x01, 0x02})
	if err == nil {
		t.Error("expected error for short key")
	}
}

func TestBuildAndDecodeTx(t *testing.T) {
	a := New()

	// Use valid base58 Solana addresses (32 zero bytes = system program).
	from := "11111111111111111111111111111111"
	to := "11111111111111111111111111111112"

	unsignedTx, err := a.BuildUnsignedTx(context.Background(), &vm.TxRequest{
		From:  from,
		To:    []string{to},
		Value: "1000000000", // 1 SOL in lamports
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(unsignedTx.RawBytes) == 0 {
		t.Fatal("raw bytes empty")
	}
	if len(unsignedTx.Hash) == 0 {
		t.Fatal("hash empty")
	}

	decoded, err := a.DecodeTx(unsignedTx.RawBytes)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.From == "" {
		t.Error("decoded from is empty")
	}
	if len(decoded.To) == 0 {
		t.Error("decoded to is empty")
	}
}

func TestExtractSignableBytes(t *testing.T) {
	a := New()

	from := "11111111111111111111111111111111"
	to := "11111111111111111111111111111112"

	unsignedTx, err := a.BuildUnsignedTx(context.Background(), &vm.TxRequest{
		From:  from,
		To:    []string{to},
		Value: "1000000000",
	})
	if err != nil {
		t.Fatal(err)
	}

	signable, err := a.ExtractSignableBytes(unsignedTx.RawBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(signable) == 0 {
		t.Fatal("signable bytes empty")
	}
}
