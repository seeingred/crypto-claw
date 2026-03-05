package solana

import (
	"encoding/hex"
	"testing"
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
