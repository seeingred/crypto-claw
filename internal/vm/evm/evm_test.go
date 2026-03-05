package evm

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestDeriveAddress(t *testing.T) {
	a := New()

	// Well-known test vector: keccak256 of a known public key.
	// Public key for private key 0x0000000000000000000000000000000000000000000000000000000000000001
	pubHex := "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
	pubKey, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatal(err)
	}

	addr, err := a.DeriveAddress(pubKey)
	if err != nil {
		t.Fatal(err)
	}

	// Known address for that private key
	expected := "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
	if !strings.EqualFold(addr, expected) {
		t.Errorf("DeriveAddress mismatch: got %s, want %s", addr, expected)
	}
}

func TestDeriveAddressInvalidKey(t *testing.T) {
	a := New()

	_, err := a.DeriveAddress([]byte{0x04, 0x01, 0x02})
	if err == nil {
		t.Error("expected error for short key")
	}

	badKey := make([]byte, 65)
	badKey[0] = 0x02 // compressed prefix, not uncompressed
	_, err = a.DeriveAddress(badKey)
	if err == nil {
		t.Error("expected error for non-uncompressed key")
	}
}
