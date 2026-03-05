package tendermint

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestDeriveAddress(t *testing.T) {
	a := New("cosmos", "uatom")

	// Known compressed public key -> known cosmos address
	// Using a test vector: compressed secp256k1 pubkey
	pubHex := "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
	pubKey, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatal(err)
	}

	addr, err := a.DeriveAddress(pubKey)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(addr, "cosmos1") {
		t.Errorf("expected cosmos1 prefix, got %s", addr)
	}
	t.Logf("Derived Cosmos address: %s", addr)
}

func TestDeriveAddressCompressed(t *testing.T) {
	a := New("cosmos", "uatom")

	// Compressed key (33 bytes)
	pubHex := "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	pubKey, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatal(err)
	}

	addr, err := a.DeriveAddress(pubKey)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(addr, "cosmos1") {
		t.Errorf("expected cosmos1 prefix, got %s", addr)
	}
	t.Logf("Derived Cosmos address (compressed): %s", addr)
}

func TestDeriveAddressInvalidKey(t *testing.T) {
	a := New("cosmos", "uatom")

	_, err := a.DeriveAddress([]byte{0x01, 0x02})
	if err == nil {
		t.Error("expected error for invalid key length")
	}
}

func TestDeriveAddressCustomPrefix(t *testing.T) {
	a := New("osmo", "uosmo")

	pubHex := "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	pubKey, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatal(err)
	}

	addr, err := a.DeriveAddress(pubKey)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(addr, "osmo1") {
		t.Errorf("expected osmo1 prefix, got %s", addr)
	}
}
