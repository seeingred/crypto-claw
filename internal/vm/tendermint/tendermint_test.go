package tendermint

import (
	"bytes"
	"context"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/gogoproto/proto"

	"github.com/seeingred/crypto-claw/internal/tss"
	"github.com/seeingred/crypto-claw/internal/vm"
)

func TestDeriveAddress(t *testing.T) {
	a := New("cosmos", "uatom")

	// Known compressed public key -> known cosmos address
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

func TestDeriveAddressWithPrefixOption(t *testing.T) {
	a := New("cosmos", "uatom")

	pubHex := "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	pubKey, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatal(err)
	}

	// Derive with osmo prefix via option.
	addr, err := a.DeriveAddress(pubKey, vm.WithPrefix("osmo"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(addr, "osmo1") {
		t.Errorf("expected osmo1 prefix, got %s", addr)
	}

	// Default still cosmos.
	addr2, err := a.DeriveAddress(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(addr2, "cosmos1") {
		t.Errorf("expected cosmos1 prefix, got %s", addr2)
	}
}

// testPubKey returns an uncompressed secp256k1 public key for testing.
func testPubKey(t *testing.T) []byte {
	t.Helper()
	pubHex := "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
	pk, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func TestBuildAndDecodeTx(t *testing.T) {
	a := New("cosmos", "uatom")
	pk := testPubKey(t)

	unsignedTx, err := a.BuildUnsignedTx(context.Background(), &vm.TxRequest{
		From:    "cosmos1abc",
		To:      []string{"cosmos1def"},
		Value:   "1000000",
		ChainID: "cosmoshub-4",
		PubKey:  pk,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(unsignedTx.RawBytes) == 0 {
		t.Fatal("raw bytes empty")
	}
	if len(unsignedTx.Hash) != 32 {
		t.Fatalf("expected 32-byte hash, got %d", len(unsignedTx.Hash))
	}

	decoded, err := a.DecodeTx(unsignedTx.RawBytes)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.From != "cosmos1abc" {
		t.Errorf("from = %q, want cosmos1abc", decoded.From)
	}
	if len(decoded.To) != 1 || decoded.To[0] != "cosmos1def" {
		t.Errorf("to = %v, want [cosmos1def]", decoded.To)
	}
	if decoded.Value != "1000000" {
		t.Errorf("value = %q, want 1000000", decoded.Value)
	}
	if decoded.ChainID != "cosmoshub-4" {
		t.Errorf("chainID = %q, want cosmoshub-4", decoded.ChainID)
	}
}

func TestExtractSignableBytes(t *testing.T) {
	a := New("cosmos", "uatom")
	pk := testPubKey(t)

	unsignedTx, err := a.BuildUnsignedTx(context.Background(), &vm.TxRequest{
		From:    "cosmos1abc",
		To:      []string{"cosmos1def"},
		Value:   "1000000",
		ChainID: "cosmoshub-4",
		PubKey:  pk,
	})
	if err != nil {
		t.Fatal(err)
	}

	signable, err := a.ExtractSignableBytes(unsignedTx.RawBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(signable) != 32 {
		t.Fatalf("expected 32-byte hash, got %d", len(signable))
	}

	// Must match what BuildUnsignedTx produced.
	if !bytes.Equal(signable, unsignedTx.Hash) {
		t.Error("ExtractSignableBytes does not match BuildUnsignedTx hash")
	}
}

func TestAssembleSignedTxProducesValidTxRaw(t *testing.T) {
	a := New("cosmos", "uatom")
	pk := testPubKey(t)

	unsignedTx, err := a.BuildUnsignedTx(context.Background(), &vm.TxRequest{
		From:          "cosmos1abc",
		To:            []string{"cosmos1def"},
		Value:         "1000000",
		ChainID:       "cosmoshub-4",
		AccountNumber: 42,
		Sequence:      7,
		Gas:           100000,
		Fee:           "2500",
		PubKey:        pk,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Fake signature.
	sig := &tss.Signature{
		R: new(big.Int).SetInt64(123456789),
		S: new(big.Int).SetInt64(987654321),
	}

	signedTx, err := a.AssembleSignedTx(unsignedTx.RawBytes, sig)
	if err != nil {
		t.Fatal(err)
	}

	// Verify it's valid protobuf TxRaw.
	var txRaw txtypes.TxRaw
	if err := proto.Unmarshal(signedTx, &txRaw); err != nil {
		t.Fatalf("signed tx is not valid TxRaw protobuf: %v", err)
	}
	if len(txRaw.Signatures) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(txRaw.Signatures))
	}
	if len(txRaw.Signatures[0]) != 64 {
		t.Fatalf("expected 64-byte signature, got %d", len(txRaw.Signatures[0]))
	}
	if len(txRaw.BodyBytes) == 0 {
		t.Error("body_bytes is empty")
	}
	if len(txRaw.AuthInfoBytes) == 0 {
		t.Error("auth_info_bytes is empty")
	}
	t.Logf("TxRaw: %d bytes, sig: %x", len(signedTx), txRaw.Signatures[0])
}
