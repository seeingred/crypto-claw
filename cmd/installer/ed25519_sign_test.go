package main

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/mr-tron/base58"
	"github.com/tyler-smith/go-bip39"

	"github.com/seeingred/crypto-claw/internal/tss"
)

func TestSignEd25519WithScalar(t *testing.T) {
	// Generate a standard ed25519 key, extract the scalar, sign with both methods.
	seed := make([]byte, 32)
	seed[0] = 42

	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey := privKey.Public().(ed25519.PublicKey)

	// Extract scalar from seed (same as ed25519 internally does)
	h := sha512.Sum512(seed)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	reversed := make([]byte, 32)
	for i := 0; i < 32; i++ {
		reversed[i] = h[31-i]
	}
	scalar := new(big.Int).SetBytes(reversed)

	message := []byte("test message for signing")

	// Sign with our raw scalar function
	sig, err := signEd25519WithScalar(scalar, pubKey, message)
	if err != nil {
		t.Fatalf("signEd25519WithScalar: %v", err)
	}

	// Verify the signature
	if !ed25519.Verify(pubKey, message, sig) {
		t.Fatal("signature verification failed!")
	}
	t.Log("Raw scalar signature verified OK")

	// Also verify with the standard library
	stdSig := ed25519.Sign(privKey, message)
	if !ed25519.Verify(pubKey, message, stdSig) {
		t.Fatal("standard signature verification failed!")
	}
	t.Log("Standard signature verified OK")

	// Signatures will differ (different nonce) but both should verify
	t.Logf("Raw sig:  %s", hex.EncodeToString(sig))
	t.Logf("Std sig:  %s", hex.EncodeToString(stdSig))
}

func TestSignWithTSSDerivedScalar(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	keys, err := DeriveKeysFromMnemonic(mnemonic)
	if err != nil {
		t.Fatal(err)
	}

	// Dealer split
	parties := []tss.PartyID{
		{ID: "party-a", Index: 0},
		{ID: "party-b", Index: 1},
	}
	shares, err := tss.DealerSetupEdDSA(
		keys.EdDSAPrivKey, keys.EdDSAPubKey, keys.EdDSAChainCode,
		parties,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Derive at m/44'/501'/0'/0' using TSS
	proto := tss.NewProtocol(1)
	derived, err := proto.DeriveKey(nil, shares[0], "m/44'/501'/0'/0'")
	if err != nil {
		t.Fatal(err)
	}

	tssPubKey := derived.PublicKey
	tssAddr := base58.Encode(tssPubKey)
	t.Logf("TSS derived address: %s", tssAddr)

	// Now derive the scalar using our export function
	scalar, pubKey, err := deriveScalarAtPath(mnemonic, "m/44'/501'/0'/0'")
	if err != nil {
		t.Fatal(err)
	}

	exportAddr := base58.Encode(pubKey)
	t.Logf("Export address:      %s", exportAddr)

	if tssAddr != exportAddr {
		t.Fatalf("address mismatch: TSS=%s Export=%s", tssAddr, exportAddr)
	}

	// Sign a message with the derived scalar
	message := []byte("test transaction message")
	sig, err := signEd25519WithScalar(scalar, pubKey, message)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Verify
	if !ed25519.Verify(pubKey, message, sig) {
		t.Fatal("TSS-derived scalar signature verification FAILED!")
	}
	t.Log("TSS-derived scalar signature verified OK!")
}

func TestDeriveScalarAtPathConsistency(t *testing.T) {
	mnemonics := []string{
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
	}

	for _, mnemonic := range mnemonics {
		if !bip39.IsMnemonicValid(mnemonic) {
			continue
		}
		t.Run(mnemonic[:20], func(t *testing.T) {
			paths := []string{"m/44'/501'/0'/0'", "m/44'/501'/0'/1'"}
			for _, path := range paths {
				scalar, pubKey, err := deriveScalarAtPath(mnemonic, path)
				if err != nil {
					t.Fatal(err)
				}

				// Sign and verify
				msg := []byte("sweep transaction")
				sig, err := signEd25519WithScalar(scalar, pubKey, msg)
				if err != nil {
					t.Fatal(err)
				}
				if !ed25519.Verify(pubKey, msg, sig) {
					t.Errorf("%s: signature verification failed", path)
				} else {
					t.Logf("%s: %s OK", path, base58.Encode(pubKey))
				}
			}
		})
	}
}
