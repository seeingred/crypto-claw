package main

import (
	"strings"
	"testing"
)

func TestGenerateMnemonicKeys(t *testing.T) {
	keys, err := GenerateMnemonicKeys()
	if err != nil {
		t.Fatalf("GenerateMnemonicKeys: %v", err)
	}

	// Mnemonic should be 24 words.
	words := strings.Split(keys.Mnemonic, " ")
	if len(words) != 24 {
		t.Errorf("mnemonic has %d words, want 24", len(words))
	}

	// ECDSA key checks.
	if keys.ECDSAPrivKey == nil || keys.ECDSAPrivKey.Sign() == 0 {
		t.Error("ECDSA private key is zero or nil")
	}
	if len(keys.ECDSAPubKey) != 65 {
		t.Errorf("ECDSA public key length = %d, want 65 (uncompressed)", len(keys.ECDSAPubKey))
	}
	if keys.ECDSAPubKey[0] != 0x04 {
		t.Errorf("ECDSA public key prefix = 0x%02x, want 0x04", keys.ECDSAPubKey[0])
	}
	if len(keys.ECDSAChainCode) != 32 {
		t.Errorf("ECDSA chain code length = %d, want 32", len(keys.ECDSAChainCode))
	}

	// EdDSA key checks.
	if keys.EdDSAPrivKey == nil || keys.EdDSAPrivKey.Sign() == 0 {
		t.Error("EdDSA private key is zero or nil")
	}
	if len(keys.EdDSAPubKey) != 32 {
		t.Errorf("EdDSA public key length = %d, want 32", len(keys.EdDSAPubKey))
	}
	if len(keys.EdDSAChainCode) != 32 {
		t.Errorf("EdDSA chain code length = %d, want 32", len(keys.EdDSAChainCode))
	}
}

func TestDeriveKeysFromMnemonicDeterministic(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

	keys1, err := DeriveKeysFromMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("first derivation: %v", err)
	}

	keys2, err := DeriveKeysFromMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("second derivation: %v", err)
	}

	// Same mnemonic must produce same keys.
	if keys1.ECDSAPrivKey.Cmp(keys2.ECDSAPrivKey) != 0 {
		t.Error("ECDSA private keys differ for same mnemonic")
	}
	if keys1.EdDSAPrivKey.Cmp(keys2.EdDSAPrivKey) != 0 {
		t.Error("EdDSA private keys differ for same mnemonic")
	}
}

func TestDeriveKeysInvalidMnemonic(t *testing.T) {
	_, err := DeriveKeysFromMnemonic("not a valid mnemonic")
	if err == nil {
		t.Error("expected error for invalid mnemonic")
	}
}
