package store

import (
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	s := &PostgresStore{
		encKey: deriveKey("test-passphrase"),
	}

	plaintext := []byte("sensitive key share data that must be protected")

	encrypted, err := s.encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if len(encrypted) <= len(plaintext) {
		t.Error("encrypted data should be larger than plaintext (nonce + tag)")
	}

	decrypted, err := s.decrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptDifferentKeys(t *testing.T) {
	s1 := &PostgresStore{encKey: deriveKey("passphrase-1")}
	s2 := &PostgresStore{encKey: deriveKey("passphrase-2")}

	plaintext := []byte("test data")

	encrypted, err := s1.encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	_, err = s2.decrypt(encrypted)
	if err == nil {
		t.Error("expected decryption with wrong key to fail")
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	key1 := deriveKey("my-passphrase")
	key2 := deriveKey("my-passphrase")

	if len(key1) != 32 {
		t.Errorf("key length = %d, want 32", len(key1))
	}

	for i := range key1 {
		if key1[i] != key2[i] {
			t.Fatal("same passphrase should produce same key")
		}
	}
}

func TestDeriveKeyDifferent(t *testing.T) {
	key1 := deriveKey("passphrase-1")
	key2 := deriveKey("passphrase-2")

	same := true
	for i := range key1 {
		if key1[i] != key2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("different passphrases should produce different keys")
	}
}
