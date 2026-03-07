package main

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/tyler-smith/go-bip39"
)

// MnemonicKeys holds keys derived from a BIP-39 mnemonic.
type MnemonicKeys struct {
	Mnemonic       string
	ECDSAPrivKey   *big.Int // secp256k1 private key scalar
	ECDSAPubKey    []byte   // uncompressed 65 bytes
	ECDSAChainCode []byte   // 32 bytes (BIP-32)
	EdDSAPrivKey   *big.Int // ed25519 signing scalar (clamped)
	EdDSAPubKey    []byte   // 32 bytes (standard ed25519 encoding)
	EdDSAChainCode []byte   // 32 bytes
}

// GenerateMnemonicKeys generates a 24-word BIP-39 mnemonic and derives keys.
func GenerateMnemonicKeys() (*MnemonicKeys, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return nil, fmt.Errorf("generate entropy: %w", err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("generate mnemonic: %w", err)
	}

	return DeriveKeysFromMnemonic(mnemonic)
}

// DeriveKeysFromMnemonic derives ECDSA and EdDSA keys from an existing mnemonic.
func DeriveKeysFromMnemonic(mnemonic string) (*MnemonicKeys, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic")
	}

	seed := bip39.NewSeed(mnemonic, "")

	ecdsaPriv, ecdsaPub, ecdsaCC, err := deriveECDSAKey(seed)
	if err != nil {
		return nil, fmt.Errorf("derive ECDSA key: %w", err)
	}

	eddsaScalar, eddsaPub, eddsaCC, err := deriveEdDSAKey(seed)
	if err != nil {
		return nil, fmt.Errorf("derive EdDSA key: %w", err)
	}

	return &MnemonicKeys{
		Mnemonic:       mnemonic,
		ECDSAPrivKey:   ecdsaPriv,
		ECDSAPubKey:    ecdsaPub,
		ECDSAChainCode: ecdsaCC,
		EdDSAPrivKey:   eddsaScalar,
		EdDSAPubKey:    eddsaPub,
		EdDSAChainCode: eddsaCC,
	}, nil
}

// deriveECDSAKey derives the BIP-32 master key (at path "m") from a BIP-39 seed.
// It does NOT derive further down a BIP-44 path — that's handled by TSS derivation
// when the user calls /derive with a specific path like m/44'/60'/0'/0/0.
func deriveECDSAKey(seed []byte) (*big.Int, []byte, []byte, error) {
	curve := tss.S256()
	n := curve.Params().N

	// Master key: HMAC-SHA512(key="Bitcoin seed", data=seed)
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed)
	I := mac.Sum(nil)

	key := new(big.Int).SetBytes(I[:32])
	chainCode := make([]byte, 32)
	copy(chainCode, I[32:])

	if key.Sign() == 0 || key.Cmp(n) >= 0 {
		return nil, nil, nil, fmt.Errorf("invalid master key")
	}

	// Compute uncompressed public key (65 bytes: 0x04 || x || y)
	x, y := curve.ScalarBaseMult(key.Bytes())
	pubKey := elliptic.Marshal(curve, x, y)

	return key, pubKey, chainCode, nil
}

// deriveEdDSAKey derives an ed25519 key via SLIP-0010 path m/44'/501'/0'/0'.
// Returns the clamped signing scalar (for TSS splitting), the standard ed25519
// public key (32 bytes), and the BIP-32 chain code.
func deriveEdDSAKey(seed []byte) (*big.Int, []byte, []byte, error) {
	// Master key: HMAC-SHA512(key="ed25519 seed", data=seed)
	mac := hmac.New(sha512.New, []byte("ed25519 seed"))
	mac.Write(seed)
	I := mac.Sum(nil)

	key := make([]byte, 32)
	copy(key, I[:32])
	chainCode := make([]byte, 32)
	copy(chainCode, I[32:])

	// SLIP-0010 path: m/44'/501'/0'/0' (all hardened for ed25519)
	indices := []uint32{
		0x8000002C, // 44'
		0x800001F5, // 501'
		0x80000000, // 0'
		0x80000000, // 0'
	}

	for _, index := range indices {
		data := make([]byte, 37)
		data[0] = 0x00
		copy(data[1:33], key)
		binary.BigEndian.PutUint32(data[33:], index)

		mac := hmac.New(sha512.New, chainCode)
		mac.Write(data)
		I := mac.Sum(nil)

		copy(key, I[:32])
		copy(chainCode, I[32:])
	}

	// Compute standard ed25519 public key from the derived seed.
	privKey := ed25519.NewKeyFromSeed(key)
	pubKey := make([]byte, ed25519.PublicKeySize)
	copy(pubKey, privKey[ed25519.SeedSize:])

	// Compute the ed25519 signing scalar for TSS splitting.
	// Standard ed25519: scalar = clamp(SHA-512(seed)[:32])
	h := sha512.Sum512(key)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64

	// Convert from little-endian (ed25519 convention) to big-endian (big.Int)
	reversed := make([]byte, 32)
	for i := 0; i < 32; i++ {
		reversed[i] = h[31-i]
	}
	edScalar := new(big.Int).SetBytes(reversed)

	return edScalar, pubKey, chainCode, nil
}
