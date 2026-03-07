package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/tss"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/mr-tron/base58"
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

// compressPubKey returns the 33-byte SEC1 compressed public key.
func compressPubKey(x, y *big.Int) []byte {
	compressed := make([]byte, 33)
	if y.Bit(0) == 0 {
		compressed[0] = 0x02
	} else {
		compressed[0] = 0x03
	}
	xBytes := x.Bytes()
	copy(compressed[1+32-len(xBytes):], xBytes)
	return compressed
}

// DeriveECDSAKeyBIP44 derives a secp256k1 private key via standard BIP-32 path
// with proper hardened derivation. This produces keys compatible with Trust Wallet,
// MetaMask, and other standard BIP-44 wallets.
func DeriveECDSAKeyBIP44(mnemonic string, indices []uint32) (*big.Int, []byte, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, nil, fmt.Errorf("invalid mnemonic")
	}

	seed := bip39.NewSeed(mnemonic, "")
	curve := tss.S256()
	n := curve.Params().N

	// Master key
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed)
	I := mac.Sum(nil)

	key := new(big.Int).SetBytes(I[:32])
	chainCode := make([]byte, 32)
	copy(chainCode, I[32:])

	if key.Sign() == 0 || key.Cmp(n) >= 0 {
		return nil, nil, fmt.Errorf("invalid master key")
	}

	for _, index := range indices {
		var data []byte
		if index >= 0x80000000 {
			// Hardened child: 0x00 || ser256(key) || ser32(index)
			data = make([]byte, 37)
			data[0] = 0x00
			keyBytes := key.Bytes()
			copy(data[1+32-len(keyBytes):33], keyBytes)
			binary.BigEndian.PutUint32(data[33:], index)
		} else {
			// Normal child: serP(point(key)) || ser32(index)
			x, y := curve.ScalarBaseMult(key.Bytes())
			compressed := compressPubKey(x, y)
			data = make([]byte, 37)
			copy(data[:33], compressed)
			binary.BigEndian.PutUint32(data[33:], index)
		}

		mac := hmac.New(sha512.New, chainCode)
		mac.Write(data)
		I := mac.Sum(nil)

		il := new(big.Int).SetBytes(I[:32])
		if il.Cmp(n) >= 0 {
			return nil, nil, fmt.Errorf("derived key >= curve order at index %d", index)
		}

		childKey := new(big.Int).Add(il, key)
		childKey.Mod(childKey, n)
		if childKey.Sign() == 0 {
			return nil, nil, fmt.Errorf("derived key is zero at index %d", index)
		}

		key = childKey
		copy(chainCode, I[32:])
	}

	// Compute uncompressed public key
	x, y := curve.ScalarBaseMult(key.Bytes())
	pubKey := elliptic.Marshal(curve, x, y)

	return key, pubKey, nil
}

// DerivedKeyExport holds an exported private key for a single derivation path.
type DerivedKeyExport struct {
	Path       string `json:"path"`
	PrivKeyHex string `json:"privKeyHex"` // hex-encoded 32-byte private key
	Address    string `json:"address"`    // checksummed Ethereum address
}

// DeriveECDSAKeyTSS replicates TSS-style BIP-32 derivation using the full private key.
// TSS uses non-hardened (compressed pubkey) derivation at ALL levels, even for indices
// with the hardened bit set. This produces the exact same keys as the TSS /derive endpoint.
// Use this to recover funds from TSS-derived addresses when you only have the mnemonic.
func DeriveECDSAKeyTSS(mnemonic string, path string) (*DerivedKeyExport, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic")
	}

	indices, err := parseBIP32Path(path)
	if err != nil {
		return nil, fmt.Errorf("parse path: %w", err)
	}

	seed := bip39.NewSeed(mnemonic, "")
	curve := tss.S256()
	n := curve.Params().N

	// Master key at m
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed)
	I := mac.Sum(nil)

	key := new(big.Int).SetBytes(I[:32])
	chainCode := make([]byte, 32)
	copy(chainCode, I[32:])

	if key.Sign() == 0 || key.Cmp(n) >= 0 {
		return nil, fmt.Errorf("invalid master key")
	}

	// Derive each level using NON-HARDENED method (compressed pubkey),
	// exactly matching what TSS does regardless of the hardened bit.
	for _, index := range indices {
		x, y := curve.ScalarBaseMult(key.Bytes())
		compressed := compressPubKey(x, y)

		data := make([]byte, 37)
		copy(data[:33], compressed)
		binary.BigEndian.PutUint32(data[33:], index)

		mac := hmac.New(sha512.New, chainCode)
		mac.Write(data)
		I := mac.Sum(nil)

		il := new(big.Int).SetBytes(I[:32])
		if il.Cmp(n) >= 0 {
			return nil, fmt.Errorf("derived key >= curve order at index %d", index)
		}

		childKey := new(big.Int).Add(il, key)
		childKey.Mod(childKey, n)
		if childKey.Sign() == 0 {
			return nil, fmt.Errorf("derived key is zero at index %d", index)
		}

		key = childKey
		copy(chainCode, I[32:])
	}

	// Compute address
	x, y := curve.ScalarBaseMult(key.Bytes())
	addr := ethcrypto.PubkeyToAddress(ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}).Hex()

	// Pad private key to 32 bytes
	privBytes := key.Bytes()
	padded := make([]byte, 32)
	copy(padded[32-len(privBytes):], privBytes)

	return &DerivedKeyExport{
		Path:       path,
		PrivKeyHex: hex.EncodeToString(padded),
		Address:    addr,
	}, nil
}

// ExportSolanaKey derives the Solana private key from a mnemonic.
// This is the SLIP-0010 key at m/44'/501'/0'/0' — identical for both TSS and standard wallets
// since EdDSA TSS doesn't support derivation (always returns master).
func ExportSolanaKey(mnemonic string) (privKeyBase58, address string, err error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return "", "", fmt.Errorf("invalid mnemonic")
	}

	solSeed, solPub, err := deriveEdDSAKeyRaw(bip39.NewSeed(mnemonic, ""))
	if err != nil {
		return "", "", fmt.Errorf("derive SOL key: %w", err)
	}

	keypair := make([]byte, 64)
	copy(keypair[:32], solSeed)
	copy(keypair[32:], solPub)

	return base58.Encode(keypair), base58.Encode(solPub), nil
}

// parseBIP32Path parses "m/44'/60'/0'/0/0" into uint32 indices.
func parseBIP32Path(path string) ([]uint32, error) {
	if path == "" || path == "m" {
		return nil, fmt.Errorf("empty derivation path")
	}
	path = trimPrefix(path, "m/")
	parts := splitPath(path)
	indices := make([]uint32, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		hardened := false
		if len(part) > 0 && (part[len(part)-1] == '\'' || part[len(part)-1] == 'h' || part[len(part)-1] == 'H') {
			hardened = true
			part = part[:len(part)-1]
		}
		val := uint32(0)
		for _, c := range part {
			if c < '0' || c > '9' {
				return nil, fmt.Errorf("invalid path component: %s", part)
			}
			val = val*10 + uint32(c-'0')
		}
		if hardened {
			val += 0x80000000
		}
		indices = append(indices, val)
	}
	if len(indices) == 0 {
		return nil, fmt.Errorf("empty derivation path")
	}
	return indices, nil
}

func trimPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}

func splitPath(s string) []string {
	var parts []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '/' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return parts
}

// deriveEdDSAKeyRaw derives the raw ed25519 seed and public key via SLIP-0010.
// Returns the 32-byte seed (for wallet export) and the 32-byte public key.
func deriveEdDSAKeyRaw(seed []byte) ([]byte, []byte, error) {
	mac := hmac.New(sha512.New, []byte("ed25519 seed"))
	mac.Write(seed)
	I := mac.Sum(nil)

	key := make([]byte, 32)
	copy(key, I[:32])
	chainCode := make([]byte, 32)
	copy(chainCode, I[32:])

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

	privKey := ed25519.NewKeyFromSeed(key)
	pubKey := make([]byte, ed25519.PublicKeySize)
	copy(pubKey, privKey[ed25519.SeedSize:])

	return key, pubKey, nil
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
