package tss

import (
	"crypto/elliptic"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

func TestDealerSetupECDSA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping dealer test in short mode (needs safe prime generation)")
	}

	curve := tss.S256()
	n := curve.Params().N

	// Use a known private key.
	privKey := new(big.Int).SetInt64(12345678901234567)

	// Compute public key.
	x, y := curve.ScalarBaseMult(privKey.Bytes())
	pubKey := elliptic.Marshal(curve, x, y)
	chainCode := make([]byte, 32)
	chainCode[0] = 0x42

	parties := []PartyID{
		{ID: "party-a", Index: 0},
		{ID: "party-b", Index: 1},
	}

	// Generate pre-params (slow).
	ppA, err := keygen.GeneratePreParams(5 * time.Minute)
	if err != nil {
		t.Fatalf("generate pre-params A: %v", err)
	}
	ppB, err := keygen.GeneratePreParams(5 * time.Minute)
	if err != nil {
		t.Fatalf("generate pre-params B: %v", err)
	}

	shares, err := DealerSetupECDSA(privKey, pubKey, chainCode, parties, []*keygen.LocalPreParams{ppA, ppB})
	if err != nil {
		t.Fatalf("DealerSetupECDSA: %v", err)
	}

	if len(shares) != 2 {
		t.Fatalf("got %d shares, want 2", len(shares))
	}

	// Both shares should have same public key.
	if string(shares[0].PublicKey) != string(shares[1].PublicKey) {
		t.Error("public keys differ between shares")
	}

	// Shares should be different.
	if string(shares[0].Share) == string(shares[1].Share) {
		t.Error("shares should differ between parties")
	}

	// Verify curve and chain code.
	if shares[0].Curve != CurveSecp256k1 {
		t.Errorf("curve = %v, want secp256k1", shares[0].Curve)
	}
	if shares[0].ChainCode[0] != 0x42 {
		t.Error("chain code not preserved")
	}

	// Verify Lagrange reconstruction of private key.
	sortedIDs := makeSortedPartyIDs(parties)
	k0 := sortedIDs[0].KeyInt()
	k1 := sortedIDs[1].KeyInt()

	// For 2-of-2: s = x0 * L0(0) + x1 * L1(0)
	// L0(0) = -k1 / (k0 - k1) = k1 / (k1 - k0)
	// L1(0) = -k0 / (k1 - k0) = k0 / (k0 - k1)
	// Actually: L0(0) = (0-k1)/(k0-k1), L1(0) = (0-k0)/(k1-k0)

	// Deserialize shares to get Xi values.
	var save0, save1 keygen.LocalPartySaveData
	if err := json.Unmarshal(shares[0].Share, &save0); err != nil {
		t.Fatalf("unmarshal share 0: %v", err)
	}
	if err := json.Unmarshal(shares[1].Share, &save1); err != nil {
		t.Fatalf("unmarshal share 1: %v", err)
	}

	x0 := save0.Xi
	x1 := save1.Xi

	// Lagrange coefficients at 0.
	diff := new(big.Int).Sub(k0, k1)
	diff.Mod(diff, n)
	diffInv := new(big.Int).ModInverse(diff, n)
	l0 := new(big.Int).Mul(new(big.Int).Neg(k1), diffInv)
	l0.Mod(l0, n)

	diff1 := new(big.Int).Sub(k1, k0)
	diff1.Mod(diff1, n)
	diff1Inv := new(big.Int).ModInverse(diff1, n)
	l1 := new(big.Int).Mul(new(big.Int).Neg(k0), diff1Inv)
	l1.Mod(l1, n)

	// Reconstruct: s = x0*l0 + x1*l1 mod n
	reconstructed := new(big.Int).Mul(x0, l0)
	reconstructed.Add(reconstructed, new(big.Int).Mul(x1, l1))
	reconstructed.Mod(reconstructed, n)

	if reconstructed.Cmp(privKey) != 0 {
		t.Errorf("Lagrange reconstruction failed: got %s, want %s", reconstructed, privKey)
	}
}

func TestDealerSetupEdDSA(t *testing.T) {
	curve := tss.Edwards()
	n := curve.Params().N

	// Use a known scalar.
	scalar := new(big.Int).SetInt64(9876543210)

	// Compute public key point.
	x, y := curve.ScalarBaseMult(scalar.Bytes())
	pubKeyBytes := make([]byte, 32)
	xBytes := x.Bytes()
	copy(pubKeyBytes[32-len(xBytes):], xBytes)

	chainCode := make([]byte, 32)
	chainCode[0] = 0xAA

	parties := []PartyID{
		{ID: "party-a", Index: 0},
		{ID: "party-b", Index: 1},
	}

	shares, err := DealerSetupEdDSA(scalar, pubKeyBytes, chainCode, parties)
	if err != nil {
		t.Fatalf("DealerSetupEdDSA: %v", err)
	}

	if len(shares) != 2 {
		t.Fatalf("got %d shares, want 2", len(shares))
	}

	if string(shares[0].PublicKey) != string(shares[1].PublicKey) {
		t.Error("public keys differ")
	}
	if string(shares[0].Share) == string(shares[1].Share) {
		t.Error("shares should differ")
	}
	if shares[0].Curve != CurveEd25519 {
		t.Errorf("curve = %v, want ed25519", shares[0].Curve)
	}

	_ = y // used in computation above
	_ = n // Lagrange reconstruction tested in ECDSA test
}

func TestShamirSplit(t *testing.T) {
	n := new(big.Int).SetInt64(997) // small prime for testing
	secret := new(big.Int).SetInt64(42)
	shareIDs := []*big.Int{big.NewInt(1), big.NewInt(2)}

	shares, err := shamirSplit(secret, shareIDs, 1, n) // threshold=1 for 2-of-2
	if err != nil {
		t.Fatalf("shamirSplit: %v", err)
	}

	if len(shares) != 2 {
		t.Fatalf("got %d shares, want 2", len(shares))
	}

	// Verify Lagrange reconstruction.
	k0, k1 := shareIDs[0], shareIDs[1]
	x0, x1 := shares[0], shares[1]

	// L0(0) = -k1/(k0-k1) mod n
	diff := new(big.Int).Sub(k0, k1)
	diff.Mod(diff, n)
	diffInv := new(big.Int).ModInverse(diff, n)
	l0 := new(big.Int).Mul(new(big.Int).Neg(k1), diffInv)
	l0.Mod(l0, n)

	diff1 := new(big.Int).Sub(k1, k0)
	diff1.Mod(diff1, n)
	diff1Inv := new(big.Int).ModInverse(diff1, n)
	l1 := new(big.Int).Mul(new(big.Int).Neg(k0), diff1Inv)
	l1.Mod(l1, n)

	reconstructed := new(big.Int).Mul(x0, l0)
	reconstructed.Add(reconstructed, new(big.Int).Mul(x1, l1))
	reconstructed.Mod(reconstructed, n)

	if reconstructed.Cmp(secret) != 0 {
		t.Errorf("reconstruction = %s, want %s", reconstructed, secret)
	}
}
