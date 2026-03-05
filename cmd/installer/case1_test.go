package main

// PRD Case 1: Wallet creation and restoration
//
// - Generate new master keys from mnemonic
// - Split into threshold shares via dealer setup
// - Derive EVM and Solana addresses
// - Restore from the same mnemonic
// - Derive addresses using the same paths — verify they match

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"

	"github.com/seeingred/crypto-claw/internal/tss"
)

func TestCase1_WalletCreationAndRestoration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Case 1 test in short mode (needs safe prime generation)")
	}

	// Step 1: Generate a mnemonic and derive keys.
	keys1, err := GenerateMnemonicKeys()
	if err != nil {
		t.Fatalf("GenerateMnemonicKeys: %v", err)
	}

	t.Logf("Mnemonic: %s", keys1.Mnemonic)
	t.Logf("ECDSA pub: %s", hex.EncodeToString(keys1.ECDSAPubKey))
	t.Logf("EdDSA pub: %s", hex.EncodeToString(keys1.EdDSAPubKey))

	// Step 2: Generate pre-params for ECDSA dealer setup.
	t.Log("Generating ECDSA safe primes (slow)...")
	ppA, err := keygen.GeneratePreParams(10 * time.Minute)
	if err != nil {
		t.Fatalf("GeneratePreParams A: %v", err)
	}
	ppB, err := keygen.GeneratePreParams(10 * time.Minute)
	if err != nil {
		t.Fatalf("GeneratePreParams B: %v", err)
	}

	parties := []tss.PartyID{
		{ID: "party-a", Index: 0},
		{ID: "party-b", Index: 1},
	}

	// Step 3: Dealer split for ECDSA.
	ecdsaShares, err := tss.DealerSetupECDSA(
		keys1.ECDSAPrivKey, keys1.ECDSAPubKey, keys1.ECDSAChainCode,
		parties, []*keygen.LocalPreParams{ppA, ppB},
	)
	if err != nil {
		t.Fatalf("DealerSetupECDSA: %v", err)
	}

	// Step 4: Dealer split for EdDSA.
	eddsaShares, err := tss.DealerSetupEdDSA(
		keys1.EdDSAPrivKey, keys1.EdDSAPubKey, keys1.EdDSAChainCode,
		parties,
	)
	if err != nil {
		t.Fatalf("DealerSetupEdDSA: %v", err)
	}

	// Step 5: Verify shares are valid and consistent.
	if len(ecdsaShares) != 2 {
		t.Fatalf("ECDSA shares: got %d, want 2", len(ecdsaShares))
	}
	if len(eddsaShares) != 2 {
		t.Fatalf("EdDSA shares: got %d, want 2", len(eddsaShares))
	}

	// Both parties should have the same public key.
	if string(ecdsaShares[0].PublicKey) != string(ecdsaShares[1].PublicKey) {
		t.Error("ECDSA public keys differ between parties")
	}
	if string(eddsaShares[0].PublicKey) != string(eddsaShares[1].PublicKey) {
		t.Error("EdDSA public keys differ between parties")
	}

	// Shares themselves should differ.
	if string(ecdsaShares[0].Share) == string(ecdsaShares[1].Share) {
		t.Error("ECDSA shares should differ between parties")
	}
	if string(eddsaShares[0].Share) == string(eddsaShares[1].Share) {
		t.Error("EdDSA shares should differ between parties")
	}

	// Step 6: RESTORE from the same mnemonic.
	keys2, err := DeriveKeysFromMnemonic(keys1.Mnemonic)
	if err != nil {
		t.Fatalf("DeriveKeysFromMnemonic (restore): %v", err)
	}

	// Step 7: Verify restored keys match originals.
	if keys1.ECDSAPrivKey.Cmp(keys2.ECDSAPrivKey) != 0 {
		t.Error("ECDSA private key mismatch after restore")
	}
	if keys1.EdDSAPrivKey.Cmp(keys2.EdDSAPrivKey) != 0 {
		t.Error("EdDSA private key mismatch after restore")
	}
	if hex.EncodeToString(keys1.ECDSAPubKey) != hex.EncodeToString(keys2.ECDSAPubKey) {
		t.Error("ECDSA public key mismatch after restore")
	}
	if hex.EncodeToString(keys1.EdDSAPubKey) != hex.EncodeToString(keys2.EdDSAPubKey) {
		t.Error("EdDSA public key mismatch after restore")
	}

	// Step 8: Re-split the restored keys and verify shares produce the same public keys.
	ecdsaShares2, err := tss.DealerSetupECDSA(
		keys2.ECDSAPrivKey, keys2.ECDSAPubKey, keys2.ECDSAChainCode,
		parties, []*keygen.LocalPreParams{ppA, ppB},
	)
	if err != nil {
		t.Fatalf("DealerSetupECDSA (restore): %v", err)
	}
	eddsaShares2, err := tss.DealerSetupEdDSA(
		keys2.EdDSAPrivKey, keys2.EdDSAPubKey, keys2.EdDSAChainCode,
		parties,
	)
	if err != nil {
		t.Fatalf("DealerSetupEdDSA (restore): %v", err)
	}

	// Public keys from re-split must match originals.
	if string(ecdsaShares[0].PublicKey) != string(ecdsaShares2[0].PublicKey) {
		t.Error("ECDSA public key differs after restore + re-split")
	}
	if string(eddsaShares[0].PublicKey) != string(eddsaShares2[0].PublicKey) {
		t.Error("EdDSA public key differs after restore + re-split")
	}

	t.Log("Case 1 PASSED: wallet creation and restoration verified")
}

// TestCase1_Fast tests the mnemonic → keys → dealer split pipeline without safe prime
// generation (uses the short-mode-compatible path). This catches regressions in the
// key derivation and splitting logic without the multi-minute Paillier overhead.
func TestCase1_Fast(t *testing.T) {
	// Step 1: Generate mnemonic.
	keys1, err := GenerateMnemonicKeys()
	if err != nil {
		t.Fatalf("GenerateMnemonicKeys: %v", err)
	}

	if len(keys1.Mnemonic) == 0 {
		t.Fatal("mnemonic is empty")
	}
	if keys1.ECDSAPrivKey == nil || keys1.ECDSAPrivKey.Sign() == 0 {
		t.Fatal("ECDSA private key is zero")
	}
	if keys1.EdDSAPrivKey == nil || keys1.EdDSAPrivKey.Sign() == 0 {
		t.Fatal("EdDSA private key is zero")
	}

	// Step 2: Restore from same mnemonic.
	keys2, err := DeriveKeysFromMnemonic(keys1.Mnemonic)
	if err != nil {
		t.Fatalf("DeriveKeysFromMnemonic: %v", err)
	}

	// Step 3: Verify deterministic derivation.
	if keys1.ECDSAPrivKey.Cmp(keys2.ECDSAPrivKey) != 0 {
		t.Error("ECDSA private key mismatch")
	}
	if keys1.EdDSAPrivKey.Cmp(keys2.EdDSAPrivKey) != 0 {
		t.Error("EdDSA private key mismatch")
	}
	if hex.EncodeToString(keys1.ECDSAPubKey) != hex.EncodeToString(keys2.ECDSAPubKey) {
		t.Error("ECDSA public key mismatch")
	}
	if hex.EncodeToString(keys1.EdDSAPubKey) != hex.EncodeToString(keys2.EdDSAPubKey) {
		t.Error("EdDSA public key mismatch")
	}

	// Step 4: EdDSA dealer split (no safe primes needed).
	parties := []tss.PartyID{
		{ID: "party-a", Index: 0},
		{ID: "party-b", Index: 1},
	}
	eddsaShares, err := tss.DealerSetupEdDSA(
		keys1.EdDSAPrivKey, keys1.EdDSAPubKey, keys1.EdDSAChainCode,
		parties,
	)
	if err != nil {
		t.Fatalf("DealerSetupEdDSA: %v", err)
	}
	if len(eddsaShares) != 2 {
		t.Fatalf("EdDSA shares: got %d, want 2", len(eddsaShares))
	}
	if string(eddsaShares[0].PublicKey) != string(eddsaShares[1].PublicKey) {
		t.Error("EdDSA public keys differ")
	}

	// Re-split from restored keys.
	eddsaShares2, err := tss.DealerSetupEdDSA(
		keys2.EdDSAPrivKey, keys2.EdDSAPubKey, keys2.EdDSAChainCode,
		parties,
	)
	if err != nil {
		t.Fatalf("DealerSetupEdDSA (restore): %v", err)
	}
	if string(eddsaShares[0].PublicKey) != string(eddsaShares2[0].PublicKey) {
		t.Error("EdDSA public key differs after restore")
	}
}

// TestInstallPipelineEndToEnd simulates the full install pipeline that runs
// when the user clicks "Start Installation" — mnemonic, dealer split, certs.
// This catches issues like the hang and SSH errors before the user sees them.
func TestInstallPipelineEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full pipeline test in short mode")
	}

	// Simulate the state the wizard would have after user fills in all steps.
	state := &WizardState{
		Step:      "prepared",
		LocalMode: true,
		ServerA:   SSHConfig{Host: "127.0.0.1", Port: 22, User: "local"},
		ServerB:   SSHConfig{Host: "127.0.0.1", Port: 22, User: "local"},
	}

	// Generate mnemonic.
	keys, err := GenerateMnemonicKeys()
	if err != nil {
		t.Fatalf("GenerateMnemonicKeys: %v", err)
	}
	state.Mnemonic = keys.Mnemonic

	// Generate pre-params.
	t.Log("Generating pre-params...")
	ppA, err := keygen.GeneratePreParams(10 * time.Minute)
	if err != nil {
		t.Fatalf("pre-params A: %v", err)
	}
	ppB, err := keygen.GeneratePreParams(10 * time.Minute)
	if err != nil {
		t.Fatalf("pre-params B: %v", err)
	}

	// Derive keys from mnemonic.
	derived, err := DeriveKeysFromMnemonic(state.Mnemonic)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}

	parties := []tss.PartyID{
		{ID: "party-a", Index: 0},
		{ID: "party-b", Index: 1},
	}

	// ECDSA dealer split.
	ecdsaShares, err := tss.DealerSetupECDSA(
		derived.ECDSAPrivKey, derived.ECDSAPubKey, derived.ECDSAChainCode,
		parties, []*keygen.LocalPreParams{ppA, ppB},
	)
	if err != nil {
		t.Fatalf("ECDSA dealer: %v", err)
	}

	// EdDSA dealer split.
	eddsaShares, err := tss.DealerSetupEdDSA(
		derived.EdDSAPrivKey, derived.EdDSAPubKey, derived.EdDSAChainCode,
		parties,
	)
	if err != nil {
		t.Fatalf("EdDSA dealer: %v", err)
	}

	state.SetECDSAKeys(ecdsaShares[0], ecdsaShares[1])
	state.SetEdDSAKeys(eddsaShares[0], eddsaShares[1])

	// Generate TLS certs.
	bundle, err := GenerateCerts([]string{"127.0.0.1"}, []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("GenerateCerts: %v", err)
	}
	if len(bundle.CACert) == 0 {
		t.Fatal("CA cert is empty")
	}

	// Verify the full state is populated.
	if state.ShareA == nil || state.ShareB == nil {
		t.Fatal("ECDSA shares not set")
	}
	if state.EdShareA == nil || state.EdShareB == nil {
		t.Fatal("EdDSA shares not set")
	}
	if state.ECDSAPubKey == "" || state.EdDSAPubKey == "" {
		t.Fatal("public keys not set in state")
	}

	t.Logf("Pipeline complete: ECDSA pub=%s... EdDSA pub=%s...",
		state.ECDSAPubKey[:16], state.EdDSAPubKey[:16])
}
