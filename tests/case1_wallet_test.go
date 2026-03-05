package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/seeingred/crypto-claw/internal/tss"
	"github.com/seeingred/crypto-claw/internal/vm/evm"
	"github.com/seeingred/crypto-claw/internal/vm/solana"
	"github.com/seeingred/crypto-claw/tests/testutil"
)

// TestWalletCreation_DKG_ECDSA verifies that DKG produces matching public keys
// for both parties and that addresses can be derived from the shared public key.
func TestWalletCreation_DKG_ECDSA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cluster := testutil.NewTestCluster(t)
	preParams := testutil.GenerateTestPreParams(t)
	protocol := testutil.NewTestProtocolWithPreParams(preParams)

	// Create context after pre-params generation (which can take minutes).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testutil.RunDKG(ctx, t, cluster, protocol, tss.CurveSecp256k1)

	shareA, ok := cluster.PartyA.GetKeyShare(tss.CurveSecp256k1)
	if !ok {
		t.Fatal("party A has no ECDSA share")
	}
	shareB, ok := cluster.PartyB.GetKeyShare(tss.CurveSecp256k1)
	if !ok {
		t.Fatal("party B has no ECDSA share")
	}

	// Verify public keys match.
	if !bytes.Equal(shareA.PublicKey, shareB.PublicKey) {
		t.Fatal("ECDSA public keys do not match between parties")
	}
	t.Logf("DKG ECDSA public key: %x", shareA.PublicKey)

	// Verify chain codes match.
	if !bytes.Equal(shareA.ChainCode, shareB.ChainCode) {
		t.Fatal("ECDSA chain codes do not match between parties")
	}
	t.Logf("Chain code: %x", shareA.ChainCode)

	// Derive EVM address.
	adapter := evm.New()
	addr, err := adapter.DeriveAddress(shareA.PublicKey)
	if err != nil {
		t.Fatal("derive EVM address:", err)
	}
	if len(addr) != 42 {
		t.Fatalf("unexpected EVM address length: %d", len(addr))
	}
	t.Logf("Derived EVM address: %s", addr)
}

// TestWalletCreation_DKG_EdDSA verifies DKG for ed25519 (Solana).
func TestWalletCreation_DKG_EdDSA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cluster := testutil.NewTestCluster(t)
	// EdDSA DKG does not need pre-params; it is fast.
	protocol := tss.NewProtocol(0)

	testutil.RunDKG(ctx, t, cluster, protocol, tss.CurveEd25519)

	shareA, ok := cluster.PartyA.GetKeyShare(tss.CurveEd25519)
	if !ok {
		t.Fatal("party A has no EdDSA share")
	}
	shareB, ok := cluster.PartyB.GetKeyShare(tss.CurveEd25519)
	if !ok {
		t.Fatal("party B has no EdDSA share")
	}

	// Verify public keys match.
	if !bytes.Equal(shareA.PublicKey, shareB.PublicKey) {
		t.Fatal("EdDSA public keys do not match between parties")
	}
	t.Logf("DKG EdDSA public key (%d bytes): %x", len(shareA.PublicKey), shareA.PublicKey)

	// Verify the public key is 32 bytes (ed25519).
	if len(shareA.PublicKey) != 32 {
		t.Fatalf("expected 32-byte ed25519 public key, got %d bytes", len(shareA.PublicKey))
	}

	// Derive Solana address from the 32-byte public key.
	adapter := solana.New()
	addr, err := adapter.DeriveAddress(shareA.PublicKey)
	if err != nil {
		t.Fatal("derive Solana address:", err)
	}
	if addr == "" {
		t.Fatal("derived Solana address is empty")
	}
	t.Logf("Derived Solana address: %s", addr)
}

// TestWalletDerivation verifies HD key derivation from master key shares.
func TestWalletDerivation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cluster := testutil.NewTestCluster(t)
	preParams := testutil.GenerateTestPreParams(t)
	protocol := testutil.NewTestProtocolWithPreParams(preParams)

	// Create context after pre-params generation (which can take minutes).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Run ECDSA DKG first.
	testutil.RunDKG(ctx, t, cluster, protocol, tss.CurveSecp256k1)

	// Derive child keys for the standard EVM path.
	derivationPath := "m/44'/60'/0'/0/0"
	pubKeyA, pubKeyB := testutil.RunDerive(ctx, t, cluster, protocol, tss.CurveSecp256k1, derivationPath)

	// Verify both parties get the same derived public key.
	if !bytes.Equal(pubKeyA, pubKeyB) {
		t.Fatal("derived public keys do not match between parties")
	}
	t.Logf("Derived public key for %s: %x", derivationPath, pubKeyA)

	// Verify the derived key is a valid uncompressed secp256k1 public key (65 bytes, 0x04 prefix).
	if len(pubKeyA) != 65 || pubKeyA[0] != 0x04 {
		t.Fatalf("invalid derived public key format: %d bytes, prefix 0x%02x", len(pubKeyA), pubKeyA[0])
	}

	// Derive EVM addresses from both parties' derived keys and verify they match.
	adapter := evm.New()
	addrA, err := adapter.DeriveAddress(pubKeyA)
	if err != nil {
		t.Fatal("derive EVM address from party A key:", err)
	}
	addrB, err := adapter.DeriveAddress(pubKeyB)
	if err != nil {
		t.Fatal("derive EVM address from party B key:", err)
	}
	if addrA != addrB {
		t.Fatalf("EVM addresses differ: A=%s B=%s", addrA, addrB)
	}
	t.Logf("Derived EVM address: %s", addrA)

	// Verify the derived address is different from the master key address.
	masterShare, _ := cluster.PartyA.GetKeyShare(tss.CurveSecp256k1)
	masterAddr, err := adapter.DeriveAddress(masterShare.PublicKey)
	if err != nil {
		t.Fatal("derive master EVM address:", err)
	}
	if addrA == masterAddr {
		t.Fatal("derived address should differ from master key address")
	}
	t.Logf("Master EVM address: %s (different from derived)", masterAddr)
}

// TestWalletRestoration verifies wallet recovery from backed-up key shares.
// This tests the full flow that the installer provides:
//  1. DKG produces key shares for both parties
//  2. Shares are serialized to JSON (the backup the user saves)
//  3. Derive EVM and Solana addresses from the original shares
//  4. Create a fresh cluster, deserialize the backed-up shares
//  5. Derive using the same paths — addresses must match
func TestWalletRestoration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cluster := testutil.NewTestCluster(t)
	preParams := testutil.GenerateTestPreParams(t)
	protocol := testutil.NewTestProtocolWithPreParams(preParams)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// --- Step 1: DKG for both curves ---
	testutil.RunDKG(ctx, t, cluster, protocol, tss.CurveSecp256k1)

	// EdDSA DKG (no pre-params needed).
	edProtocol := tss.NewProtocol(0)
	testutil.RunDKG(ctx, t, cluster, edProtocol, tss.CurveEd25519)

	// --- Step 2: Derive original addresses ---
	evmPath := "m/44'/60'/0'/0/0"
	origEVMPubA, _ := testutil.RunDerive(ctx, t, cluster, protocol, tss.CurveSecp256k1, evmPath)
	evmAdapter := evm.New()
	origEVMAddr, err := evmAdapter.DeriveAddress(origEVMPubA)
	if err != nil {
		t.Fatal("derive original EVM address:", err)
	}
	t.Logf("Original EVM address: %s", origEVMAddr)

	origEdPubA, _ := testutil.RunDerive(ctx, t, cluster, edProtocol, tss.CurveEd25519, "m/44'/501'/0'/0'")
	solAdapter := solana.New()
	origSolAddr, err := solAdapter.DeriveAddress(origEdPubA)
	if err != nil {
		t.Fatal("derive original Solana address:", err)
	}
	t.Logf("Original Solana address: %s", origSolAddr)

	// --- Step 3: Serialize shares to JSON (simulating installer backup) ---
	ecdsaShareA, _ := cluster.PartyA.GetKeyShare(tss.CurveSecp256k1)
	ecdsaShareB, _ := cluster.PartyB.GetKeyShare(tss.CurveSecp256k1)
	eddsaShareA, _ := cluster.PartyA.GetKeyShare(tss.CurveEd25519)
	eddsaShareB, _ := cluster.PartyB.GetKeyShare(tss.CurveEd25519)

	type backupBundle struct {
		ECDSAShare *tss.KeyShare `json:"ecdsaShare"`
		EdDSAShare *tss.KeyShare `json:"eddsaShare"`
	}

	backupA, err := json.Marshal(backupBundle{ECDSAShare: ecdsaShareA, EdDSAShare: eddsaShareA})
	if err != nil {
		t.Fatal("marshal backup A:", err)
	}
	backupB, err := json.Marshal(backupBundle{ECDSAShare: ecdsaShareB, EdDSAShare: eddsaShareB})
	if err != nil {
		t.Fatal("marshal backup B:", err)
	}
	t.Logf("Backup A: %d bytes, Backup B: %d bytes", len(backupA), len(backupB))

	// --- Step 4: Restore — deserialize into a fresh cluster ---
	var restoredA, restoredB backupBundle
	if err := json.Unmarshal(backupA, &restoredA); err != nil {
		t.Fatal("unmarshal backup A:", err)
	}
	if err := json.Unmarshal(backupB, &restoredB); err != nil {
		t.Fatal("unmarshal backup B:", err)
	}

	restoredCluster := testutil.NewTestCluster(t)
	restoredCluster.PartyA.SetKeyShare(restoredA.ECDSAShare)
	restoredCluster.PartyB.SetKeyShare(restoredB.ECDSAShare)
	restoredCluster.PartyA.SetKeyShare(restoredA.EdDSAShare)
	restoredCluster.PartyB.SetKeyShare(restoredB.EdDSAShare)

	// Verify restored public keys match originals.
	rEcdsaA, _ := restoredCluster.PartyA.GetKeyShare(tss.CurveSecp256k1)
	if !bytes.Equal(rEcdsaA.PublicKey, ecdsaShareA.PublicKey) {
		t.Fatal("restored ECDSA public key doesn't match original")
	}
	rEddsaA, _ := restoredCluster.PartyA.GetKeyShare(tss.CurveEd25519)
	if !bytes.Equal(rEddsaA.PublicKey, eddsaShareA.PublicKey) {
		t.Fatal("restored EdDSA public key doesn't match original")
	}

	// --- Step 5: Derive from restored shares — addresses must match ---
	restoredEVMPubA, restoredEVMPubB := testutil.RunDerive(ctx, t, restoredCluster, protocol, tss.CurveSecp256k1, evmPath)
	if !bytes.Equal(restoredEVMPubA, restoredEVMPubB) {
		t.Fatal("restored: EVM derived public keys differ between parties")
	}

	restoredEVMAddr, err := evmAdapter.DeriveAddress(restoredEVMPubA)
	if err != nil {
		t.Fatal("derive restored EVM address:", err)
	}
	if restoredEVMAddr != origEVMAddr {
		t.Fatalf("EVM address mismatch after restore: original=%s restored=%s", origEVMAddr, restoredEVMAddr)
	}
	t.Logf("Restored EVM address matches: %s", restoredEVMAddr)

	restoredEdPubA, restoredEdPubB := testutil.RunDerive(ctx, t, restoredCluster, edProtocol, tss.CurveEd25519, "m/44'/501'/0'/0'")
	if !bytes.Equal(restoredEdPubA, restoredEdPubB) {
		t.Fatal("restored: Solana derived public keys differ between parties")
	}

	restoredSolAddr, err := solAdapter.DeriveAddress(restoredEdPubA)
	if err != nil {
		t.Fatal("derive restored Solana address:", err)
	}
	if restoredSolAddr != origSolAddr {
		t.Fatalf("Solana address mismatch after restore: original=%s restored=%s", origSolAddr, restoredSolAddr)
	}
	t.Logf("Restored Solana address matches: %s", restoredSolAddr)
}

// TestDeriveAddress_EVM verifies EVM address derivation from a known public key.
func TestDeriveAddress_EVM(t *testing.T) {
	adapter := evm.New()

	// Test with a known uncompressed public key (65 bytes, 0x04 prefix).
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	// Fill with deterministic test data.
	for i := 1; i < 65; i++ {
		pubKey[i] = byte(i)
	}

	addr, err := adapter.DeriveAddress(pubKey)
	if err != nil {
		t.Fatal("derive address:", err)
	}
	if addr == "" {
		t.Fatal("derived address is empty")
	}
	if len(addr) != 42 { // "0x" + 40 hex chars
		t.Fatalf("unexpected address length: %d", len(addr))
	}
	t.Logf("Derived EVM address: %s", addr)
}

// TestSetupCluster verifies that the test cluster setup works:
// certs are generated, configs are valid.
func TestSetupCluster(t *testing.T) {
	cluster := testutil.NewTestCluster(t)

	if cluster.PartyA.Config.Party != "a" {
		t.Fatal("party A config wrong")
	}
	if cluster.PartyB.Config.Party != "b" {
		t.Fatal("party B config wrong")
	}

	// Verify certs were generated.
	tlsA, err := testutil.LoadTestTLS(cluster.PartyA.CertDir)
	if err != nil {
		t.Fatal("load TLS A:", err)
	}
	if len(tlsA.Certificates) == 0 {
		t.Fatal("no certs for party A")
	}

	tlsB, err := testutil.LoadTestTLS(cluster.PartyB.CertDir)
	if err != nil {
		t.Fatal("load TLS B:", err)
	}
	if len(tlsB.Certificates) == 0 {
		t.Fatal("no certs for party B")
	}

	// Verify in-memory router works.
	router := testutil.NewInMemoryRouter()
	parties := cluster.Parties()
	if len(parties) != 2 {
		t.Fatalf("expected 2 parties, got %d", len(parties))
	}

	routerA := router.ForParty(parties[0])
	routerB := router.ForParty(parties[1])

	// Send message A -> B.
	testMsg := []byte("hello from A")
	if err := routerA.Send(context.Background(), parties[1], testMsg); err != nil {
		t.Fatal("send A->B:", err)
	}

	select {
	case msg := <-routerB.Receive():
		if msg.From.ID != parties[0].ID {
			t.Fatalf("expected from %s, got %s", parties[0].ID, msg.From.ID)
		}
		if !bytes.Equal(msg.Payload, testMsg) {
			t.Fatal("message payload mismatch")
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive message")
	}
}
