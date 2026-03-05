package tests

import (
	"bytes"
	"context"
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

// TestWalletRestoration verifies that key derivation is deterministic:
// deriving with the same path twice produces identical results.
func TestWalletRestoration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cluster := testutil.NewTestCluster(t)
	preParams := testutil.GenerateTestPreParams(t)
	protocol := testutil.NewTestProtocolWithPreParams(preParams)

	// Create context after pre-params generation (which can take minutes).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Run ECDSA DKG.
	testutil.RunDKG(ctx, t, cluster, protocol, tss.CurveSecp256k1)

	derivationPath := "m/44'/60'/0'/0/0"

	// First derivation.
	pubKeyA1, pubKeyB1 := testutil.RunDerive(ctx, t, cluster, protocol, tss.CurveSecp256k1, derivationPath)

	// Second derivation with the SAME path — should produce identical keys.
	// Re-derive from the original master shares (RunDerive uses GetKeyShare which
	// returns the master share, not the previously derived share).
	pubKeyA2, pubKeyB2 := testutil.RunDerive(ctx, t, cluster, protocol, tss.CurveSecp256k1, derivationPath)

	if !bytes.Equal(pubKeyA1, pubKeyA2) {
		t.Fatal("party A: derived public keys differ across two derivations with the same path")
	}
	if !bytes.Equal(pubKeyB1, pubKeyB2) {
		t.Fatal("party B: derived public keys differ across two derivations with the same path")
	}

	t.Logf("Derivation is deterministic: both runs produced %x", pubKeyA1)

	// Verify EVM addresses also match.
	adapter := evm.New()
	addr1, err := adapter.DeriveAddress(pubKeyA1)
	if err != nil {
		t.Fatal("derive EVM address (first):", err)
	}
	addr2, err := adapter.DeriveAddress(pubKeyA2)
	if err != nil {
		t.Fatal("derive EVM address (second):", err)
	}
	if addr1 != addr2 {
		t.Fatalf("EVM addresses differ across derivations: %s vs %s", addr1, addr2)
	}
	t.Logf("Restored EVM address: %s", addr1)
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
