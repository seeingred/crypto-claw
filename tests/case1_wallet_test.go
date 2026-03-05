package tests

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/seeingred/crypto-claw/internal/tss"
	"github.com/seeingred/crypto-claw/internal/vm/evm"
	"github.com/seeingred/crypto-claw/tests/testutil"
)

// TestWalletCreation_DKG_ECDSA verifies that DKG produces matching public keys
// for both parties and that addresses can be derived from the shared public key.
func TestWalletCreation_DKG_ECDSA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Skip("requires TSS protocol implementation")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cluster := testutil.NewTestCluster(t)
	_ = ctx
	_ = cluster

	// Once TSS Protocol is implemented:
	// var protocol tss.Protocol = tssimpl.New()
	// testutil.RunDKG(ctx, t, cluster, protocol, tss.CurveSecp256k1)

	// shareA, ok := cluster.PartyA.GetKeyShare(tss.CurveSecp256k1)
	// if !ok { t.Fatal("party A has no ECDSA share") }
	// shareB, ok := cluster.PartyB.GetKeyShare(tss.CurveSecp256k1)
	// if !ok { t.Fatal("party B has no ECDSA share") }

	// Verify public keys match.
	// if !bytes.Equal(shareA.PublicKey, shareB.PublicKey) {
	//     t.Fatal("ECDSA public keys do not match between parties")
	// }

	// Verify chain codes match.
	// if !bytes.Equal(shareA.ChainCode, shareB.ChainCode) {
	//     t.Fatal("ECDSA chain codes do not match between parties")
	// }

	// Derive EVM address.
	// adapter := evm.New()
	// addr, err := adapter.DeriveAddress(shareA.PublicKey)
	// if err != nil { t.Fatal("derive EVM address:", err) }
	// t.Logf("DKG ECDSA public key: %x", shareA.PublicKey)
	// t.Logf("Derived EVM address: %s", addr)
}

// TestWalletCreation_DKG_EdDSA verifies DKG for ed25519 (Solana).
func TestWalletCreation_DKG_EdDSA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Skip("requires TSS protocol implementation")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cluster := testutil.NewTestCluster(t)
	_ = ctx
	_ = cluster
}

// TestWalletDerivation verifies HD key derivation from master key shares.
func TestWalletDerivation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Skip("requires TSS protocol implementation")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cluster := testutil.NewTestCluster(t)
	_ = ctx
	_ = cluster

	// After DKG, derive child keys:
	// var protocol tss.Protocol = tssimpl.New()
	// testutil.RunDKG(ctx, t, cluster, protocol, tss.CurveSecp256k1)
	//
	// shareA, _ := cluster.PartyA.GetKeyShare(tss.CurveSecp256k1)
	// derivedA, err := protocol.DeriveKey(ctx, shareA, "m/44'/60'/0'/0/0")
	// if err != nil { t.Fatal("derive key A:", err) }
	//
	// shareB, _ := cluster.PartyB.GetKeyShare(tss.CurveSecp256k1)
	// derivedB, err := protocol.DeriveKey(ctx, shareB, "m/44'/60'/0'/0/0")
	// if err != nil { t.Fatal("derive key B:", err) }
	//
	// if !bytes.Equal(derivedA.PublicKey, derivedB.PublicKey) {
	//     t.Fatal("derived public keys do not match")
	// }
	// if derivedA.Address != derivedB.Address {
	//     t.Fatal("derived addresses do not match")
	// }
}

// TestWalletRestoration verifies that running DKG with the same seed/parameters
// produces consistent key material.
func TestWalletRestoration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Skip("requires TSS protocol implementation")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cluster := testutil.NewTestCluster(t)
	_ = ctx
	_ = cluster
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

// Ensure imports are used.
var (
	_ = tss.CurveSecp256k1
	_ = evm.New
)
