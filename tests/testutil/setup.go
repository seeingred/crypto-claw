// Package testutil provides helpers for integration tests.
package testutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/seeingred/crypto-claw/internal/config"
	"github.com/seeingred/crypto-claw/internal/tss"
)

// TestParty represents a test party (A or B) running in-process.
type TestParty struct {
	ID       string
	PartyID  tss.PartyID
	Config   *config.Config
	CertDir  string
	KeyShare map[tss.Curve]*tss.KeyShare // populated after DKG
	mu       sync.Mutex
}

// TestCluster holds a pair of test parties wired together.
type TestCluster struct {
	PartyA *TestParty
	PartyB *TestParty
	TmpDir string
}

// NewTestCluster creates a test cluster with generated certs and configs.
func NewTestCluster(t *testing.T) *TestCluster {
	t.Helper()
	tmpDir := t.TempDir()

	certDirA := filepath.Join(tmpDir, "certs-a")
	certDirB := filepath.Join(tmpDir, "certs-b")
	if err := os.MkdirAll(certDirA, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(certDirB, 0700); err != nil {
		t.Fatal(err)
	}

	// Generate CA + certs for both parties.
	if err := generateTestCerts(certDirA, certDirB); err != nil {
		t.Fatal("generate certs:", err)
	}

	partyA := &TestParty{
		ID:      "party-a",
		PartyID: tss.PartyID{ID: "party-a", Index: 0},
		CertDir: certDirA,
		Config: &config.Config{
			Party:   "a",
			DataDir: filepath.Join(tmpDir, "data-a"),
			API: config.APIConfig{
				ListenAddr: "127.0.0.1:0", // OS picks port
			},
			Transport: config.TransportConfig{
				RemoteAddr: "127.0.0.1:0",
				CertFile:   filepath.Join(certDirA, "cert.pem"),
				KeyFile:    filepath.Join(certDirA, "key.pem"),
				CACertFile: filepath.Join(certDirA, "ca.pem"),
			},
			Chains: config.ChainsConfig{
				EVM: []config.EVMChainConfig{
					{Name: "hardhat", ChainID: 31337, RPCURL: "http://127.0.0.1:8545"},
				},
				Solana: []config.SolanaChainConfig{
					{Name: "local", RPCURL: "http://127.0.0.1:8899"},
				},
			},
		},
		KeyShare: make(map[tss.Curve]*tss.KeyShare),
	}

	partyB := &TestParty{
		ID:      "party-b",
		PartyID: tss.PartyID{ID: "party-b", Index: 1},
		CertDir: certDirB,
		Config: &config.Config{
			Party:   "b",
			DataDir: filepath.Join(tmpDir, "data-b"),
			Transport: config.TransportConfig{
				ListenAddr: "127.0.0.1:0",
				CertFile:   filepath.Join(certDirB, "cert.pem"),
				KeyFile:    filepath.Join(certDirB, "key.pem"),
				CACertFile: filepath.Join(certDirB, "ca.pem"),
			},
		},
		KeyShare: make(map[tss.Curve]*tss.KeyShare),
	}

	if err := os.MkdirAll(partyA.Config.DataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(partyB.Config.DataDir, 0700); err != nil {
		t.Fatal(err)
	}

	return &TestCluster{PartyA: partyA, PartyB: partyB, TmpDir: tmpDir}
}

// Parties returns the party ID list for DKG/signing.
func (c *TestCluster) Parties() []tss.PartyID {
	return []tss.PartyID{c.PartyA.PartyID, c.PartyB.PartyID}
}

// SetKeyShare stores a key share for a party.
func (p *TestParty) SetKeyShare(share *tss.KeyShare) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.KeyShare[share.Curve] = share
}

// GetKeyShare retrieves a stored key share.
func (p *TestParty) GetKeyShare(curve tss.Curve) (*tss.KeyShare, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ks, ok := p.KeyShare[curve]
	return ks, ok
}

// InMemoryRouter is a simple in-process message router for testing TSS protocols
// between two parties without network transport.
type InMemoryRouter struct {
	channels map[string]chan tss.IncomingMessage
	mu       sync.RWMutex
}

// NewInMemoryRouter creates a router connecting test parties.
func NewInMemoryRouter() *InMemoryRouter {
	return &InMemoryRouter{
		channels: make(map[string]chan tss.IncomingMessage),
	}
}

// ForParty returns a MessageRouter scoped to the given party.
func (r *InMemoryRouter) ForParty(id tss.PartyID) tss.MessageRouter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.channels[id.ID]; !ok {
		r.channels[id.ID] = make(chan tss.IncomingMessage, 1024)
	}
	return &inMemoryPartyRouter{router: r, self: id}
}

type inMemoryPartyRouter struct {
	router *InMemoryRouter
	self   tss.PartyID
}

func (p *inMemoryPartyRouter) Send(_ context.Context, to tss.PartyID, msg []byte) error {
	p.router.mu.RLock()
	ch, ok := p.router.channels[to.ID]
	p.router.mu.RUnlock()
	if !ok {
		return fmt.Errorf("no channel for party %s", to.ID)
	}
	ch <- tss.IncomingMessage{From: p.self, Payload: msg}
	return nil
}

func (p *inMemoryPartyRouter) Receive() <-chan tss.IncomingMessage {
	p.router.mu.RLock()
	defer p.router.mu.RUnlock()
	return p.router.channels[p.self.ID]
}

// RunDKG runs distributed key generation for both parties using an in-memory router.
// This is a helper that will work once the TSS Protocol implementation is available.
func RunDKG(ctx context.Context, t *testing.T, cluster *TestCluster, protocol tss.Protocol, curve tss.Curve) {
	t.Helper()

	router := NewInMemoryRouter()
	parties := cluster.Parties()

	var wg sync.WaitGroup
	var errA, errB error
	var shareA, shareB *tss.KeyShare

	wg.Add(2)
	go func() {
		defer wg.Done()
		shareA, errA = protocol.DKG(ctx, curve, cluster.PartyA.PartyID, parties, router.ForParty(cluster.PartyA.PartyID))
	}()
	go func() {
		defer wg.Done()
		shareB, errB = protocol.DKG(ctx, curve, cluster.PartyB.PartyID, parties, router.ForParty(cluster.PartyB.PartyID))
	}()

	wg.Wait()

	if errA != nil {
		t.Fatalf("DKG party A failed: %v", errA)
	}
	if errB != nil {
		t.Fatalf("DKG party B failed: %v", errB)
	}

	cluster.PartyA.SetKeyShare(shareA)
	cluster.PartyB.SetKeyShare(shareB)
}

// generateTestCerts generates a self-signed CA and party certs for mTLS testing.
func generateTestCerts(certDirA, certDirB string) error {
	// Generate CA key.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "crypto-claw-test-ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create CA cert: %w", err)
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	// Write CA cert to both dirs.
	for _, dir := range []string{certDirA, certDirB} {
		if err := os.WriteFile(filepath.Join(dir, "ca.pem"), caCertPEM, 0644); err != nil {
			return err
		}
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return err
	}

	// Generate certs for each party.
	for i, dir := range []string{certDirA, certDirB} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("generate party key: %w", err)
		}

		template := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 2)),
			Subject:      pkix.Name{CommonName: fmt.Sprintf("party-%s", string(rune('a'+i)))},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"localhost"},
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
		if err != nil {
			return fmt.Errorf("create party cert: %w", err)
		}

		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

		if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0600); err != nil {
			return err
		}
	}

	return nil
}

// LoadTestTLS loads the test TLS config for a party.
func LoadTestTLS(certDir string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(certDir, "cert.pem"),
		filepath.Join(certDir, "key.pem"),
	)
	if err != nil {
		return nil, fmt.Errorf("load key pair: %w", err)
	}

	caCert, err := os.ReadFile(filepath.Join(certDir, "ca.pem"))
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to add CA cert to pool")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// GenerateTestEdDSAKey generates a random ed25519 key pair for testing.
func GenerateTestEdDSAKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate ed25519 key:", err)
	}
	return pub, priv
}

// GenerateTestECDSAKey generates a random secp256k1-style key pair for testing.
// Uses P-256 as a stand-in since secp256k1 requires go-ethereum's crypto.
func GenerateTestECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate ecdsa key:", err)
	}
	return key
}
