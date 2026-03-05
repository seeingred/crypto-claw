package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"
)

func TestGenerateCA(t *testing.T) {
	ca, err := GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	if ca.Cert == nil {
		t.Fatal("CA cert is nil")
	}
	if !ca.Cert.IsCA {
		t.Error("cert is not a CA")
	}
	if ca.Cert.Subject.CommonName != "test-ca" {
		t.Errorf("common name = %q, want %q", ca.Cert.Subject.CommonName, "test-ca")
	}
	if len(ca.CertPEM) == 0 {
		t.Error("cert PEM is empty")
	}
	if len(ca.KeyPEM) == 0 {
		t.Error("key PEM is empty")
	}
}

func TestGeneratePartyCert(t *testing.T) {
	ca, err := GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	party, err := GeneratePartyCert(ca, "party-a", "127.0.0.1", "localhost")
	if err != nil {
		t.Fatalf("GeneratePartyCert: %v", err)
	}

	if party.Cert == nil {
		t.Fatal("party cert is nil")
	}
	if party.Cert.Subject.CommonName != "party-a" {
		t.Errorf("common name = %q, want %q", party.Cert.Subject.CommonName, "party-a")
	}

	// Verify the cert is signed by the CA.
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	_, err = party.Cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Errorf("cert verification failed: %v", err)
	}
}

func TestMTLSHandshake(t *testing.T) {
	ca, err := GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	serverCert, err := GeneratePartyCert(ca, "server", "127.0.0.1", "localhost")
	if err != nil {
		t.Fatalf("GeneratePartyCert server: %v", err)
	}

	clientCert, err := GeneratePartyCert(ca, "client", "127.0.0.1", "localhost")
	if err != nil {
		t.Fatalf("GeneratePartyCert client: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Cert)

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{serverCert.Cert.Raw},
			PrivateKey:  serverCert.Key,
		}},
		ClientCAs:  caPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	}

	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{clientCert.Cert.Raw},
			PrivateKey:  clientCert.Key,
		}},
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS13,
	}

	// Start a TLS listener.
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 5)
		n, err := conn.Read(buf)
		if err != nil {
			done <- err
			return
		}
		if string(buf[:n]) != "hello" {
			done <- fmt.Errorf("expected 'hello', got %q", string(buf[:n]))
			return
		}
		done <- nil
	}()

	conn, err := tls.Dial("tcp", listener.Addr().String(), clientTLS)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("server error: %v", err)
	}
}
