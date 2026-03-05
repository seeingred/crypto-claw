package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

func TestMessageRoundTrip(t *testing.T) {
	msg := &Message{
		Type:    MsgSignRequest,
		ID:      42,
		Payload: []byte(`{"to":"0xabc","value":"1000000000"}`),
	}

	var buf bytes.Buffer
	if err := WriteMessage(&buf, msg); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	got, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	if got.Type != msg.Type {
		t.Errorf("Type = %d, want %d", got.Type, msg.Type)
	}
	if got.ID != msg.ID {
		t.Errorf("ID = %d, want %d", got.ID, msg.ID)
	}
	if !bytes.Equal(got.Payload, msg.Payload) {
		t.Errorf("Payload mismatch")
	}
}

func TestEmptyPayload(t *testing.T) {
	msg := &Message{
		Type: MsgHealthCheck,
		ID:   1,
	}

	var buf bytes.Buffer
	if err := WriteMessage(&buf, msg); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	got, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	if got.Type != MsgHealthCheck {
		t.Errorf("Type = %d, want %d", got.Type, MsgHealthCheck)
	}
	if len(got.Payload) != 0 {
		t.Errorf("Payload should be empty, got %d bytes", len(got.Payload))
	}
}

func setupMTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()

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
		RootCAs:    caPool,
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

	return serverTLS, clientTLS
}

func TestServerClientMessageExchange(t *testing.T) {
	serverTLS, clientTLS := setupMTLS(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv := NewServer("127.0.0.1:0", serverTLS)

	// Server echoes back with MsgHealthResp.
	srv.SetHandler(func(msg *Message) (*Message, error) {
		return &Message{
			Type:    MsgHealthResp,
			Payload: msg.Payload,
		}, nil
	})

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("server start: %v", err)
	}
	defer srv.Stop()

	client := NewClient(srv.Addr().String(), clientTLS)
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer client.Close()

	// Give connection time to establish.
	time.Sleep(100 * time.Millisecond)

	resp, err := client.Request(ctx, &Message{
		Type:    MsgHealthCheck,
		Payload: []byte("ping"),
	})
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	if resp.Type != MsgHealthResp {
		t.Errorf("response type = %d, want %d", resp.Type, MsgHealthResp)
	}
	if !bytes.Equal(resp.Payload, []byte("ping")) {
		t.Errorf("response payload = %q, want %q", resp.Payload, "ping")
	}
}
