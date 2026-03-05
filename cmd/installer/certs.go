package main

import (
	"fmt"
	"log/slog"

	"github.com/seeingred/crypto-claw/internal/transport"
)

// CertBundle holds all generated TLS certificates for the installer.
type CertBundle struct {
	CACert []byte
	CAKey  []byte
	CertA  []byte
	KeyA   []byte
	CertB  []byte
	KeyB   []byte
}

// GenerateCerts creates a self-signed CA and issues certificates for both parties.
// The certificates include localhost and 127.0.0.1 in their SANs, plus any
// additional hosts provided (typically the server IP addresses).
func GenerateCerts(hostsA []string, hostsB []string) (*CertBundle, error) {
	slog.Info("generating TLS CA certificate")

	ca, err := transport.GenerateCA("crypto-claw-ca")
	if err != nil {
		return nil, fmt.Errorf("generate CA: %w", err)
	}

	// Build SAN list for Party A: always include localhost + 127.0.0.1.
	sansA := append([]string{"localhost", "127.0.0.1"}, hostsA...)
	sansA = dedupStrings(sansA)

	slog.Info("generating Party A certificate", "sans", sansA)
	certA, err := transport.GeneratePartyCert(ca, "crypto-claw-party-a", sansA...)
	if err != nil {
		return nil, fmt.Errorf("generate party A cert: %w", err)
	}

	// Build SAN list for Party B: always include localhost + 127.0.0.1.
	sansB := append([]string{"localhost", "127.0.0.1"}, hostsB...)
	sansB = dedupStrings(sansB)

	slog.Info("generating Party B certificate", "sans", sansB)
	certB, err := transport.GeneratePartyCert(ca, "crypto-claw-party-b", sansB...)
	if err != nil {
		return nil, fmt.Errorf("generate party B cert: %w", err)
	}

	return &CertBundle{
		CACert: ca.CertPEM,
		CAKey:  ca.KeyPEM,
		CertA:  certA.CertPEM,
		KeyA:   certA.KeyPEM,
		CertB:  certB.CertPEM,
		KeyB:   certB.KeyPEM,
	}, nil
}

// dedupStrings removes duplicate strings from a slice, preserving order.
func dedupStrings(ss []string) []string {
	seen := make(map[string]struct{}, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
