package analyzer

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/seeingred/crypto-claw/internal/config"
	"github.com/seeingred/crypto-claw/internal/store"
	"github.com/seeingred/crypto-claw/internal/transport"
	"github.com/seeingred/crypto-claw/internal/vm"
	"github.com/seeingred/crypto-claw/internal/vm/evm"

	"log/slog"
)

// mockWhitelist implements WhitelistChecker for tests.
type mockWhitelist struct {
	entries map[string]*store.WhitelistEntry
}

func (m *mockWhitelist) IsWhitelisted(_ context.Context, address string) (bool, error) {
	_, ok := m.entries[address]
	return ok, nil
}

func (m *mockWhitelist) GetWhitelistEntry(_ context.Context, address string) (*store.WhitelistEntry, error) {
	e, ok := m.entries[address]
	if !ok {
		return nil, nil
	}
	return e, nil
}

func TestAnalyze_RejectsZeroAddress(t *testing.T) {
	cfg := config.AnalyzerConfig{DisableAI: true}
	a := New(cfg, nil, nil, slog.Default())

	req := transport.SignRequestPayload{
		To:             []string{"0x0000000000000000000000000000000000000000"},
		Value:          "1000",
		DerivationPath: "m/44'/60'/0'/0/0",
		UnsignedTx:     base64.StdEncoding.EncodeToString([]byte("fake")),
		SignableBytes:  base64.StdEncoding.EncodeToString([]byte("fake")),
	}

	result := a.Analyze(context.Background(), req)
	if result.Decision.Action != ActionReject {
		t.Errorf("expected reject for zero address, got %s", result.Decision.Action)
	}
}

func TestAnalyze_RejectsNoRecipients(t *testing.T) {
	cfg := config.AnalyzerConfig{DisableAI: true}
	a := New(cfg, nil, nil, slog.Default())

	req := transport.SignRequestPayload{
		To:             []string{},
		DerivationPath: "m/44'/60'/0'/0/0",
		UnsignedTx:     base64.StdEncoding.EncodeToString([]byte("fake")),
		SignableBytes:  base64.StdEncoding.EncodeToString([]byte("fake")),
	}

	result := a.Analyze(context.Background(), req)
	if result.Decision.Action != ActionReject {
		t.Errorf("expected reject for no recipients, got %s", result.Decision.Action)
	}
}

func TestAnalyze_WhitelistedAddressApproves(t *testing.T) {
	wl := &mockWhitelist{entries: map[string]*store.WhitelistEntry{
		"0xabcdef1234567890abcdef1234567890abcdef12": {
			Address: "0xabcdef1234567890abcdef1234567890abcdef12",
			Label:   "test wallet",
		},
	}}

	cfg := config.AnalyzerConfig{DisableAI: true}
	a := New(cfg, nil, wl, slog.Default())

	req := transport.SignRequestPayload{
		To:             []string{"0xabcdef1234567890abcdef1234567890abcdef12"},
		Value:          "1000",
		DerivationPath: "m/44'/60'/0'/0/0",
		UnsignedTx:     base64.StdEncoding.EncodeToString([]byte("fake")),
		SignableBytes:  base64.StdEncoding.EncodeToString([]byte("fake")),
	}

	result := a.Analyze(context.Background(), req)
	if result.Decision.Action != ActionApprove {
		t.Errorf("expected approve for whitelisted address, got %s", result.Decision.Action)
	}
	if !result.Whitelisted {
		t.Error("expected Whitelisted=true")
	}
	if result.WhitelistLabel != "test wallet" {
		t.Errorf("expected label 'test wallet', got %q", result.WhitelistLabel)
	}
}

func TestAnalyze_NonWhitelistedEscalates(t *testing.T) {
	wl := &mockWhitelist{entries: map[string]*store.WhitelistEntry{}}

	cfg := config.AnalyzerConfig{DisableAI: true}
	a := New(cfg, nil, wl, slog.Default())

	req := transport.SignRequestPayload{
		To:             []string{"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		Value:          "1000",
		DerivationPath: "m/44'/60'/0'/0/0",
		UnsignedTx:     base64.StdEncoding.EncodeToString([]byte("fake")),
		SignableBytes:  base64.StdEncoding.EncodeToString([]byte("fake")),
	}

	result := a.Analyze(context.Background(), req)
	if result.Decision.Action != ActionEscalate {
		t.Errorf("expected escalate for non-whitelisted (AI disabled), got %s", result.Decision.Action)
	}
}

func TestAnalyze_DecodesEVMTransaction(t *testing.T) {
	// Build a real EVM unsigned tx.
	vmReg := vm.NewRegistry()
	vmReg.Register([]string{"60"}, evm.New())

	adapter := evm.New()
	unsignedTx, err := adapter.BuildUnsignedTx(context.Background(), &vm.TxRequest{
		To:      []string{"0x1111111111111111111111111111111111111111"},
		Value:   "1000000000000000000",
		ChainID: "1",
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.AnalyzerConfig{DisableAI: true}
	a := New(cfg, vmReg, nil, slog.Default())

	req := transport.SignRequestPayload{
		To:             []string{"0x1111111111111111111111111111111111111111"},
		Value:          "1000000000000000000",
		DerivationPath: "m/44'/60'/0'/0/0",
		UnsignedTx:     base64.StdEncoding.EncodeToString(unsignedTx.RawBytes),
		SignableBytes:  base64.StdEncoding.EncodeToString(unsignedTx.Hash),
	}

	result := a.Analyze(context.Background(), req)

	if result.DecodedTx == nil {
		t.Fatal("expected decoded tx, got nil")
	}
	if !result.SignableBytesOK {
		t.Error("expected signable bytes to match")
	}
	if len(result.DecodedTx.To) == 0 || result.DecodedTx.To[0] != "0x1111111111111111111111111111111111111111" {
		t.Errorf("unexpected decoded to: %v", result.DecodedTx.To)
	}
}

func TestAnalyze_DetectsSignableBytesMismatch(t *testing.T) {
	vmReg := vm.NewRegistry()
	vmReg.Register([]string{"60"}, evm.New())

	adapter := evm.New()
	unsignedTx, err := adapter.BuildUnsignedTx(context.Background(), &vm.TxRequest{
		To:      []string{"0x1111111111111111111111111111111111111111"},
		Value:   "1000",
		ChainID: "1",
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.AnalyzerConfig{DisableAI: true}
	a := New(cfg, vmReg, nil, slog.Default())

	// Tamper with signable bytes.
	tamperedHash := make([]byte, 32)
	copy(tamperedHash, unsignedTx.Hash)
	tamperedHash[0] ^= 0xFF

	req := transport.SignRequestPayload{
		To:             []string{"0x1111111111111111111111111111111111111111"},
		Value:          "1000",
		DerivationPath: "m/44'/60'/0'/0/0",
		UnsignedTx:     base64.StdEncoding.EncodeToString(unsignedTx.RawBytes),
		SignableBytes:  base64.StdEncoding.EncodeToString(tamperedHash),
	}

	result := a.Analyze(context.Background(), req)

	if result.SignableBytesOK {
		t.Error("expected signable bytes mismatch")
	}
	if result.Decision.Action != ActionReject {
		t.Errorf("expected reject for tampered signable bytes, got %s", result.Decision.Action)
	}
}

func TestAnalyze_HighValueEscalates(t *testing.T) {
	cfg := config.AnalyzerConfig{DisableAI: true}
	a := New(cfg, nil, nil, slog.Default())

	req := transport.SignRequestPayload{
		To:             []string{"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		Value:          "200000000000000000000", // 200 ETH
		DerivationPath: "m/44'/60'/0'/0/0",
		UnsignedTx:     base64.StdEncoding.EncodeToString([]byte("fake")),
		SignableBytes:  base64.StdEncoding.EncodeToString([]byte("fake")),
	}

	result := a.Analyze(context.Background(), req)
	if result.Decision.Action != ActionEscalate {
		t.Errorf("expected escalate for high value, got %s", result.Decision.Action)
	}
}

func TestIdentifyChain(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"m/44'/60'/0'/0/0", "EVM (Ethereum)"},
		{"m/44'/501'/0'/0'", "Solana"},
		{"m/44'/118'/0'/0/0", "Cosmos"},
		{"m/44'/999'/0'/0/0", "unknown"},
	}
	for _, tt := range tests {
		got := identifyChain(tt.path)
		if got != tt.want {
			t.Errorf("identifyChain(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestFormatValue(t *testing.T) {
	got := formatValue("1500000000000000000", "EVM (Ethereum)")
	if got != "1.500000 ETH" {
		t.Errorf("formatValue = %q, want %q", got, "1.500000 ETH")
	}

	got = formatValue("0", "EVM (Ethereum)")
	if got != "" {
		t.Errorf("formatValue for zero = %q, want empty", got)
	}

	got = formatValue("100", "Solana")
	if got != "" {
		t.Errorf("formatValue for non-EVM = %q, want empty", got)
	}
}
