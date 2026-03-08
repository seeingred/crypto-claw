package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seeingred/crypto-claw/internal/tss"
)

// ---------------------------------------------------------------------------
// State tests
// ---------------------------------------------------------------------------

func TestSanitizedStateExcludesSecrets(t *testing.T) {
	state := &WizardState{
		Step:             "dkg",
		CACert:           []byte("ca-cert-pem"),
		CAKey:            []byte("ca-key-pem"),
		CertA:            []byte("cert-a"),
		KeyA:             []byte("key-a"),
		CertB:            []byte("cert-b"),
		KeyB:             []byte("key-b"),
		LLMAPIKey:        "sk-secret-key",
		TelegramBotToken: "123456:ABC",
		ShareA:           &tss.KeyShare{PublicKey: []byte{0x04, 0xaa}},
		ShareB:           &tss.KeyShare{PublicKey: []byte{0x04, 0xbb}},
		ServerA:          SSHConfig{Host: "10.0.0.1", Port: 22, User: "admin", Password: "secret123", KeyPath: "/home/admin/.ssh/id_rsa"},
		ServerB:          SSHConfig{Host: "10.0.0.2", Port: 2222, User: "root"},
	}

	s := state.SanitizedState()

	// JSON-encode and ensure no secrets leak.
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(data)

	for _, secret := range []string{"ca-cert-pem", "ca-key-pem", "cert-a", "key-a", "sk-secret-key", "123456:ABC", "secret123", "/home/admin/.ssh/id_rsa"} {
		if strings.Contains(js, secret) {
			t.Errorf("sanitized state leaks secret %q", secret)
		}
	}

	// Verify expected fields are present.
	if s["step"] != "dkg" {
		t.Errorf("step = %v, want dkg", s["step"])
	}
	if s["certsGenerated"] != true {
		t.Error("certsGenerated should be true")
	}
	if s["dkgComplete"] != true {
		t.Error("dkgComplete should be true")
	}
	if s["telegramConfigured"] != true {
		t.Error("telegramConfigured should be true")
	}

	// Server info should have host/port/user but only boolean indicators for creds.
	srvA := s["serverA"].(map[string]any)
	if srvA["host"] != "10.0.0.1" {
		t.Errorf("serverA host = %v", srvA["host"])
	}
	if srvA["hasKey"] != true {
		t.Error("serverA hasKey should be true")
	}
	if srvA["hasPassword"] != true {
		t.Error("serverA hasPassword should be true")
	}
	srvB := s["serverB"].(map[string]any)
	if srvB["hasKey"] != false {
		t.Error("serverB hasKey should be false")
	}
	if srvB["hasPassword"] != false {
		t.Error("serverB hasPassword should be false")
	}
}

func TestSetECDSAKeys(t *testing.T) {
	state := &WizardState{}
	shareA := &tss.KeyShare{PublicKey: []byte{0xaa, 0xbb, 0xcc}}
	shareB := &tss.KeyShare{PublicKey: []byte{0xdd, 0xee, 0xff}}

	state.SetECDSAKeys(shareA, shareB)

	if state.ShareA != shareA || state.ShareB != shareB {
		t.Error("shares not stored correctly")
	}
	if state.ECDSAPubKey != "aabbcc" {
		t.Errorf("ECDSAPubKey = %q, want %q", state.ECDSAPubKey, "aabbcc")
	}
}

func TestSetEdDSAKeys(t *testing.T) {
	state := &WizardState{}
	shareA := &tss.KeyShare{PublicKey: []byte{0x11, 0x22}}
	shareB := &tss.KeyShare{PublicKey: []byte{0x33, 0x44}}

	state.SetEdDSAKeys(shareA, shareB)

	if state.EdShareA != shareA || state.EdShareB != shareB {
		t.Error("ed shares not stored correctly")
	}
	if state.EdDSAPubKey != "1122" {
		t.Errorf("EdDSAPubKey = %q, want %q", state.EdDSAPubKey, "1122")
	}
}

func TestAppendAndDrainLogs(t *testing.T) {
	state := &WizardState{}

	state.AppendLog("line 1")
	state.AppendLog("line 2")
	state.AppendLog("line 3")

	logs := state.DrainLogs()
	if len(logs) != 3 {
		t.Fatalf("expected 3 logs, got %d", len(logs))
	}
	if logs[0] != "line 1" || logs[2] != "line 3" {
		t.Error("log content mismatch")
	}

	// Drain again should be empty.
	logs2 := state.DrainLogs()
	if len(logs2) != 0 {
		t.Errorf("expected 0 logs after second drain, got %d", len(logs2))
	}
}

func TestDrainLogsConcurrent(t *testing.T) {
	state := &WizardState{}
	var wg sync.WaitGroup

	// Concurrent writers.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			state.AppendLog("concurrent log")
		}()
	}
	wg.Wait()

	logs := state.DrainLogs()
	if len(logs) != 100 {
		t.Errorf("expected 100 logs, got %d", len(logs))
	}
}

// ---------------------------------------------------------------------------
// SSHConfig tests
// ---------------------------------------------------------------------------

func TestSSHConfigAddr(t *testing.T) {
	tests := []struct {
		name string
		cfg  SSHConfig
		want string
	}{
		{
			name: "custom port",
			cfg:  SSHConfig{Host: "10.0.0.1", Port: 2222},
			want: "10.0.0.1:2222",
		},
		{
			name: "default port",
			cfg:  SSHConfig{Host: "example.com", Port: 0},
			want: "example.com:22",
		},
		{
			name: "standard port",
			cfg:  SSHConfig{Host: "192.168.1.1", Port: 22},
			want: "192.168.1.1:22",
		},
		{
			name: "ipv6",
			cfg:  SSHConfig{Host: "::1", Port: 22},
			want: "[::1]:22",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.Addr()
			if got != tt.want {
				t.Errorf("Addr() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// dedupStrings tests
// ---------------------------------------------------------------------------

func TestDedupStrings(t *testing.T) {
	tests := []struct {
		input []string
		want  []string
	}{
		{[]string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{[]string{"a", "a", "b"}, []string{"a", "b"}},
		{[]string{"localhost", "127.0.0.1", "localhost", "10.0.0.1"}, []string{"localhost", "127.0.0.1", "10.0.0.1"}},
		{nil, []string{}},
		{[]string{}, []string{}},
	}

	for _, tt := range tests {
		got := dedupStrings(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("dedupStrings(%v) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("dedupStrings(%v)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Certificate generation tests
// ---------------------------------------------------------------------------

func TestGenerateCerts(t *testing.T) {
	bundle, err := GenerateCerts([]string{"10.0.0.1"}, []string{"10.0.0.2"})
	if err != nil {
		t.Fatalf("GenerateCerts: %v", err)
	}

	if len(bundle.CACert) == 0 {
		t.Error("CACert is empty")
	}
	if len(bundle.CAKey) == 0 {
		t.Error("CAKey is empty")
	}
	if len(bundle.CertA) == 0 {
		t.Error("CertA is empty")
	}
	if len(bundle.KeyA) == 0 {
		t.Error("KeyA is empty")
	}
	if len(bundle.CertB) == 0 {
		t.Error("CertB is empty")
	}
	if len(bundle.KeyB) == 0 {
		t.Error("KeyB is empty")
	}

	// Verify PEM format.
	for name, pem := range map[string][]byte{
		"CACert": bundle.CACert,
		"CertA":  bundle.CertA,
		"CertB":  bundle.CertB,
	} {
		if !bytes.Contains(pem, []byte("-----BEGIN CERTIFICATE-----")) {
			t.Errorf("%s is not valid PEM", name)
		}
	}
	for name, pem := range map[string][]byte{
		"CAKey": bundle.CAKey,
		"KeyA":  bundle.KeyA,
		"KeyB":  bundle.KeyB,
	} {
		if !bytes.Contains(pem, []byte("-----BEGIN")) {
			t.Errorf("%s is not valid PEM", name)
		}
	}
}

func TestGenerateCertsLocalhost(t *testing.T) {
	// With no extra hosts, should still succeed (localhost/127.0.0.1 always included).
	bundle, err := GenerateCerts(nil, nil)
	if err != nil {
		t.Fatalf("GenerateCerts with nil hosts: %v", err)
	}
	if len(bundle.CertA) == 0 || len(bundle.CertB) == 0 {
		t.Error("certs should be generated even with nil extra hosts")
	}
}

// ---------------------------------------------------------------------------
// buildPartyConfig tests
// ---------------------------------------------------------------------------

func TestBuildPartyConfigA(t *testing.T) {
	state := &WizardState{
		PartyAAddr: "0.0.0.0:8080",
		ServerB:    SSHConfig{Host: "10.0.0.2"},
	}

	cfg := buildPartyConfig(state, "a", "/etc/crypto-claw")

	if cfg.Party != "a" {
		t.Errorf("Party = %q, want %q", cfg.Party, "a")
	}
	if cfg.API.ListenAddr != "0.0.0.0:8080" {
		t.Errorf("API.ListenAddr = %q, want %q", cfg.API.ListenAddr, "0.0.0.0:8080")
	}
	if cfg.Transport.RemoteAddr != "10.0.0.2:9000" {
		t.Errorf("Transport.RemoteAddr = %q, want %q", cfg.Transport.RemoteAddr, "10.0.0.2:9000")
	}
	if cfg.Transport.CertFile != "/etc/crypto-claw/cert.pem" {
		t.Errorf("Transport.CertFile = %q", cfg.Transport.CertFile)
	}
	if len(cfg.Chains.EVM) != 1 {
		t.Fatalf("expected 1 EVM chain, got %d", len(cfg.Chains.EVM))
	}
	if cfg.Chains.EVM[0].ChainID != 1 {
		t.Errorf("EVM chain ID = %d, want 1", cfg.Chains.EVM[0].ChainID)
	}
}

func TestBuildPartyConfigB(t *testing.T) {
	state := &WizardState{
		LLMProvider:      "anthropic",
		LLMAPIKey:        "sk-test",
		LLMModel:         "claude-sonnet-4-20250514",
		TelegramBotToken: "123:ABC",
		TelegramUserID:   42,
	}

	cfg := buildPartyConfig(state, "b", "/etc/crypto-claw")

	if cfg.Party != "b" {
		t.Errorf("Party = %q, want %q", cfg.Party, "b")
	}
	if cfg.Transport.ListenAddr != "0.0.0.0:9000" {
		t.Errorf("Transport.ListenAddr = %q, want %q", cfg.Transport.ListenAddr, "0.0.0.0:9000")
	}
	if cfg.Analyzer.LLM.Provider != "anthropic" {
		t.Errorf("LLM.Provider = %q", cfg.Analyzer.LLM.Provider)
	}
	if cfg.Analyzer.LLM.APIKey != "sk-test" {
		t.Errorf("LLM.APIKey not set correctly")
	}
	if cfg.Telegram.BotToken != "123:ABC" {
		t.Errorf("Telegram.BotToken not set correctly")
	}
	if cfg.Telegram.AuthorizedUserID != 42 {
		t.Errorf("Telegram.AuthorizedUserID = %d, want 42", cfg.Telegram.AuthorizedUserID)
	}
}

func TestBuildPartyConfigLocalMode(t *testing.T) {
	state := &WizardState{
		LocalMode:  true,
		PartyAAddr: "127.0.0.1:8080",
	}

	cfg := buildPartyConfig(state, "a", "/tmp/test")

	if cfg.Transport.RemoteAddr != "127.0.0.1:9000" {
		t.Errorf("local mode RemoteAddr = %q, want %q", cfg.Transport.RemoteAddr, "127.0.0.1:9000")
	}
}

// ---------------------------------------------------------------------------
// writeKeyShares tests
// ---------------------------------------------------------------------------

func TestWriteKeyShares(t *testing.T) {
	dir := t.TempDir()

	state := &WizardState{
		ShareA:   &tss.KeyShare{Curve: tss.CurveSecp256k1, PublicKey: []byte{0x04, 0xaa}},
		ShareB:   &tss.KeyShare{Curve: tss.CurveSecp256k1, PublicKey: []byte{0x04, 0xbb}},
		EdShareA: &tss.KeyShare{Curve: tss.CurveEd25519, PublicKey: []byte{0x01, 0x22}},
		EdShareB: &tss.KeyShare{Curve: tss.CurveEd25519, PublicKey: []byte{0x03, 0x44}},
	}

	// Write shares for party A.
	if err := writeKeyShares(state, "a", dir); err != nil {
		t.Fatalf("writeKeyShares(a): %v", err)
	}

	ecdsaPath := filepath.Join(dir, "ecdsa_share.json")
	eddsaPath := filepath.Join(dir, "eddsa_share.json")

	ecdsaData, err := os.ReadFile(ecdsaPath)
	if err != nil {
		t.Fatalf("read ECDSA share: %v", err)
	}
	eddsaData, err := os.ReadFile(eddsaPath)
	if err != nil {
		t.Fatalf("read EdDSA share: %v", err)
	}

	var ecdsaShare, eddsaShare tss.KeyShare
	if err := json.Unmarshal(ecdsaData, &ecdsaShare); err != nil {
		t.Fatalf("unmarshal ECDSA share: %v", err)
	}
	if err := json.Unmarshal(eddsaData, &eddsaShare); err != nil {
		t.Fatalf("unmarshal EdDSA share: %v", err)
	}

	if ecdsaShare.Curve != tss.CurveSecp256k1 {
		t.Errorf("ECDSA curve = %v, want secp256k1", ecdsaShare.Curve)
	}
	if eddsaShare.Curve != tss.CurveEd25519 {
		t.Errorf("EdDSA curve = %v, want ed25519", eddsaShare.Curve)
	}

	// Party B shares.
	dirB := t.TempDir()
	if err := writeKeyShares(state, "b", dirB); err != nil {
		t.Fatalf("writeKeyShares(b): %v", err)
	}

	ecdsaDataB, err := os.ReadFile(filepath.Join(dirB, "ecdsa_share.json"))
	if err != nil {
		t.Fatalf("read ECDSA share B: %v", err)
	}
	var ecdsaShareB tss.KeyShare
	if err := json.Unmarshal(ecdsaDataB, &ecdsaShareB); err != nil {
		t.Fatalf("unmarshal ECDSA share B: %v", err)
	}
	if !bytes.Equal(ecdsaShareB.PublicKey, []byte{0x04, 0xbb}) {
		t.Error("party B ECDSA share has wrong public key")
	}
}

func TestWriteKeySharesNil(t *testing.T) {
	dir := t.TempDir()
	state := &WizardState{} // no shares set

	if err := writeKeyShares(state, "a", dir); err != nil {
		t.Fatalf("writeKeyShares with nil shares: %v", err)
	}

	// Files should not exist.
	if _, err := os.Stat(filepath.Join(dir, "ecdsa_share.json")); !os.IsNotExist(err) {
		t.Error("ecdsa_share.json should not exist when share is nil")
	}
	if _, err := os.Stat(filepath.Join(dir, "eddsa_share.json")); !os.IsNotExist(err) {
		t.Error("eddsa_share.json should not exist when share is nil")
	}
}

// ---------------------------------------------------------------------------
// API handler tests
// ---------------------------------------------------------------------------

func newTestMux(state *WizardState) *http.ServeMux {
	mux := http.NewServeMux()
	registerAPIRoutes(mux, state)
	return mux
}

func TestHandleState(t *testing.T) {
	state := &WizardState{
		Step:      "welcome",
		LocalMode: true,
	}

	mux := newTestMux(state)
	req := httptest.NewRequest("GET", "/api/state", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["step"] != "welcome" {
		t.Errorf("step = %v, want welcome", resp["step"])
	}
	if resp["localMode"] != true {
		t.Errorf("localMode = %v, want true", resp["localMode"])
	}
}

func TestHandleLocalhostSetup(t *testing.T) {
	state := &WizardState{Step: "welcome"}
	mux := newTestMux(state)

	body := `{"partyAAddr":"127.0.0.1:9090"}`
	req := httptest.NewRequest("POST", "/api/localhost/setup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if !state.LocalMode {
		t.Error("LocalMode should be true")
	}
	if state.PartyAAddr != "127.0.0.1:9090" {
		t.Errorf("PartyAAddr = %q, want %q", state.PartyAAddr, "127.0.0.1:9090")
	}
	if state.Step != "servers" {
		t.Errorf("Step = %q, want %q", state.Step, "servers")
	}
	if state.ServerA.Host != "127.0.0.1" {
		t.Errorf("ServerA.Host = %q, want %q", state.ServerA.Host, "127.0.0.1")
	}
}

func TestHandleLocalhostSetupDefaults(t *testing.T) {
	state := &WizardState{Step: "welcome"}
	mux := newTestMux(state)

	// Empty body — should use defaults.
	req := httptest.NewRequest("POST", "/api/localhost/setup", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if state.PartyAAddr != "127.0.0.1:8080" {
		t.Errorf("PartyAAddr = %q, want default", state.PartyAAddr)
	}
}

func TestHandleServersSave(t *testing.T) {
	state := &WizardState{Step: "welcome"}
	mux := newTestMux(state)

	body := `{
		"serverA": {"host": "10.0.0.1", "port": 22, "user": "admin"},
		"serverB": {"host": "10.0.0.2", "port": 2222, "user": "root", "password": "pass"}
	}`
	req := httptest.NewRequest("POST", "/api/servers/save", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if state.ServerA.Host != "10.0.0.1" {
		t.Errorf("ServerA.Host = %q", state.ServerA.Host)
	}
	if state.ServerB.Port != 2222 {
		t.Errorf("ServerB.Port = %d", state.ServerB.Port)
	}
	if state.ServerB.Password != "pass" {
		t.Errorf("ServerB.Password not saved")
	}
	if state.Step != "servers" {
		t.Errorf("Step = %q, want %q", state.Step, "servers")
	}
}

func TestHandleServersTestValidation(t *testing.T) {
	state := &WizardState{}
	mux := newTestMux(state)

	tests := []struct {
		name string
		body string
		want string
	}{
		{"missing host", `{"user":"root"}`, "host is required"},
		{"missing user", `{"host":"10.0.0.1"}`, "user is required"},
		{"invalid json", `{bad}`, "invalid request body"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/servers/test", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
			}

			var resp map[string]string
			json.Unmarshal(w.Body.Bytes(), &resp)
			if !strings.Contains(resp["error"], tt.want) {
				t.Errorf("error = %q, want to contain %q", resp["error"], tt.want)
			}
		})
	}
}

func TestHandleInstallPrepare(t *testing.T) {
	state := &WizardState{}
	mux := newTestMux(state)

	req := httptest.NewRequest("POST", "/api/install/prepare", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	mnemonic, ok := resp["mnemonic"].(string)
	if !ok || mnemonic == "" {
		t.Error("response missing mnemonic")
	}
	words := strings.Split(mnemonic, " ")
	if len(words) != 24 {
		t.Errorf("mnemonic has %d words, want 24", len(words))
	}

	if resp["ecdsaPubKey"] == nil || resp["ecdsaPubKey"] == "" {
		t.Error("response missing ecdsaPubKey")
	}
	if resp["eddsaPubKey"] == nil || resp["eddsaPubKey"] == "" {
		t.Error("response missing eddsaPubKey")
	}

	if state.Mnemonic == "" {
		t.Error("mnemonic not stored in state")
	}
	if state.Step != "prepared" {
		t.Errorf("Step = %q, want %q", state.Step, "prepared")
	}
}

func TestHandleDeployRequiresPrepare(t *testing.T) {
	state := &WizardState{} // no mnemonic
	mux := newTestMux(state)

	req := httptest.NewRequest("POST", "/api/deploy", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	body := w.Body.String()
	if !strings.Contains(body, "install/prepare") {
		t.Errorf("error should mention install/prepare, got: %s", body)
	}
}

func TestHandleLLMSave(t *testing.T) {
	state := &WizardState{}
	mux := newTestMux(state)

	body := `{"provider":"anthropic","apiKey":"sk-test","model":"claude-sonnet-4-20250514"}`
	req := httptest.NewRequest("POST", "/api/llm/save", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if state.LLMProvider != "anthropic" {
		t.Errorf("LLMProvider = %q", state.LLMProvider)
	}
	if state.LLMAPIKey != "sk-test" {
		t.Errorf("LLMAPIKey not saved")
	}
	if state.LLMModel != "claude-sonnet-4-20250514" {
		t.Errorf("LLMModel = %q", state.LLMModel)
	}
	if state.Step != "llm" {
		t.Errorf("Step = %q, want %q", state.Step, "llm")
	}
}

func TestHandleLLMSaveValidation(t *testing.T) {
	state := &WizardState{}
	mux := newTestMux(state)

	body := `{"apiKey":"sk-test"}`
	req := httptest.NewRequest("POST", "/api/llm/save", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !strings.Contains(resp["error"], "provider is required") {
		t.Errorf("error = %q", resp["error"])
	}
}

func TestHandleTelegramSaveInvalidToken(t *testing.T) {
	state := &WizardState{}
	mux := newTestMux(state)

	// Invalid token should return status "error" without saving.
	body := `{"botToken":"123456:ABCdefGHI"}`
	req := httptest.NewRequest("POST", "/api/telegram/save", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "error" {
		t.Errorf("expected status=error for invalid token, got %v", resp["status"])
	}
	// Token should NOT be saved for invalid token.
	if state.TelegramBotToken != "" {
		t.Errorf("TelegramBotToken should not be saved for invalid token")
	}
}

func TestHandleTelegramSaveValidation(t *testing.T) {
	state := &WizardState{}
	mux := newTestMux(state)

	body := `{}`
	req := httptest.NewRequest("POST", "/api/telegram/save", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}


// TestHandleDKGCancelAndRestart verifies that a second DKG request cancels the
// first one and proceeds instead of returning 409 forever. This is the fix for
// the bug where refreshing the page during DKG left the handler permanently locked.
func TestHandleDKGCancelAndRestart(t *testing.T) {
	// We can't easily test the real DKG handler (takes minutes), so we test
	// the cancel-and-wait pattern with a simulated slow handler.
	var (
		mu         sync.Mutex
		cancelPrev context.CancelFunc
		done       chan struct{}
	)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if cancelPrev != nil && done != nil {
			cancelPrev()
			waitCh := done
			mu.Unlock()
			<-waitCh
			mu.Lock()
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancelPrev = cancel
		done = make(chan struct{})
		currentDone := done
		mu.Unlock()

		defer close(currentDone)

		// Simulate slow work that respects cancellation.
		select {
		case <-ctx.Done():
			writeError(w, http.StatusInternalServerError, "cancelled")
			return
		case <-time.After(2 * time.Second):
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux := http.NewServeMux()
	mux.HandleFunc("POST /test", handler)

	// Start first request in background.
	var wg sync.WaitGroup
	w1 := httptest.NewRecorder()
	wg.Add(1)
	go func() {
		defer wg.Done()
		req := httptest.NewRequest("POST", "/test", nil)
		mux.ServeHTTP(w1, req)
	}()

	// Give first handler time to start.
	time.Sleep(50 * time.Millisecond)

	// Second request should cancel the first and proceed (not 409).
	w2 := httptest.NewRecorder()
	wg.Add(1)
	go func() {
		defer wg.Done()
		req := httptest.NewRequest("POST", "/test", nil)
		mux.ServeHTTP(w2, req)
	}()

	wg.Wait()

	// First request should have been cancelled.
	if w1.Code != http.StatusInternalServerError {
		t.Errorf("first request status = %d, want %d (cancelled)", w1.Code, http.StatusInternalServerError)
	}
	// Second request should succeed.
	if w2.Code != http.StatusOK {
		t.Errorf("second request status = %d, want %d", w2.Code, http.StatusOK)
	}
}

func TestCORSMiddleware(t *testing.T) {
	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// OPTIONS request.
	req := httptest.NewRequest("OPTIONS", "/api/state", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("OPTIONS status = %d, want %d", w.Code, http.StatusNoContent)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("CORS origin header missing")
	}
	if w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("CORS methods header missing")
	}

	// Normal request.
	req2 := httptest.NewRequest("GET", "/api/state", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("GET status = %d, want %d", w2.Code, http.StatusOK)
	}
	if w2.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("CORS origin header missing on GET")
	}
}

func TestFallbackHandler(t *testing.T) {
	// Root path should return HTML.
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	fallbackHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "Crypto Claw Installer") {
		t.Error("fallback HTML missing expected content")
	}
	if w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q", w.Header().Get("Content-Type"))
	}

	// Non-root path should 404.
	req2 := httptest.NewRequest("GET", "/some/path", nil)
	w2 := httptest.NewRecorder()
	fallbackHandler(w2, req2)

	if w2.Code != http.StatusNotFound {
		t.Errorf("non-root status = %d, want %d", w2.Code, http.StatusNotFound)
	}
}

func TestDeployLogsSSE(t *testing.T) {
	state := &WizardState{}
	state.AppendLog("log line 1")
	state.AppendLog("log line 2")
	state.DeployDone = true

	mux := newTestMux(state)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req := httptest.NewRequest("GET", "/api/deploy/logs", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, `"message":"log line 1"`) {
		t.Errorf("SSE missing log line 1, body: %s", body)
	}
	if !strings.Contains(body, `"message":"log line 2"`) {
		t.Errorf("SSE missing log line 2, body: %s", body)
	}
	if !strings.Contains(body, `"type":"complete"`) {
		t.Errorf("SSE missing complete event, body: %s", body)
	}
	if w.Header().Get("Content-Type") != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", w.Header().Get("Content-Type"))
	}
}

// TestDockerBuildWithLogs verifies that dockerBuildWithLogs streams output
// with [build] prefix so the frontend progress bar can track it.
func TestDockerBuildWithLogs(t *testing.T) {
	// Use a simple command that produces output instead of actual docker build.
	// We test the log streaming mechanism by running "echo" lines.
	var mu sync.Mutex
	var logs []string
	logFn := func(msg string) {
		mu.Lock()
		defer mu.Unlock()
		logs = append(logs, msg)
	}

	// Create a tiny script that outputs a few lines to stdout and stderr.
	tmpDir := t.TempDir()
	script := filepath.Join(tmpDir, "fake-build.sh")
	os.WriteFile(script, []byte("#!/bin/sh\necho 'Step 1/3: FROM golang'\necho 'Step 2/3: COPY . .' >&2\necho 'Step 3/3: RUN go build'\n"), 0755)

	// Use the script as a "docker build" command by testing the io.Pipe logic directly.
	cmd := exec.Command("sh", script)
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		scanner := bufio.NewScanner(pr)
		scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)
		for scanner.Scan() {
			line := scanner.Text()
			if trimmed := strings.TrimSpace(line); trimmed != "" {
				logFn(fmt.Sprintf("[build] %s", trimmed))
			}
		}
	}()

	err := cmd.Wait()
	pw.Close()
	<-scanDone

	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(logs) < 3 {
		t.Fatalf("expected at least 3 log lines, got %d: %v", len(logs), logs)
	}

	// All logs should have [build] prefix.
	for _, l := range logs {
		if !strings.HasPrefix(l, "[build] ") {
			t.Errorf("log missing [build] prefix: %q", l)
		}
	}

	// stderr line should also be captured (io.Pipe merges both).
	found := false
	for _, l := range logs {
		if strings.Contains(l, "COPY") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("stderr output not captured, logs: %v", logs)
	}
}

// TestDeployLogProgressMarkers verifies that the log messages from handleDeploy
// contain the patterns that the frontend progress bar relies on.
func TestDeployLogProgressMarkers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	t.Setenv("CRYPTO_CLAW_NO_PROCESSES", "1")

	ppA, ppB := ensurePreParams(t)
	state := &WizardState{
		Step:          "welcome",
		LocalMode:     true,
		preParamReady: make(chan struct{}),
	}
	state.InjectPreParams(ppA, ppB)

	mux := http.NewServeMux()
	registerAPIRoutes(mux, state)
	server := httptest.NewServer(corsMiddleware(mux))
	defer server.Close()
	client := server.Client()

	// Setup: servers, LLM, telegram, prepare
	client.Post(server.URL+"/api/servers/save", "application/json",
		strings.NewReader(`{"localMode":true,"serverA":{"host":"127.0.0.1","port":22,"user":"local"},"serverB":{"host":"127.0.0.1","port":22,"user":"local"}}`))
	client.Post(server.URL+"/api/llm/skip", "application/json", nil)
	state.mu.Lock()
	state.TelegramBotToken = "123456:test"
	state.TelegramUserID = 1
	state.Step = "telegram"
	state.mu.Unlock()
	client.Post(server.URL+"/api/install/prepare", "application/json", nil)

	// Collect SSE logs
	logsCh := make(chan string, 200)
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		resp, err := client.Get(server.URL + "/api/deploy/logs")
		if err != nil {
			return
		}
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			var msg map[string]string
			json.Unmarshal([]byte(line[6:]), &msg)
			logsCh <- msg["message"]
			if msg["type"] == "complete" || msg["type"] == "error" {
				return
			}
		}
	}()

	// Deploy
	client.Post(server.URL+"/api/deploy", "application/json", nil)

	// Collect all logs
	var allLogs []string
	timeout := time.After(5 * time.Minute)
loop:
	for {
		select {
		case msg := <-logsCh:
			allLogs = append(allLogs, msg)
		case <-doneCh:
			for {
				select {
				case msg := <-logsCh:
					allLogs = append(allLogs, msg)
				default:
					break loop
				}
			}
		case <-timeout:
			t.Fatal("timed out")
		}
	}

	// These patterns are required by the frontend progress bar.
	// If any are missing, the progress bar will be broken.
	requiredPatterns := []string{
		"Deriving keys",
		"Key shares generated",
		"TLS certificates generated",
		"Configuration written",
		"deployment complete",
	}

	joined := strings.Join(allLogs, "\n")
	for _, pattern := range requiredPatterns {
		if !strings.Contains(joined, pattern) {
			t.Errorf("missing required progress marker: %q", pattern)
			t.Logf("All logs:\n%s", joined)
		}
	}

	// Cleanup
	os.RemoveAll(localBaseDir())
}

// ---------------------------------------------------------------------------
// DKG integration test
// ---------------------------------------------------------------------------

func TestRunInstallerDKG(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DKG test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	ecdsaResult, eddsaResult, err := RunInstallerDKG(ctx)
	if err != nil {
		t.Fatalf("RunInstallerDKG: %v", err)
	}

	// ECDSA checks.
	if ecdsaResult.ShareA == nil || ecdsaResult.ShareB == nil {
		t.Fatal("ECDSA shares are nil")
	}
	if len(ecdsaResult.ShareA.PublicKey) == 0 {
		t.Error("ECDSA ShareA public key is empty")
	}
	if len(ecdsaResult.ShareB.PublicKey) == 0 {
		t.Error("ECDSA ShareB public key is empty")
	}
	// Both parties should have the same public key.
	if !bytes.Equal(ecdsaResult.ShareA.PublicKey, ecdsaResult.ShareB.PublicKey) {
		t.Error("ECDSA public keys differ between parties")
	}
	if ecdsaResult.ShareA.Curve != tss.CurveSecp256k1 {
		t.Errorf("ECDSA curve = %v, want secp256k1", ecdsaResult.ShareA.Curve)
	}

	// EdDSA checks.
	if eddsaResult.ShareA == nil || eddsaResult.ShareB == nil {
		t.Fatal("EdDSA shares are nil")
	}
	if len(eddsaResult.ShareA.PublicKey) == 0 {
		t.Error("EdDSA ShareA public key is empty")
	}
	if !bytes.Equal(eddsaResult.ShareA.PublicKey, eddsaResult.ShareB.PublicKey) {
		t.Error("EdDSA public keys differ between parties")
	}
	if eddsaResult.ShareA.Curve != tss.CurveEd25519 {
		t.Errorf("EdDSA curve = %v, want ed25519", eddsaResult.ShareA.Curve)
	}

	// Shares should be different (they hold different secret shares).
	if bytes.Equal(ecdsaResult.ShareA.Share, ecdsaResult.ShareB.Share) {
		t.Error("ECDSA shares should differ between parties")
	}
}

// ---------------------------------------------------------------------------
// findAvailableAddr tests
// ---------------------------------------------------------------------------

func TestFindAvailableListener(t *testing.T) {
	ln, err := findAvailableListener(0)
	if err != nil {
		t.Fatal("findAvailableListener(0):", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("invalid addr %q: %v", addr, err)
	}
	if host != "127.0.0.1" {
		t.Errorf("host = %q, want 127.0.0.1", host)
	}
	if port == "" {
		t.Error("port is empty")
	}
}

func TestFindAvailableListenerBusyPort(t *testing.T) {
	// Occupy a port, then ask for it.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listen:", err)
	}
	defer busy.Close()

	_, busyPortStr, _ := net.SplitHostPort(busy.Addr().String())
	busyPort := 0
	fmt.Sscanf(busyPortStr, "%d", &busyPort)

	ln, err := findAvailableListener(busyPort)
	if err != nil {
		t.Fatal("findAvailableListener:", err)
	}
	defer ln.Close()

	_, gotPort, _ := net.SplitHostPort(ln.Addr().String())
	if gotPort == busyPortStr {
		t.Errorf("returned the busy port %s", busyPortStr)
	}
}

func TestFindAvailableListenerPreferred(t *testing.T) {
	// When the preferred port is free, it should be used.
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listen:", err)
	}
	freeAddr := tmp.Addr().String()
	tmp.Close() // release it

	_, freePortStr, _ := net.SplitHostPort(freeAddr)
	freePort := 0
	fmt.Sscanf(freePortStr, "%d", &freePort)

	ln, err := findAvailableListener(freePort)
	if err != nil {
		t.Fatal("findAvailableListener:", err)
	}
	defer ln.Close()

	_, gotPort, _ := net.SplitHostPort(ln.Addr().String())
	if gotPort != freePortStr {
		t.Errorf("got port %s, want preferred %s", gotPort, freePortStr)
	}
}

// ---------------------------------------------------------------------------
// State restoration test (backend step → frontend step index mapping)
// ---------------------------------------------------------------------------

func TestHandleStateReturnsStep(t *testing.T) {
	state := &WizardState{Step: "dkg"}
	mux := newTestMux(state)

	req := httptest.NewRequest("GET", "/api/state", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	step, ok := resp["step"]
	if !ok {
		t.Fatal("response missing 'step' field")
	}
	if step != "dkg" {
		t.Errorf("step = %q, want %q", step, "dkg")
	}
}

func TestHandleStatePreservesProgress(t *testing.T) {
	// Simulate a wizard that has completed through the LLM step.
	state := &WizardState{
		Step:        "llm",
		LLMProvider: "anthropic",
		LLMModel:    "claude-sonnet-4-20250514",
		ECDSAPubKey: "abcdef1234",
		EdDSAPubKey: "5678fedcba",
	}
	state.ShareA = &tss.KeyShare{PublicKey: []byte{1}}
	state.ShareB = &tss.KeyShare{PublicKey: []byte{1}}

	mux := newTestMux(state)

	req := httptest.NewRequest("GET", "/api/state", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	// All progress should be reflected.
	if resp["step"] != "llm" {
		t.Errorf("step = %v, want llm", resp["step"])
	}
	if resp["dkgComplete"] != true {
		t.Errorf("dkgComplete = %v, want true", resp["dkgComplete"])
	}
	if resp["llmConfigured"] != true {
		t.Errorf("llmConfigured = %v, want true", resp["llmConfigured"])
	}
	if resp["ecdsaPubKey"] != "abcdef1234" {
		t.Errorf("ecdsaPubKey = %v", resp["ecdsaPubKey"])
	}
}

// ---------------------------------------------------------------------------
// findProjectRoot test
// ---------------------------------------------------------------------------

func TestFindProjectRoot(t *testing.T) {
	root := findProjectRoot()
	// Should find the repo root (which has go.mod).
	goModPath := filepath.Join(root, "go.mod")
	if _, err := os.Stat(goModPath); err != nil {
		t.Errorf("findProjectRoot() = %q, but go.mod not found there", root)
	}
}
