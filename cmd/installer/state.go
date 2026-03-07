package main

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/seeingred/crypto-claw/internal/tss"
)

// WizardState holds all configuration gathered during the installer wizard.
type WizardState struct {
	mu sync.Mutex

	// Current wizard step.
	Step string `json:"step"`

	// Installer mode: "install" (new), "restore" (from mnemonic), "update" (code only).
	Mode string `json:"mode"`

	// Server configuration for SSH deployment.
	ServerA   SSHConfig `json:"serverA"`
	ServerB   SSHConfig `json:"serverB"`
	LocalMode bool      `json:"localMode"` // localhost installation for testing

	// Generated TLS certificates (PEM-encoded, populated during install).
	CACert []byte `json:"-"`
	CAKey  []byte `json:"-"`
	CertA  []byte `json:"-"`
	KeyA   []byte `json:"-"`
	CertB  []byte `json:"-"`
	KeyB   []byte `json:"-"`

	// Mnemonic and derived keys (populated during install/prepare).
	Mnemonic    string         `json:"-"` // 24-word BIP-39 recovery phrase
	ECDSAPubKey string         `json:"ecdsaPubKey,omitempty"`
	EdDSAPubKey string         `json:"eddsaPubKey,omitempty"`
	ShareA      *tss.KeyShare  `json:"-"`
	ShareB      *tss.KeyShare  `json:"-"`
	EdShareA    *tss.KeyShare  `json:"-"`
	EdShareB    *tss.KeyShare  `json:"-"`

	// LLM configuration.
	LLMProvider string `json:"llmProvider,omitempty"`
	LLMAPIKey   string `json:"-"`
	LLMModel    string `json:"llmModel,omitempty"`
	LLMEndpoint string `json:"llmEndpoint,omitempty"`
	DisableAI   bool   `json:"disableAI,omitempty"` // skip LLM, deterministic + whitelist only

	// Telegram configuration.
	TelegramBotToken    string `json:"-"`
	TelegramBotUsername string `json:"telegramBotUsername,omitempty"`
	TelegramUserID      int64  `json:"telegramUserId,omitempty"`

	// Deployment state.
	DeployLogs   []string `json:"-"`
	DeployDone   bool     `json:"deployDone"`
	DeployFailed bool     `json:"deployFailed"`

	// Party A configuration.
	PartyAAddr string `json:"partyAAddr,omitempty"` // e.g., "127.0.0.1:8080"

	// Pre-computed ECDSA parameters (Paillier safe primes).
	// Generated in background on startup to avoid blocking install.
	preParamA     *keygen.LocalPreParams
	preParamB     *keygen.LocalPreParams
	preParamReady chan struct{} // closed when both are ready
	preParamErr   error
}

// SanitizedState returns a copy of the state safe for sending to the frontend
// (no secrets like keys, tokens, or SSH passwords).
func (s *WizardState) SanitizedState() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()

	return map[string]any{
		"step":      s.Step,
		"mode":      s.Mode,
		"localMode": s.LocalMode,
		"serverA": map[string]any{
			"host":       s.ServerA.Host,
			"port":       s.ServerA.Port,
			"user":       s.ServerA.User,
			"hasKey":     s.ServerA.KeyPath != "",
			"hasPassword": s.ServerA.Password != "",
		},
		"serverB": map[string]any{
			"host":       s.ServerB.Host,
			"port":       s.ServerB.Port,
			"user":       s.ServerB.User,
			"hasKey":     s.ServerB.KeyPath != "",
			"hasPassword": s.ServerB.Password != "",
		},
		"certsGenerated":   len(s.CACert) > 0,
		"ecdsaPubKey":      s.ECDSAPubKey,
		"eddsaPubKey":      s.EdDSAPubKey,
		"dkgComplete":      s.ShareA != nil && s.ShareB != nil,
		"mnemonicGenerated": s.Mnemonic != "",
		"llmProvider":    s.LLMProvider,
		"llmModel":       s.LLMModel,
		"llmEndpoint":    s.LLMEndpoint,
		"llmConfigured":  s.LLMProvider != "" || s.DisableAI,
		"disableAI":      s.DisableAI,
		"telegramConfigured":   s.TelegramBotToken != "",
		"telegramBotUsername":  s.TelegramBotUsername,
		"telegramUserId":      s.TelegramUserID,
		"deployDone":         s.DeployDone,
		"partyAAddr":         s.PartyAAddr,
	}
}

// SetECDSAKeys stores the ECDSA DKG results.
func (s *WizardState) SetECDSAKeys(shareA, shareB *tss.KeyShare) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ShareA = shareA
	s.ShareB = shareB
	s.ECDSAPubKey = hex.EncodeToString(shareA.PublicKey)
}

// SetEdDSAKeys stores the EdDSA DKG results.
func (s *WizardState) SetEdDSAKeys(shareA, shareB *tss.KeyShare) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.EdShareA = shareA
	s.EdShareB = shareB
	s.EdDSAPubKey = hex.EncodeToString(shareA.PublicKey)
}

// StartPreParamGeneration begins generating ECDSA safe primes in the background.
// This is slow (2-10 min) but runs while the user fills in wizard steps.
func (s *WizardState) StartPreParamGeneration() {
	s.preParamReady = make(chan struct{})
	go func() {
		defer close(s.preParamReady)
		slog.Info("background: generating ECDSA safe primes (this runs while you configure the wizard)...")

		var wg sync.WaitGroup
		var ppA, ppB *keygen.LocalPreParams
		var errA, errB error

		wg.Add(2)
		go func() {
			defer wg.Done()
			ppA, errA = keygen.GeneratePreParams(10 * time.Minute)
		}()
		go func() {
			defer wg.Done()
			ppB, errB = keygen.GeneratePreParams(10 * time.Minute)
		}()
		wg.Wait()

		s.mu.Lock()
		defer s.mu.Unlock()
		if errA != nil {
			s.preParamErr = errA
			slog.Error("background: pre-param generation failed", "error", errA)
			return
		}
		if errB != nil {
			s.preParamErr = errB
			slog.Error("background: pre-param generation failed", "error", errB)
			return
		}
		s.preParamA = ppA
		s.preParamB = ppB
		slog.Info("background: ECDSA safe primes ready")
	}()
}

// WaitPreParams blocks until pre-params are ready.
// Logs periodic updates so the UI doesn't appear stuck.
func (s *WizardState) WaitPreParams(logFn func(string)) (*keygen.LocalPreParams, *keygen.LocalPreParams, error) {
	s.mu.Lock()
	if s.preParamA != nil && s.preParamB != nil {
		a, b := s.preParamA, s.preParamB
		s.mu.Unlock()
		logFn("Cryptographic parameters ready (pre-computed).")
		return a, b, nil
	}
	s.mu.Unlock()

	logFn("Waiting for safe prime generation (started when wizard launched)...")
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	elapsed := 0
	for {
		select {
		case <-s.preParamReady:
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.preParamErr != nil {
				return nil, nil, s.preParamErr
			}
			logFn("Cryptographic parameters ready.")
			return s.preParamA, s.preParamB, nil
		case <-ticker.C:
			elapsed += 15
			logFn(fmt.Sprintf("Still generating safe primes... (%ds elapsed, typically takes 2-5 minutes)", elapsed))
		}
	}
}

// InjectPreParams sets pre-computed pre-params (used by tests to skip generation).
func (s *WizardState) InjectPreParams(a, b *keygen.LocalPreParams) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preParamA = a
	s.preParamB = b
	if s.preParamReady != nil {
		select {
		case <-s.preParamReady:
			// already closed
		default:
			close(s.preParamReady)
		}
	}
}

// AppendLog appends a log entry to the deploy logs.
func (s *WizardState) AppendLog(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DeployLogs = append(s.DeployLogs, msg)
}

// DrainLogs returns and clears all pending deploy log entries.
func (s *WizardState) DrainLogs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	logs := s.DeployLogs
	s.DeployLogs = nil
	return logs
}
