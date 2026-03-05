package main

import (
	"encoding/hex"
	"sync"

	"github.com/seeingred/crypto-claw/internal/tss"
)

// WizardState holds all configuration gathered during the installer wizard.
type WizardState struct {
	mu sync.Mutex

	// Current wizard step.
	Step string `json:"step"`

	// Server configuration for SSH deployment.
	ServerA   SSHConfig `json:"serverA"`
	ServerB   SSHConfig `json:"serverB"`
	LocalMode bool      `json:"localMode"` // localhost installation for testing

	// Generated TLS certificates (PEM-encoded).
	CACert []byte `json:"-"`
	CAKey  []byte `json:"-"`
	CertA  []byte `json:"-"`
	KeyA   []byte `json:"-"`
	CertB  []byte `json:"-"`
	KeyB   []byte `json:"-"`

	// DKG results.
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

	// Telegram configuration.
	TelegramBotToken string `json:"-"`
	TelegramUserID   int64  `json:"telegramUserId,omitempty"`

	// Deployment state.
	DeployLogs []string `json:"-"`
	DeployDone bool     `json:"deployDone"`

	// Party A configuration.
	PartyAAddr string `json:"partyAAddr,omitempty"` // e.g., "127.0.0.1:8080"
}

// SanitizedState returns a copy of the state safe for sending to the frontend
// (no secrets like keys, tokens, or SSH passwords).
func (s *WizardState) SanitizedState() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()

	return map[string]any{
		"step":      s.Step,
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
		"certsGenerated": len(s.CACert) > 0,
		"ecdsaPubKey":    s.ECDSAPubKey,
		"eddsaPubKey":    s.EdDSAPubKey,
		"dkgComplete":    s.ShareA != nil && s.ShareB != nil,
		"llmProvider":    s.LLMProvider,
		"llmModel":       s.LLMModel,
		"llmEndpoint":    s.LLMEndpoint,
		"llmConfigured":  s.LLMProvider != "",
		"telegramConfigured": s.TelegramBotToken != "",
		"telegramUserId":     s.TelegramUserID,
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
