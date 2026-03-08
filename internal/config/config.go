package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Config holds the complete configuration for both parties.
type Config struct {
	Party    string       `json:"party"` // "a" or "b"
	DataDir  string       `json:"dataDir"`
	Database DatabaseConfig `json:"database"`

	// Party A specific
	API       APIConfig       `json:"api,omitempty"`
	Transport TransportConfig `json:"transport"`

	// Party B specific
	Analyzer AnalyzerConfig `json:"analyzer,omitempty"`
	Telegram TelegramConfig `json:"telegram,omitempty"`
}

type DatabaseConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	DBName   string `json:"dbName"`
	SSLMode  string `json:"sslMode"`
}

func (d DatabaseConfig) DSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		d.User, d.Password, d.Host, d.Port, d.DBName, d.SSLMode)
}

type APIConfig struct {
	ListenAddr string `json:"listenAddr"` // e.g. "127.0.0.1:8080"
	WebDir     string `json:"webDir"`     // path to embedded web dashboard
}

type TransportConfig struct {
	// Party A uses these to connect to Party B
	RemoteAddr string `json:"remoteAddr,omitempty"` // Party B's address

	// Party B uses this to listen
	ListenAddr string `json:"listenAddr,omitempty"`

	// TLS settings
	CertFile   string `json:"certFile"`
	KeyFile    string `json:"keyFile"`
	CACertFile string `json:"caCertFile"` // Peer's CA cert for pinning
}

type AnalyzerConfig struct {
	LLM          LLMConfig         `json:"llm"`
	AutoMode     bool              `json:"autoMode"`              // true = auto-approve whitelisted addresses, false = manual approval for all
	DisableAI    bool              `json:"disableAI,omitempty"`   // true = no LLM, deterministic + whitelist only
	ExplorerAPIs map[string]string `json:"explorerApis,omitempty"` // chain -> API key
	Whitelist    []WhitelistSeed   `json:"whitelist,omitempty"`   // seed addresses to pre-populate
}

// WhitelistSeed is an address to seed into the whitelist on startup.
type WhitelistSeed struct {
	Address string `json:"address"`
	Label   string `json:"label,omitempty"`
}

type LLMConfig struct {
	Provider string `json:"provider"` // "openai", "anthropic", "local"
	APIKey   string `json:"apiKey,omitempty"`
	Endpoint string `json:"endpoint,omitempty"` // for local models
	Model    string `json:"model"`              // e.g. "gpt-4", "claude-sonnet-4-20250514"
}

type TelegramConfig struct {
	BotToken         string        `json:"botToken"`
	AuthorizedUserID int64         `json:"authorizedUserId"`
	EscalationTimeout time.Duration `json:"escalationTimeout"` // default reject after this
}

// Load reads config from a JSON file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.DataDir == "" {
		cfg.DataDir = filepath.Dir(path)
	}
	return &cfg, nil
}

// Save writes config to a JSON file.
func Save(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}
