package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/ssh"

	"github.com/seeingred/crypto-claw/internal/tss"
)

// registerAPIRoutes mounts all API endpoint handlers on the given mux under /api/.
func registerAPIRoutes(mux *http.ServeMux, state *WizardState) {
	mux.HandleFunc("POST /api/servers/test", handleServersTest(state))
	mux.HandleFunc("POST /api/servers/save", handleServersSave(state))
	mux.HandleFunc("POST /api/llm/save", handleLLMSave(state))
	mux.HandleFunc("POST /api/llm/test", handleLLMTest())
	mux.HandleFunc("POST /api/llm/skip", handleLLMSkip(state))
	mux.HandleFunc("POST /api/telegram/save", handleTelegramSave(state))
	mux.HandleFunc("POST /api/telegram/verify", handleTelegramVerify(state))
	mux.HandleFunc("POST /api/install/prepare", handleInstallPrepare(state))
	mux.HandleFunc("POST /api/install/restore", handleInstallRestore(state))
	mux.HandleFunc("POST /api/install/export", handleInstallExport(state))
	mux.HandleFunc("POST /api/install/sweep", handleSweepSOL(state))
	mux.HandleFunc("POST /api/install/sweep-token", handleSweepToken(state))
	mux.HandleFunc("POST /api/install/token-accounts", handleTokenAccounts(state))
	mux.HandleFunc("POST /api/deploy", handleDeploy(state))
	mux.HandleFunc("POST /api/update", handleUpdate(state))
	mux.HandleFunc("GET /api/deploy/logs", handleDeployLogs(state))
	mux.HandleFunc("GET /api/state", handleState(state))
	mux.HandleFunc("GET /api/preflight", handlePreflight(state))
	mux.HandleFunc("POST /api/localhost/setup", handleLocalhostSetup(state))
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// handleServersTest tests an SSH connection to a server.
func handleServersTest(state *WizardState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg SSHConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		if cfg.Host == "" {
			writeError(w, http.StatusBadRequest, "host is required")
			return
		}
		if cfg.User == "" {
			writeError(w, http.StatusBadRequest, "user is required")
			return
		}

		client, err := SSHConnect(cfg)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"success": false,
				"error":   err.Error(),
			})
			return
		}
		defer client.Close()

		// Run a quick command to verify connectivity.
		stdout, _, err := SSHRunCommand(client, "uname -a")
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"success": false,
				"error":   "connected but command failed: " + err.Error(),
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"success": true,
			"system":  stdout,
		})
	}
}

// handleServersSave saves the SSH server configurations for both parties.
func handleServersSave(state *WizardState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ServerA   SSHConfig `json:"serverA"`
			ServerB   SSHConfig `json:"serverB"`
			LocalMode bool      `json:"localMode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		state.mu.Lock()
		state.LocalMode = req.LocalMode
		if req.LocalMode {
			state.ServerA = SSHConfig{Host: "127.0.0.1", Port: 22, User: "local"}
			state.ServerB = SSHConfig{Host: "127.0.0.1", Port: 22, User: "local"}
			state.PartyAAddr = "127.0.0.1:8080"
		} else {
			state.ServerA = req.ServerA
			state.ServerB = req.ServerB
		}
		state.Step = "servers"
		state.mu.Unlock()

		if req.LocalMode {
			slog.Info("localhost mode enabled")
		} else {
			slog.Info("server configs saved",
				"serverA", req.ServerA.Host,
				"serverB", req.ServerB.Host,
			)
		}

		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// handleInstallPrepare generates a BIP-39 mnemonic and derives keys.
// This is fast (<1s) and returns the mnemonic for the user to back up
// before proceeding with deployment.
func handleInstallPrepare(state *WizardState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		keys, err := GenerateMnemonicKeys()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "generate keys: "+err.Error())
			return
		}

		state.mu.Lock()
		state.Mnemonic = keys.Mnemonic
		state.ECDSAPubKey = hex.EncodeToString(keys.ECDSAPubKey)
		state.EdDSAPubKey = hex.EncodeToString(keys.EdDSAPubKey)
		state.Step = "prepared"
		state.Mode = "install"
		state.mu.Unlock()

		slog.Info("mnemonic generated, keys derived",
			"ecdsaPub", state.ECDSAPubKey[:16]+"...",
			"eddsaPub", state.EdDSAPubKey[:16]+"...",
		)

		writeJSON(w, http.StatusOK, map[string]any{
			"status":      "ok",
			"mnemonic":    keys.Mnemonic,
			"ecdsaPubKey": state.ECDSAPubKey,
			"eddsaPubKey": state.EdDSAPubKey,
		})
	}
}

// handleInstallRestore restores keys from an existing BIP-39 mnemonic.
func handleInstallRestore(state *WizardState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Mnemonic string `json:"mnemonic"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		req.Mnemonic = strings.TrimSpace(req.Mnemonic)
		if req.Mnemonic == "" {
			writeError(w, http.StatusBadRequest, "mnemonic is required")
			return
		}

		keys, err := DeriveKeysFromMnemonic(req.Mnemonic)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid mnemonic: "+err.Error())
			return
		}

		state.mu.Lock()
		state.Mnemonic = keys.Mnemonic
		state.ECDSAPubKey = hex.EncodeToString(keys.ECDSAPubKey)
		state.EdDSAPubKey = hex.EncodeToString(keys.EdDSAPubKey)
		state.Step = "prepared"
		state.Mode = "restore"
		state.mu.Unlock()

		slog.Info("wallet restored from mnemonic",
			"ecdsaPub", state.ECDSAPubKey[:16]+"...",
			"eddsaPub", state.EdDSAPubKey[:16]+"...",
		)

		writeJSON(w, http.StatusOK, map[string]any{
			"status":      "ok",
			"ecdsaPubKey": state.ECDSAPubKey,
			"eddsaPubKey": state.EdDSAPubKey,
		})
	}
}

// exportKeyReq describes a single key to export, with optional bech32 prefix for Cosmos app chains.
type exportKeyReq struct {
	Path   string `json:"path"`             // e.g. "m/44'/118'/0'/0/0"
	Prefix string `json:"prefix,omitempty"` // bech32 prefix, e.g. "osmo", "cosmos", "juno"
}

// handleInstallExport accepts a mnemonic and optional derivation paths.
// It derives the exact private keys that TSS would have produced, allowing
// disaster recovery: mnemonic + paths → private keys → import into wallet → move funds.
// Supports two input formats:
//   - "paths": ["m/44'/60'/0'/0/0"] — simple string array (EVM/Solana auto-detected)
//   - "keys": [{"path":"m/44'/118'/0'/0/0","prefix":"osmo"}] — with bech32 prefix for Cosmos app chains
func handleInstallExport(state *WizardState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Mnemonic string        `json:"mnemonic"`
			Paths    []string      `json:"paths"`    // simple: ["m/44'/60'/0'/0/0"]
			Keys     []exportKeyReq `json:"keys"`     // rich: [{"path":"m/44'/118'/0'/0/0","prefix":"osmo"}]
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		req.Mnemonic = strings.TrimSpace(req.Mnemonic)
		if req.Mnemonic == "" {
			writeError(w, http.StatusBadRequest, "mnemonic is required")
			return
		}

		// Validate mnemonic by deriving master keys.
		keys, err := DeriveKeysFromMnemonic(req.Mnemonic)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid mnemonic: "+err.Error())
			return
		}

		// Solana key (TSS doesn't derive EdDSA, so there's only one SOL address).
		solPriv, solAddr, err := ExportSolanaKey(req.Mnemonic)
		if err != nil {
			writeError(w, http.StatusBadRequest, "derive Solana key: "+err.Error())
			return
		}

		// List derived paths from DB (returned to frontend for user to choose).
		dbAddrs := listDerivedAddressesFromDB()

		// Merge both input formats into a unified list.
		exportReqs := make([]exportKeyReq, 0, len(req.Paths)+len(req.Keys))
		for _, p := range req.Paths {
			exportReqs = append(exportReqs, exportKeyReq{Path: p})
		}
		exportReqs = append(exportReqs, req.Keys...)

		// Derive each requested path using TSS-compatible derivation.
		var derivedKeys []map[string]string
		for _, kr := range exportReqs {
			path := kr.Path
			prefix := kr.Prefix
			coinType := extractCoinTypeFromPath(path)

			if coinType == "501" {
				// Solana / ed25519 — use SLIP-0010 derivation.
				exported, err := ExportSolanaKeyAtPath(req.Mnemonic, path)
				if err != nil {
					slog.Warn("export: failed to derive SOL path", "path", path, "error", err)
					derivedKeys = append(derivedKeys, map[string]string{
						"path":  path,
						"curve": "ed25519",
						"error": err.Error(),
					})
					continue
				}
				derivedKeys = append(derivedKeys, map[string]string{
					"path":       exported.Path,
					"curve":      "ed25519",
					"privKeyHex": exported.PrivKeyHex,
					"address":    exported.Address,
				})
			} else if prefix != "" {
				// Cosmos app chain — secp256k1 with bech32 prefix.
				exported, err := DeriveECDSAKeyTSS(req.Mnemonic, path, prefix)
				if err != nil {
					slog.Warn("export: failed to derive Cosmos path", "path", path, "prefix", prefix, "error", err)
					derivedKeys = append(derivedKeys, map[string]string{
						"path":  path,
						"curve": "secp256k1",
						"error": err.Error(),
					})
					continue
				}
				derivedKeys = append(derivedKeys, map[string]string{
					"path":       exported.Path,
					"curve":      "secp256k1",
					"privKeyHex": exported.PrivKeyHex,
					"address":    exported.Address,
				})
			} else if coinType == "118" {
				// Cosmos Hub (no prefix specified) — default to "cosmos".
				exported, err := DeriveECDSAKeyTSS(req.Mnemonic, path, "cosmos")
				if err != nil {
					slog.Warn("export: failed to derive Cosmos path", "path", path, "error", err)
					derivedKeys = append(derivedKeys, map[string]string{
						"path":  path,
						"curve": "secp256k1",
						"error": err.Error(),
					})
					continue
				}
				derivedKeys = append(derivedKeys, map[string]string{
					"path":       exported.Path,
					"curve":      "secp256k1",
					"privKeyHex": exported.PrivKeyHex,
					"address":    exported.Address,
				})
			} else {
				// EVM / secp256k1.
				exported, err := DeriveECDSAKeyTSS(req.Mnemonic, path)
				if err != nil {
					slog.Warn("export: failed to derive path", "path", path, "error", err)
					derivedKeys = append(derivedKeys, map[string]string{
						"path":  path,
						"curve": "secp256k1",
						"error": err.Error(),
					})
					continue
				}
				derivedKeys = append(derivedKeys, map[string]string{
					"path":       exported.Path,
					"curve":      "secp256k1",
					"privKeyHex": exported.PrivKeyHex,
					"address":    exported.Address,
				})
			}
		}

		slog.Info("wallet keys exported",
			"ecdsaMaster", hex.EncodeToString(keys.ECDSAPubKey[:8])+"...",
			"solAddress", solAddr,
			"derivedPaths", len(derivedKeys),
		)

		writeJSON(w, http.StatusOK, map[string]any{
			"status":          "ok",
			"solPrivKey":      solPriv,
			"solAddress":      solAddr,
			"derivedKeys":     derivedKeys,
			"dbAddresses":     dbAddrs,
		})
	}
}

// listDerivedAddressesFromDB tries to connect to the local postgres and list derived keys.
// Returns nil if DB is not available (best effort).
func listDerivedAddressesFromDB() []map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	connStr := "host=127.0.0.1 port=5432 user=crypto_claw password=crypto_claw dbname=crypto_claw_a sslmode=disable"
	conn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		slog.Debug("export: could not connect to local DB", "error", err)
		return nil
	}
	defer conn.Close(ctx)

	rows, err := conn.Query(ctx, "SELECT derivation_path, curve, address FROM derived_keys ORDER BY created_at")
	if err != nil {
		slog.Debug("export: could not query derived_keys", "error", err)
		return nil
	}
	defer rows.Close()

	var result []map[string]string
	for rows.Next() {
		var path, curve, address string
		if err := rows.Scan(&path, &curve, &address); err != nil {
			continue
		}
		result = append(result, map[string]string{
			"path":    path,
			"curve":   curve,
			"address": address,
		})
	}
	return result
}

// handleSweepSOL sweeps all SOL from a TSS-derived Solana address to a destination.
// TSS-derived ed25519 keys can't be exported as standard ed25519 keypairs (wallets
// do SHA-512(seed) internally which is irreversible), so we sign directly with the
// raw scalar and broadcast the transaction.
func handleSweepSOL(state *WizardState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Mnemonic    string `json:"mnemonic"`
			Path        string `json:"path"`
			Destination string `json:"destination"`
			RpcURL      string `json:"rpcUrl"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		req.Mnemonic = strings.TrimSpace(req.Mnemonic)
		if req.Mnemonic == "" || req.Path == "" || req.Destination == "" || req.RpcURL == "" {
			writeError(w, http.StatusBadRequest, "mnemonic, path, destination, and rpcUrl are required")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		txid, err := sweepSOL(ctx, req.Mnemonic, req.Path, req.Destination, req.RpcURL)
		if err != nil {
			slog.Error("sweep failed", "path", req.Path, "error", err)
			writeError(w, http.StatusInternalServerError, "sweep failed: "+err.Error())
			return
		}

		slog.Info("SOL sweep successful", "path", req.Path, "txid", txid)
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "ok",
			"txid":   txid,
		})
	}
}

// handleSweepToken sweeps all of an SPL token from a TSS-derived Solana address.
func handleSweepToken(state *WizardState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Mnemonic    string `json:"mnemonic"`
			Path        string `json:"path"`
			Destination string `json:"destination"`
			Mint        string `json:"mint"`
			RpcURL      string `json:"rpcUrl"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		req.Mnemonic = strings.TrimSpace(req.Mnemonic)
		if req.Mnemonic == "" || req.Path == "" || req.Destination == "" || req.Mint == "" || req.RpcURL == "" {
			writeError(w, http.StatusBadRequest, "mnemonic, path, destination, mint, and rpcUrl are required")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		txid, err := sweepSPLToken(ctx, req.Mnemonic, req.Path, req.Destination, req.Mint, req.RpcURL)
		if err != nil {
			slog.Error("token sweep failed", "path", req.Path, "mint", req.Mint, "error", err)
			writeError(w, http.StatusInternalServerError, "token sweep failed: "+err.Error())
			return
		}

		slog.Info("token sweep successful", "path", req.Path, "mint", req.Mint, "txid", txid)
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "ok",
			"txid":   txid,
		})
	}
}

// handleTokenAccounts fetches all SPL token accounts for a derived Solana address.
func handleTokenAccounts(state *WizardState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Address string `json:"address"`
			RpcURL  string `json:"rpcUrl"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		if req.Address == "" || req.RpcURL == "" {
			writeError(w, http.StatusBadRequest, "address and rpcUrl are required")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		accounts, err := getTokenAccounts(ctx, req.RpcURL, req.Address)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to fetch token accounts: "+err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "ok",
			"accounts": accounts,
		})
	}
}

// handleLLMSave saves the LLM provider configuration.
func handleLLMSave(state *WizardState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Provider string `json:"provider"`
			APIKey   string `json:"apiKey"`
			Model    string `json:"model"`
			Endpoint string `json:"endpoint"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		if req.Provider == "" {
			writeError(w, http.StatusBadRequest, "provider is required")
			return
		}

		// Auto-detect provider from API key format if there's a mismatch.
		if req.APIKey != "" {
			detected := detectLLMProvider(req.APIKey)
			if detected != "" && detected != req.Provider {
				slog.Warn("API key format doesn't match selected provider, auto-correcting",
					"selected", req.Provider, "detected", detected)
				req.Provider = detected
			}
		}

		state.mu.Lock()
		state.LLMProvider = req.Provider
		state.LLMAPIKey = req.APIKey
		state.LLMModel = req.Model
		// Only save custom endpoint for local provider — cloud providers
		// use their default URLs and a stale endpoint would break them.
		if req.Provider == "local" {
			state.LLMEndpoint = req.Endpoint
		} else {
			state.LLMEndpoint = ""
		}
		state.Step = "llm"
		state.mu.Unlock()

		slog.Info("LLM config saved", "provider", req.Provider, "model", req.Model)

		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// handleLLMSkip skips LLM setup — Party B will use deterministic checks + whitelist only.
func handleLLMSkip(state *WizardState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		state.LLMProvider = ""
		state.LLMAPIKey = ""
		state.LLMModel = ""
		state.LLMEndpoint = ""
		state.DisableAI = true
		state.Step = "llm"
		state.mu.Unlock()

		slog.Info("LLM setup skipped — AI disabled, deterministic + whitelist mode")

		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// handleLLMTest sends a minimal request to the LLM provider to verify the API key works.
func handleLLMTest() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Provider string `json:"provider"`
			APIKey   string `json:"apiKey"`
			Model    string `json:"model"`
			Endpoint string `json:"endpoint"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		if req.Provider == "" {
			writeError(w, http.StatusBadRequest, "provider is required")
			return
		}
		if req.Provider != "local" && req.APIKey == "" {
			writeError(w, http.StatusBadRequest, "API key is required")
			return
		}

		// Auto-detect provider mismatch.
		detected := detectLLMProvider(req.APIKey)
		if detected != "" && detected != req.Provider {
			writeError(w, http.StatusBadRequest, fmt.Sprintf(
				"API key looks like %s but you selected %s", detected, req.Provider))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		var testErr error
		switch req.Provider {
		case "anthropic":
			testErr = testAnthropicKey(ctx, req.APIKey, req.Model)
		case "openai":
			testErr = testOpenAIKey(ctx, req.APIKey, req.Model)
		case "local":
			testErr = testLocalEndpoint(ctx, req.Endpoint, req.Model)
		default:
			writeError(w, http.StatusBadRequest, "unknown provider: "+req.Provider)
			return
		}

		if testErr != nil {
			slog.Warn("LLM test failed", "provider", req.Provider, "err", testErr)
			writeJSON(w, http.StatusOK, map[string]any{
				"success": false,
				"error":   testErr.Error(),
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	}
}

// testAnthropicKey sends a minimal messages request to the Anthropic API.
func testAnthropicKey(ctx context.Context, apiKey, model string) error {
	if model == "" {
		model = "claude-haiku-4-5-20251001"
	}
	body := fmt.Sprintf(`{"model":"%s","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`, model)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.anthropic.com/v1/messages", strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return fmt.Errorf("invalid API key (401 Unauthorized)")
	}
	if resp.StatusCode == 403 {
		return fmt.Errorf("API key lacks permission (403 Forbidden)")
	}
	if resp.StatusCode >= 400 {
		var errResp struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error.Message != "" {
			return fmt.Errorf("%s", errResp.Error.Message)
		}
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}
	return nil
}

// testOpenAIKey sends a minimal chat completion request to the OpenAI API.
func testOpenAIKey(ctx context.Context, apiKey, model string) error {
	if model == "" {
		model = "gpt-4o-mini"
	}
	body := fmt.Sprintf(`{"model":"%s","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`, model)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return fmt.Errorf("invalid API key (401 Unauthorized)")
	}
	if resp.StatusCode == 403 {
		return fmt.Errorf("API key lacks permission (403 Forbidden)")
	}
	if resp.StatusCode >= 400 {
		var errResp struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error.Message != "" {
			return fmt.Errorf("%s", errResp.Error.Message)
		}
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}
	return nil
}

// testLocalEndpoint tests a local LLM endpoint by trying Ollama's native API first,
// then falling back to the OpenAI-compatible endpoint.
func testLocalEndpoint(ctx context.Context, endpoint, model string) error {
	if endpoint == "" {
		return fmt.Errorf("endpoint URL is required")
	}
	if model == "" {
		model = "default"
	}
	base := strings.TrimRight(endpoint, "/")

	// Try Ollama native API first (/api/chat).
	ollamaURL := base + "/api/chat"
	ollamaBody := fmt.Sprintf(`{"model":"%s","messages":[{"role":"user","content":"ping"}],"stream":false}`, model)
	if err := tryLocalRequest(ctx, ollamaURL, ollamaBody); err == nil {
		return nil
	}

	// Fall back to OpenAI-compatible endpoint (/v1/chat/completions).
	openaiURL := base + "/v1/chat/completions"
	openaiBody := fmt.Sprintf(`{"model":"%s","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`, model)
	if err := tryLocalRequest(ctx, openaiURL, openaiBody); err != nil {
		return fmt.Errorf("endpoint not reachable (tried %s/api/chat and %s/v1/chat/completions): %w", base, base, err)
	}
	return nil
}

func tryLocalRequest(ctx context.Context, url, body string) error {
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// handleTelegramSave validates the Telegram bot token via getMe and saves it.
func handleTelegramSave(state *WizardState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			BotToken string `json:"botToken"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		if req.BotToken == "" {
			writeError(w, http.StatusBadRequest, "botToken is required")
			return
		}

		// Validate token by calling getMe.
		bot, err := tgbotapi.NewBotAPI(req.BotToken)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"status": "error",
				"error":  "Invalid bot token: " + err.Error(),
			})
			return
		}

		state.mu.Lock()
		state.TelegramBotToken = req.BotToken
		state.TelegramBotUsername = bot.Self.UserName
		state.Step = "telegram"
		state.mu.Unlock()

		slog.Info("Telegram bot token validated", "bot", bot.Self.UserName)

		writeJSON(w, http.StatusOK, map[string]any{
			"status":      "ok",
			"botUsername": bot.Self.UserName,
		})
	}
}

// handleTelegramVerify waits for the user to send /start to the bot and captures their user ID.
func handleTelegramVerify(state *WizardState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		token := state.TelegramBotToken
		state.mu.Unlock()

		if token == "" {
			writeError(w, http.StatusBadRequest, "save bot token first")
			return
		}

		bot, err := tgbotapi.NewBotAPI(token)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "bot init: "+err.Error())
			return
		}

		// Clear any old updates.
		u := tgbotapi.NewUpdate(-1)
		u.Timeout = 1
		bot.GetUpdates(u)

		// Poll for a message (up to 60s).
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		u = tgbotapi.NewUpdate(0)
		u.Timeout = 5

		for {
			select {
			case <-ctx.Done():
				writeJSON(w, http.StatusOK, map[string]any{
					"status": "timeout",
					"error":  "No message received within 60 seconds. Please send /start to the bot and try again.",
				})
				return
			default:
			}

			updates, err := bot.GetUpdates(u)
			if err != nil {
				continue
			}

			for _, update := range updates {
				u.Offset = update.UpdateID + 1

				if update.Message == nil {
					continue
				}

				userID := update.Message.From.ID
				userName := update.Message.From.UserName
				if userName == "" {
					userName = update.Message.From.FirstName
				}

				state.mu.Lock()
				state.TelegramUserID = userID
				state.mu.Unlock()

				// Send confirmation message.
				msg := tgbotapi.NewMessage(update.Message.Chat.ID,
					fmt.Sprintf("✅ Connected! Welcome %s. Crypto Claw will send notifications to this chat.", userName))
				bot.Send(msg)

				slog.Info("Telegram user verified", "userID", userID, "username", userName)

				writeJSON(w, http.StatusOK, map[string]any{
					"status":   "ok",
					"userId":   userID,
					"username": userName,
				})
				return
			}
		}
	}
}

func handleDeploy(state *WizardState) http.HandlerFunc {
	var deploying sync.Mutex

	return func(w http.ResponseWriter, r *http.Request) {
		if !deploying.TryLock() {
			writeError(w, http.StatusConflict, "deployment already in progress")
			return
		}

		state.mu.Lock()
		mnemonic := state.Mnemonic
		state.DeployDone = false
		state.DeployFailed = false
		state.DeployLogs = nil
		state.Step = "deploying"
		localMode := state.LocalMode
		state.mu.Unlock()

		if mnemonic == "" {
			deploying.Unlock()
			writeError(w, http.StatusBadRequest, "call /api/install/prepare first")
			return
		}

		logFn := func(msg string) {
			slog.Info(msg)
			state.AppendLog(msg)
		}

		// Run the full installation pipeline in background.
		go func() {
			defer deploying.Unlock()
			failed := false

			fail := func(msg string) {
				logFn(msg)
				failed = true
			}

			// Phase 1: Derive keys from mnemonic.
			logFn("Deriving keys from mnemonic...")
			keys, err := DeriveKeysFromMnemonic(mnemonic)
			if err != nil {
				fail(fmt.Sprintf("ERROR: derive keys: %v", err))
				state.mu.Lock()
				state.DeployDone = true
				state.DeployFailed = true
				state.mu.Unlock()
				return
			}

			partyA := tss.PartyID{ID: "party-a", Index: 0}
			partyB := tss.PartyID{ID: "party-b", Index: 1}
			parties := []tss.PartyID{partyA, partyB}

			// Phase 2: Wait for pre-computed ECDSA safe primes (generated in background since startup).
			ppA, ppB, ppErr := state.WaitPreParams(logFn)
			if ppErr != nil {
				fail(fmt.Sprintf("ERROR: generate pre-params: %v", ppErr))
				state.mu.Lock()
				state.DeployDone = true
				state.DeployFailed = true
				state.mu.Unlock()
				return
			}
			logFn("Cryptographic parameters ready.")

			// Phase 3: Trusted dealer key splitting.
			logFn("Splitting ECDSA key into threshold shares...")
			ecdsaShares, err := tss.DealerSetupECDSA(
				keys.ECDSAPrivKey, keys.ECDSAPubKey, keys.ECDSAChainCode,
				parties, []*keygen.LocalPreParams{ppA, ppB},
			)
			if err != nil {
				fail(fmt.Sprintf("ERROR: ECDSA dealer setup: %v", err))
				state.mu.Lock()
				state.DeployDone = true
				state.DeployFailed = true
				state.mu.Unlock()
				return
			}

			logFn("Splitting EdDSA key into threshold shares...")
			eddsaShares, err := tss.DealerSetupEdDSA(
				keys.EdDSAPrivKey, keys.EdDSAPubKey, keys.EdDSAChainCode,
				parties,
			)
			if err != nil {
				fail(fmt.Sprintf("ERROR: EdDSA dealer setup: %v", err))
				state.mu.Lock()
				state.DeployDone = true
				state.DeployFailed = true
				state.mu.Unlock()
				return
			}

			state.SetECDSAKeys(ecdsaShares[0], ecdsaShares[1])
			state.SetEdDSAKeys(eddsaShares[0], eddsaShares[1])
			logFn("Key shares generated.")

			// Phase 4: Generate TLS certificates.
			logFn("Generating TLS certificates...")
			state.mu.Lock()
			hostsA := []string{state.ServerA.Host}
			hostsB := []string{state.ServerB.Host}
			state.mu.Unlock()

			// In local Docker mode, containers resolve each other via host.docker.internal.
			if localMode {
				hostsA = append(hostsA, "host.docker.internal")
				hostsB = append(hostsB, "host.docker.internal")
			}

			bundle, err := GenerateCerts(hostsA, hostsB)
			if err != nil {
				fail(fmt.Sprintf("ERROR: generate certs: %v", err))
				state.mu.Lock()
				state.DeployDone = true
				state.DeployFailed = true
				state.mu.Unlock()
				return
			}

			state.mu.Lock()
			state.CACert = bundle.CACert
			state.CAKey = bundle.CAKey
			state.CertA = bundle.CertA
			state.KeyA = bundle.KeyA
			state.CertB = bundle.CertB
			state.KeyB = bundle.KeyB
			state.mu.Unlock()
			logFn("TLS certificates generated.")

			// Phase 5: Deploy to servers.
			if localMode {
				logFn("Starting local deployment...")
				if err := DeployLocal(state, logFn); err != nil {
					fail(fmt.Sprintf("ERROR: local deploy failed: %v", err))
				}
			} else {
				logFn("Starting remote deployment...")
				if err := deployRemote(state, logFn); err != nil {
					fail(fmt.Sprintf("ERROR: %v", err))
				}
			}

			state.mu.Lock()
			state.DeployDone = true
			state.DeployFailed = failed
			if !failed {
				state.Step = "done"
			} else {
				state.Step = "deploying" // stay on install step
			}
			state.mu.Unlock()

			// Log AFTER releasing the lock to avoid deadlock (logFn -> AppendLog -> state.mu.Lock).
			if !failed {
				logFn("Deployment finished successfully.")
			} else {
				logFn("Deployment finished with errors.")
			}
		}()

		writeJSON(w, http.StatusOK, map[string]string{"status": "started"})
	}
}

// handleUpdate redeploys code without regenerating keys, certs, or config.
// It reuses the existing installation and only restarts processes.
func handleUpdate(state *WizardState) http.HandlerFunc {
	var updating sync.Mutex

	return func(w http.ResponseWriter, r *http.Request) {
		if !updating.TryLock() {
			writeError(w, http.StatusConflict, "update already in progress")
			return
		}

		state.mu.Lock()
		state.DeployDone = false
		state.DeployFailed = false
		state.DeployLogs = nil
		state.Mode = "update"
		state.Step = "deploying"
		localMode := state.LocalMode
		state.mu.Unlock()

		logFn := func(msg string) {
			slog.Info(msg)
			state.AppendLog(msg)
		}

		go func() {
			defer updating.Unlock()
			failed := false

			fail := func(msg string) {
				logFn(msg)
				failed = true
			}

			if localMode {
				logFn("Starting local update (code only)...")
				if err := UpdateLocal(logFn); err != nil {
					fail(fmt.Sprintf("ERROR: local update failed: %v", err))
				}
			} else {
				fail("ERROR: remote update not yet implemented — use deploy for remote servers")
			}

			state.mu.Lock()
			state.DeployDone = true
			state.DeployFailed = failed
			if !failed {
				state.Step = "done"
			} else {
				state.Step = "deploying"
			}
			state.mu.Unlock()

			if !failed {
				logFn("Update finished successfully.")
			} else {
				logFn("Update finished with errors.")
			}
		}()

		writeJSON(w, http.StatusOK, map[string]string{"status": "started"})
	}
}

// deployRemote deploys both parties to their respective remote servers.
func deployRemote(state *WizardState, logFn func(string)) error {
	state.mu.Lock()
	serverA := state.ServerA
	serverB := state.ServerB
	certA := state.CertA
	keyA := state.KeyA
	certB := state.CertB
	keyB := state.KeyB
	caCert := state.CACert
	state.mu.Unlock()

	var wg sync.WaitGroup
	var errA, errB error

	// Deploy Party B first (it needs to be listening before Party A connects).
	logFn("Deploying Party B...")
	clientB, err := SSHConnect(serverB)
	if err != nil {
		logFn(fmt.Sprintf("ERROR: SSH connect to Party B (%s): %v", serverB.Host, err))
		return fmt.Errorf("SSH connect to Party B (%s): %w", serverB.Host, err)
	}
	defer clientB.Close()

	certDirB := "/etc/crypto-claw"
	cfgB := buildPartyConfig(state, "b", certDirB)
	if err := DeployParty(clientB, "b", cfgB, certB, keyB, caCert, logFn); err != nil {
		logFn(fmt.Sprintf("ERROR: deploy Party B: %v", err))
		return fmt.Errorf("deploy Party B: %w", err)
	}

	// Deploy Party A.
	logFn("Deploying Party A...")
	clientA, err := SSHConnect(serverA)
	if err != nil {
		logFn(fmt.Sprintf("ERROR: SSH connect to Party A (%s): %v", serverA.Host, err))
		return fmt.Errorf("SSH connect to Party A (%s): %w", serverA.Host, err)
	}
	defer clientA.Close()

	certDirA := "/etc/crypto-claw"
	cfgA := buildPartyConfig(state, "a", certDirA)
	if err := DeployParty(clientA, "a", cfgA, certA, keyA, caCert, logFn); err != nil {
		logFn(fmt.Sprintf("ERROR: deploy Party A: %v", err))
		return fmt.Errorf("deploy Party A: %w", err)
	}

	// Upload key shares to both servers.
	logFn("Uploading key shares...")
	wg.Add(2)
	go func() {
		defer wg.Done()
		errA = uploadKeyShares(clientA, state, "a")
	}()
	go func() {
		defer wg.Done()
		errB = uploadKeyShares(clientB, state, "b")
	}()
	wg.Wait()

	if errA != nil {
		logFn(fmt.Sprintf("ERROR: upload key shares to Party A: %v", errA))
		return errA
	}
	if errB != nil {
		logFn(fmt.Sprintf("ERROR: upload key shares to Party B: %v", errB))
		return errB
	}

	logFn("Remote deployment complete.")
	return nil
}

// uploadKeyShares uploads serialized key shares to a remote server.
func uploadKeyShares(client *ssh.Client, state *WizardState, party string) error {
	state.mu.Lock()
	var ecdsaShare, eddsaShare *tss.KeyShare
	if party == "a" {
		ecdsaShare = state.ShareA
		eddsaShare = state.EdShareA
	} else {
		ecdsaShare = state.ShareB
		eddsaShare = state.EdShareB
	}
	state.mu.Unlock()

	if ecdsaShare != nil {
		data, err := json.Marshal(ecdsaShare)
		if err != nil {
			return fmt.Errorf("marshal ECDSA share: %w", err)
		}
		if err := SSHUploadFile(client, data, filepath.Join(remoteConfigDir, "ecdsa_share.json")); err != nil {
			return fmt.Errorf("upload ECDSA share: %w", err)
		}
	}

	if eddsaShare != nil {
		data, err := json.Marshal(eddsaShare)
		if err != nil {
			return fmt.Errorf("marshal EdDSA share: %w", err)
		}
		if err := SSHUploadFile(client, data, filepath.Join(remoteConfigDir, "eddsa_share.json")); err != nil {
			return fmt.Errorf("upload EdDSA share: %w", err)
		}
	}

	return nil
}

// handleDeployLogs streams deployment logs via Server-Sent Events.
func handleDeployLogs(state *WizardState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			writeError(w, http.StatusInternalServerError, "streaming not supported")
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		// Flush headers immediately so the browser's EventSource connects.
		fmt.Fprintf(w, ": connected\n\n")
		flusher.Flush()

		ctx := r.Context()
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				logs := state.DrainLogs()
				for _, log := range logs {
					evt, _ := json.Marshal(map[string]string{"type": "log", "message": log})
					fmt.Fprintf(w, "data: %s\n\n", evt)
				}
				if len(logs) > 0 {
					flusher.Flush()
				}

				state.mu.Lock()
				done := state.DeployDone
				failed := state.DeployFailed
				state.mu.Unlock()

				if done && len(logs) == 0 {
					if failed {
						evt, _ := json.Marshal(map[string]string{"type": "error", "message": "Deployment failed. Check the logs above for details."})
						fmt.Fprintf(w, "data: %s\n\n", evt)
					} else {
						evt, _ := json.Marshal(map[string]string{"type": "complete", "message": "deployment complete"})
						fmt.Fprintf(w, "data: %s\n\n", evt)
					}
					flusher.Flush()
					return
				}
			}
		}
	}
}

// handleState returns the current sanitized wizard state.
func handleState(state *WizardState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, state.SanitizedState())
	}
}

// handlePreflight checks prerequisites before deployment (Docker, Postgres, etc.).
func handlePreflight(state *WizardState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		localMode := state.LocalMode
		state.mu.Unlock()

		checks := make(map[string]any)

		if localMode {
			// Check Docker — only hard requirement. Postgres is auto-deployed in Docker if needed.
			dockerOk := false
			dockerErr := ""
			out, err := exec.Command("docker", "info").CombinedOutput()
			if err != nil {
				if strings.Contains(string(out), "Cannot connect") || strings.Contains(string(out), "no such file") || strings.Contains(err.Error(), "executable file not found") {
					dockerErr = "Docker is not running. Please start Docker Desktop."
				} else {
					dockerErr = "Docker check failed: " + strings.TrimSpace(string(out))
				}
			} else {
				dockerOk = true
			}
			checks["docker"] = map[string]any{"ok": dockerOk, "error": dockerErr}
		}

		allOk := true
		for _, v := range checks {
			if m, ok := v.(map[string]any); ok && !m["ok"].(bool) {
				allOk = false
				break
			}
		}
		checks["ready"] = allOk

		writeJSON(w, http.StatusOK, checks)
	}
}

// handleLocalhostSetup configures the wizard for local mode (no SSH needed).
func handleLocalhostSetup(state *WizardState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PartyAAddr string `json:"partyAAddr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			// No body is fine; use defaults.
			req.PartyAAddr = "127.0.0.1:8080"
		}
		if req.PartyAAddr == "" {
			req.PartyAAddr = "127.0.0.1:8080"
		}

		state.mu.Lock()
		state.LocalMode = true
		state.PartyAAddr = req.PartyAAddr
		state.ServerA = SSHConfig{Host: "127.0.0.1", Port: 22, User: "local"}
		state.ServerB = SSHConfig{Host: "127.0.0.1", Port: 22, User: "local"}
		state.Step = "servers"
		state.mu.Unlock()

		slog.Info("localhost mode enabled", "partyAAddr", req.PartyAAddr)

		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// extractCoinTypeFromPath returns the coin type from a BIP-44 path (e.g. "60" from "m/44'/60'/0'/0/0").
func extractCoinTypeFromPath(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "m/"), "/")
	if len(parts) < 2 {
		return ""
	}
	ct := parts[1]
	ct = strings.TrimRight(ct, "'hH")
	return ct
}

// detectLLMProvider guesses the provider from the API key format.
func detectLLMProvider(apiKey string) string {
	switch {
	case strings.HasPrefix(apiKey, "sk-ant-"):
		return "anthropic"
	case strings.HasPrefix(apiKey, "sk-proj-") || strings.HasPrefix(apiKey, "sk-or-"):
		return "openai"
	default:
		return "" // unknown — trust user selection
	}
}
