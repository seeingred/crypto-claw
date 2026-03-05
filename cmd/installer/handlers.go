package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"golang.org/x/crypto/ssh"

	"github.com/seeingred/crypto-claw/internal/tss"
)

// registerAPIRoutes mounts all API endpoint handlers on the given mux under /api/.
func registerAPIRoutes(mux *http.ServeMux, state *WizardState) {
	mux.HandleFunc("POST /api/servers/test", handleServersTest(state))
	mux.HandleFunc("POST /api/servers/save", handleServersSave(state))
	mux.HandleFunc("POST /api/certs/generate", handleCertsGenerate(state))
	mux.HandleFunc("POST /api/dkg/run", handleDKGRun(state))
	mux.HandleFunc("POST /api/llm/save", handleLLMSave(state))
	mux.HandleFunc("POST /api/telegram/save", handleTelegramSave(state))
	mux.HandleFunc("POST /api/telegram/verify", handleTelegramVerify(state))
	mux.HandleFunc("POST /api/deploy", handleDeploy(state))
	mux.HandleFunc("GET /api/deploy/logs", handleDeployLogs(state))
	mux.HandleFunc("GET /api/state", handleState(state))
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
			ServerA SSHConfig `json:"serverA"`
			ServerB SSHConfig `json:"serverB"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		state.mu.Lock()
		state.ServerA = req.ServerA
		state.ServerB = req.ServerB
		state.Step = "servers"
		state.mu.Unlock()

		slog.Info("server configs saved",
			"serverA", req.ServerA.Host,
			"serverB", req.ServerB.Host,
		)

		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// handleCertsGenerate generates TLS CA + party certificates.
func handleCertsGenerate(state *WizardState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		hostsA := []string{state.ServerA.Host}
		hostsB := []string{state.ServerB.Host}
		state.mu.Unlock()

		bundle, err := GenerateCerts(hostsA, hostsB)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "generate certs: "+err.Error())
			return
		}

		state.mu.Lock()
		state.CACert = bundle.CACert
		state.CAKey = bundle.CAKey
		state.CertA = bundle.CertA
		state.KeyA = bundle.KeyA
		state.CertB = bundle.CertB
		state.KeyB = bundle.KeyB
		state.Step = "certs"
		state.mu.Unlock()

		slog.Info("TLS certificates generated")

		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// handleDKGRun runs the DKG ceremony for both ECDSA and EdDSA.
func handleDKGRun(state *WizardState) http.HandlerFunc {
	var running sync.Mutex

	return func(w http.ResponseWriter, r *http.Request) {
		if !running.TryLock() {
			writeError(w, http.StatusConflict, "DKG is already running")
			return
		}
		defer running.Unlock()

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
		defer cancel()

		ecdsaResult, eddsaResult, err := RunInstallerDKG(ctx)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "DKG failed: "+err.Error())
			return
		}

		state.SetECDSAKeys(ecdsaResult.ShareA, ecdsaResult.ShareB)
		state.SetEdDSAKeys(eddsaResult.ShareA, eddsaResult.ShareB)

		state.mu.Lock()
		state.Step = "dkg"
		state.mu.Unlock()

		slog.Info("DKG ceremony complete",
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

		state.mu.Lock()
		state.LLMProvider = req.Provider
		state.LLMAPIKey = req.APIKey
		state.LLMModel = req.Model
		state.LLMEndpoint = req.Endpoint
		state.Step = "llm"
		state.mu.Unlock()

		slog.Info("LLM config saved", "provider", req.Provider, "model", req.Model)

		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// handleTelegramSave saves the Telegram bot token.
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

		state.mu.Lock()
		state.TelegramBotToken = req.BotToken
		state.Step = "telegram"
		state.mu.Unlock()

		slog.Info("Telegram bot token saved")

		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// handleTelegramVerify polls for the first message to the Telegram bot
// and returns the user ID of the sender.
func handleTelegramVerify(state *WizardState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		token := state.TelegramBotToken
		state.mu.Unlock()

		if token == "" {
			writeError(w, http.StatusBadRequest, "bot token not set; save it first")
			return
		}

		bot, err := tgbotapi.NewBotAPI(token)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid bot token: "+err.Error())
			return
		}

		slog.Info("telegram bot connected, waiting for first message...", "botName", bot.Self.UserName)

		// Poll for the first message with a timeout.
		u := tgbotapi.NewUpdate(0)
		u.Timeout = 30

		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		// We poll in a loop; the Telegram API long-poll timeout is 30s, so we
		// may need up to two iterations to cover our 60s timeout.
		for {
			select {
			case <-ctx.Done():
				writeJSON(w, http.StatusOK, map[string]any{
					"success": false,
					"error":   "timed out waiting for a message; send /start to the bot",
				})
				return
			default:
			}

			updates, err := bot.GetUpdates(u)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "get updates: "+err.Error())
				return
			}

			for _, update := range updates {
				u.Offset = update.UpdateID + 1

				var userID int64
				if update.Message != nil && update.Message.From != nil {
					userID = update.Message.From.ID
				} else if update.CallbackQuery != nil && update.CallbackQuery.From != nil {
					userID = update.CallbackQuery.From.ID
				}

				if userID != 0 {
					state.mu.Lock()
					state.TelegramUserID = userID
					state.mu.Unlock()

					// Send confirmation to the user.
					msg := tgbotapi.NewMessage(userID,
						"Crypto Claw installer has verified your identity. "+
							"This bot will be used for transaction notifications.")
					bot.Send(msg)

					slog.Info("telegram user verified", "userId", userID)

					writeJSON(w, http.StatusOK, map[string]any{
						"success": true,
						"userId":  userID,
					})
					return
				}
			}
		}
	}
}

// handleDeploy starts deployment of both parties.
func handleDeploy(state *WizardState) http.HandlerFunc {
	var deploying sync.Mutex

	return func(w http.ResponseWriter, r *http.Request) {
		if !deploying.TryLock() {
			writeError(w, http.StatusConflict, "deployment already in progress")
			return
		}

		state.mu.Lock()
		state.DeployDone = false
		state.DeployLogs = nil
		state.Step = "deploying"
		localMode := state.LocalMode
		state.mu.Unlock()

		logFn := func(msg string) {
			slog.Info(msg)
			state.AppendLog(msg)
		}

		// Run deployment in background.
		go func() {
			defer deploying.Unlock()

			if localMode {
				logFn("Starting local deployment...")
				if err := DeployLocal(state, logFn); err != nil {
					logFn(fmt.Sprintf("ERROR: local deploy failed: %v", err))
				}
			} else {
				logFn("Starting remote deployment...")
				deployRemote(state, logFn)
			}

			state.mu.Lock()
			state.DeployDone = true
			state.Step = "done"
			state.mu.Unlock()
			logFn("Deployment finished.")
		}()

		writeJSON(w, http.StatusOK, map[string]string{"status": "started"})
	}
}

// deployRemote deploys both parties to their respective remote servers.
func deployRemote(state *WizardState, logFn func(string)) {
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
		return
	}
	defer clientB.Close()

	certDirB := "/etc/crypto-claw"
	cfgB := buildPartyConfig(state, "b", certDirB)
	if err := DeployParty(clientB, "b", cfgB, certB, keyB, caCert, logFn); err != nil {
		logFn(fmt.Sprintf("ERROR: deploy Party B: %v", err))
		return
	}

	// Deploy Party A.
	logFn("Deploying Party A...")
	clientA, err := SSHConnect(serverA)
	if err != nil {
		logFn(fmt.Sprintf("ERROR: SSH connect to Party A (%s): %v", serverA.Host, err))
		return
	}
	defer clientA.Close()

	certDirA := "/etc/crypto-claw"
	cfgA := buildPartyConfig(state, "a", certDirA)
	if err := DeployParty(clientA, "a", cfgA, certA, keyA, caCert, logFn); err != nil {
		logFn(fmt.Sprintf("ERROR: deploy Party A: %v", err))
		return
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
	}
	if errB != nil {
		logFn(fmt.Sprintf("ERROR: upload key shares to Party B: %v", errB))
	}

	logFn("Remote deployment complete.")
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
					fmt.Fprintf(w, "data: %s\n\n", log)
				}
				if len(logs) > 0 {
					flusher.Flush()
				}

				state.mu.Lock()
				done := state.DeployDone
				state.mu.Unlock()

				if done && len(logs) == 0 {
					fmt.Fprintf(w, "event: done\ndata: deployment complete\n\n")
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
