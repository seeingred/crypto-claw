package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
)

// sharedPreParams caches pre-params across tests to avoid regenerating.
// Set by TestMain or the first test that needs them.
var sharedPreParams struct {
	a, b *keygen.LocalPreParams
	err  error
	done bool
}

func ensurePreParams(t *testing.T) (*keygen.LocalPreParams, *keygen.LocalPreParams) {
	t.Helper()
	if sharedPreParams.done {
		if sharedPreParams.err != nil {
			t.Fatalf("pre-params generation failed: %v", sharedPreParams.err)
		}
		return sharedPreParams.a, sharedPreParams.b
	}
	t.Log("Generating ECDSA pre-params (one-time, cached for all tests)...")
	start := time.Now()
	sharedPreParams.a, sharedPreParams.err = keygen.GeneratePreParams(10 * time.Minute)
	if sharedPreParams.err != nil {
		sharedPreParams.done = true
		t.Fatalf("pre-params A: %v", sharedPreParams.err)
	}
	sharedPreParams.b, sharedPreParams.err = keygen.GeneratePreParams(10 * time.Minute)
	if sharedPreParams.err != nil {
		sharedPreParams.done = true
		t.Fatalf("pre-params B: %v", sharedPreParams.err)
	}
	sharedPreParams.done = true
	t.Logf("Pre-params generated in %v", time.Since(start))
	return sharedPreParams.a, sharedPreParams.b
}

// TestE2E_LocalInstall is a full end-to-end test of the installer wizard
// in local mode. It exercises every API endpoint in sequence and verifies
// the deployment produces expected output files.
func TestE2E_LocalInstall(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode (needs safe prime generation)")
	}

	// Skip starting party processes in local deploy (no PostgreSQL in test env).
	t.Setenv("CRYPTO_CLAW_NO_PROCESSES", "1")

	ppA, ppB := ensurePreParams(t)

	// Set up state with pre-params injected to skip background generation.
	state := &WizardState{
		Step:          "welcome",
		preParamReady: make(chan struct{}),
	}
	state.InjectPreParams(ppA, ppB)

	mux := http.NewServeMux()
	registerAPIRoutes(mux, state)
	server := httptest.NewServer(corsMiddleware(mux))
	defer server.Close()

	client := server.Client()
	baseURL := server.URL

	// Helper to make API calls.
	post := func(path, body string) *http.Response {
		t.Helper()
		resp, err := client.Post(baseURL+"/api"+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		return resp
	}

	get := func(path string) *http.Response {
		t.Helper()
		resp, err := client.Get(baseURL + "/api" + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		return resp
	}

	decodeJSON := func(resp *http.Response) map[string]any {
		t.Helper()
		defer resp.Body.Close()
		var result map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("decode JSON: %v", err)
		}
		return result
	}

	// ---------------------------------------------------------------
	// Step 1: Verify initial state
	// ---------------------------------------------------------------
	t.Log("Step 1: Check initial state")
	{
		result := decodeJSON(get("/state"))
		if result["step"] != "welcome" {
			t.Fatalf("initial step = %v, want welcome", result["step"])
		}
	}

	// ---------------------------------------------------------------
	// Step 2: Save servers (local mode)
	// ---------------------------------------------------------------
	t.Log("Step 2: Save servers (local mode)")
	{
		resp := post("/servers/save", `{"localMode": true, "serverA": {"host":"127.0.0.1","port":22,"user":"local"}, "serverB": {"host":"127.0.0.1","port":22,"user":"local"}}`)
		result := decodeJSON(resp)
		if resp.StatusCode != 200 {
			t.Fatalf("servers/save status = %d, body = %v", resp.StatusCode, result)
		}
		if result["status"] != "ok" {
			t.Fatalf("servers/save: %v", result)
		}
	}

	// Verify state updated.
	{
		result := decodeJSON(get("/state"))
		if result["step"] != "servers" {
			t.Fatalf("step after servers = %v, want servers", result["step"])
		}
		if result["localMode"] != true {
			t.Fatalf("localMode = %v, want true", result["localMode"])
		}
	}

	// ---------------------------------------------------------------
	// Step 3: Save LLM config
	// ---------------------------------------------------------------
	t.Log("Step 3: Save LLM config")
	{
		resp := post("/llm/save", `{"provider":"anthropic","apiKey":"sk-test","model":"claude-sonnet-4-20250514"}`)
		result := decodeJSON(resp)
		if resp.StatusCode != 200 {
			t.Fatalf("llm/save status = %d", resp.StatusCode)
		}
		if result["status"] != "ok" {
			t.Fatalf("llm/save: %v", result)
		}
	}

	// ---------------------------------------------------------------
	// Step 4: Set Telegram config (directly, skip API validation)
	// ---------------------------------------------------------------
	t.Log("Step 4: Set Telegram config (direct)")
	state.mu.Lock()
	state.TelegramBotToken = "123456:ABCdef_test_token"
	state.TelegramBotUsername = "test_bot"
	state.TelegramUserID = 12345
	state.Step = "telegram"
	state.mu.Unlock()

	// ---------------------------------------------------------------
	// Step 5: Install prepare (generate mnemonic)
	// ---------------------------------------------------------------
	t.Log("Step 5: Install prepare (mnemonic generation)")
	var mnemonic string
	{
		resp := post("/install/prepare", "")
		result := decodeJSON(resp)
		if resp.StatusCode != 200 {
			t.Fatalf("install/prepare status = %d", resp.StatusCode)
		}
		if result["status"] != "ok" {
			t.Fatalf("install/prepare: %v", result)
		}
		mnemonic, _ = result["mnemonic"].(string)
		if mnemonic == "" {
			t.Fatal("mnemonic is empty")
		}
		words := strings.Split(mnemonic, " ")
		if len(words) != 24 {
			t.Fatalf("mnemonic has %d words, want 24", len(words))
		}
		ecdsaPub, _ := result["ecdsaPubKey"].(string)
		eddsaPub, _ := result["eddsaPubKey"].(string)
		if ecdsaPub == "" || eddsaPub == "" {
			t.Fatal("public keys missing from prepare response")
		}
		t.Logf("Mnemonic: %s...%s", words[0], words[23])
		t.Logf("ECDSA pub: %s...", ecdsaPub[:16])
		t.Logf("EdDSA pub: %s...", eddsaPub[:16])
	}

	// ---------------------------------------------------------------
	// Step 6: Deploy (local mode)
	// ---------------------------------------------------------------
	t.Log("Step 6: Start deployment")

	// Start SSE log listener in background.
	logsCh := make(chan string, 100)
	doneCh := make(chan struct{})
	errCh := make(chan string, 1)
	go func() {
		defer close(doneCh)
		resp, err := client.Get(baseURL + "/api/deploy/logs")
		if err != nil {
			errCh <- fmt.Sprintf("SSE connect: %v", err)
			return
		}
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			data := line[6:]
			var msg map[string]string
			if err := json.Unmarshal([]byte(data), &msg); err != nil {
				continue
			}
			logsCh <- fmt.Sprintf("[%s] %s", msg["type"], msg["message"])
			if msg["type"] == "complete" {
				return
			}
			if msg["type"] == "error" {
				errCh <- msg["message"]
				return
			}
		}
	}()

	// Trigger deployment.
	{
		resp := post("/deploy", "")
		result := decodeJSON(resp)
		if resp.StatusCode != 200 {
			t.Fatalf("deploy status = %d, body = %v", resp.StatusCode, result)
		}
		if result["status"] != "started" {
			t.Fatalf("deploy: %v", result)
		}
	}

	// Wait for deployment to finish (collect logs).
	t.Log("Waiting for deployment to complete...")
	timeout := time.After(5 * time.Minute)
	var allLogs []string
loop:
	for {
		select {
		case msg := <-logsCh:
			allLogs = append(allLogs, msg)
			t.Log("  " + msg)
		case errMsg := <-errCh:
			// Print all logs for debugging.
			for _, l := range allLogs {
				t.Log("  " + l)
			}
			t.Fatalf("Deployment failed: %s", errMsg)
		case <-doneCh:
			// Drain remaining logs.
			for {
				select {
				case msg := <-logsCh:
					allLogs = append(allLogs, msg)
					t.Log("  " + msg)
				default:
					break loop
				}
			}
		case <-timeout:
			for _, l := range allLogs {
				t.Log("  " + l)
			}
			t.Fatal("Deployment timed out after 5 minutes")
		}
	}

	// ---------------------------------------------------------------
	// Step 7: Verify final state
	// ---------------------------------------------------------------
	t.Log("Step 7: Verify final state")
	{
		result := decodeJSON(get("/state"))
		if result["step"] != "done" {
			t.Errorf("final step = %v, want done", result["step"])
		}
		if result["deployDone"] != true {
			t.Errorf("deployDone = %v, want true", result["deployDone"])
		}
		if result["mnemonicGenerated"] != true {
			t.Error("mnemonicGenerated should be true")
		}
		if result["ecdsaPubKey"] == "" {
			t.Error("ecdsaPubKey is empty")
		}
		if result["eddsaPubKey"] == "" {
			t.Error("eddsaPubKey is empty")
		}
	}

	// ---------------------------------------------------------------
	// Step 8: Verify local deployment files
	// ---------------------------------------------------------------
	t.Log("Step 8: Verify local deployment files")
	baseDir := localBaseDir()

	for _, party := range []string{"a", "b"} {
		partyDir := filepath.Join(baseDir, "party-"+party)
		for _, file := range []string{"config.json", "ca.pem", "cert.pem", "key.pem", "ecdsa_share.json", "eddsa_share.json"} {
			path := filepath.Join(partyDir, file)
			info, err := os.Stat(path)
			if err != nil {
				t.Errorf("missing file party-%s/%s: %v", party, file, err)
				continue
			}
			if info.Size() == 0 {
				t.Errorf("empty file party-%s/%s", party, file)
			}
		}

		// Verify config.json is valid JSON with expected fields.
		cfgData, err := os.ReadFile(filepath.Join(partyDir, "config.json"))
		if err != nil {
			t.Errorf("read config party-%s: %v", party, err)
			continue
		}
		var cfg map[string]any
		if err := json.Unmarshal(cfgData, &cfg); err != nil {
			t.Errorf("parse config party-%s: %v", party, err)
			continue
		}
		if cfg["party"] != party {
			t.Errorf("config party-%s: party = %v, want %s", party, cfg["party"], party)
		}
		t.Logf("  party-%s config OK (%d bytes)", party, len(cfgData))
	}

	// ---------------------------------------------------------------
	// Step 9: Verify restoration produces same keys
	// ---------------------------------------------------------------
	t.Log("Step 9: Verify mnemonic restoration")
	{
		keys1, err := DeriveKeysFromMnemonic(mnemonic)
		if err != nil {
			t.Fatalf("derive from mnemonic: %v", err)
		}
		keys2, err := DeriveKeysFromMnemonic(mnemonic)
		if err != nil {
			t.Fatalf("derive from mnemonic (second): %v", err)
		}
		if keys1.ECDSAPrivKey.Cmp(keys2.ECDSAPrivKey) != 0 {
			t.Error("ECDSA key mismatch after restore")
		}
		if keys1.EdDSAPrivKey.Cmp(keys2.EdDSAPrivKey) != 0 {
			t.Error("EdDSA key mismatch after restore")
		}
	}

	// ---------------------------------------------------------------
	// Step 10: Cleanup
	// ---------------------------------------------------------------
	t.Log("Step 10: Cleanup")
	if err := os.RemoveAll(baseDir); err != nil {
		t.Logf("WARNING: cleanup failed: %v", err)
	} else {
		t.Logf("Cleaned up %s", baseDir)
	}

	t.Log("E2E local install test PASSED")
}

// TestE2E_DeployFailsGracefully verifies that deployment errors are properly
// reported through the SSE stream as error events, not as "complete".
func TestE2E_DeployFailsGracefully(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	ppA, ppB := ensurePreParams(t)

	state := &WizardState{
		Step:          "welcome",
		preParamReady: make(chan struct{}),
	}
	state.InjectPreParams(ppA, ppB)

	// Set up for remote mode with unreachable servers — should fail at SSH connect.
	state.mu.Lock()
	state.ServerA = SSHConfig{Host: "192.0.2.1", Port: 22, User: "root", Password: "bad"}
	state.ServerB = SSHConfig{Host: "192.0.2.2", Port: 22, User: "root", Password: "bad"}
	state.LLMProvider = "test"
	state.TelegramBotToken = "test"
	state.TelegramUserID = 1
	state.Step = "telegram"
	state.mu.Unlock()

	mux := http.NewServeMux()
	registerAPIRoutes(mux, state)
	server := httptest.NewServer(corsMiddleware(mux))
	defer server.Close()

	client := server.Client()

	// Generate mnemonic.
	resp, err := client.Post(server.URL+"/api/install/prepare", "application/json", nil)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	resp.Body.Close()

	// Start SSE listener.
	gotError := make(chan string, 1)
	gotComplete := make(chan struct{}, 1)
	go func() {
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
			if msg["type"] == "error" {
				gotError <- msg["message"]
				return
			}
			if msg["type"] == "complete" {
				gotComplete <- struct{}{}
				return
			}
		}
	}()

	// Trigger deploy.
	resp, err = client.Post(server.URL+"/api/deploy", "application/json", nil)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	resp.Body.Close()

	// Should get error, NOT complete.
	select {
	case errMsg := <-gotError:
		t.Logf("Got expected error: %s", errMsg)
	case <-gotComplete:
		t.Fatal("Got 'complete' but expected 'error' — deployment should have failed")
	case <-time.After(2 * time.Minute):
		t.Fatal("Timed out waiting for deployment result")
	}

	// Verify state reflects failure.
	state.mu.Lock()
	if !state.DeployFailed {
		t.Error("DeployFailed should be true")
	}
	if state.Step == "done" {
		t.Error("Step should NOT be 'done' after failure")
	}
	state.mu.Unlock()
}
