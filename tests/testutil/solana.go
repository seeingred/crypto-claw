package testutil

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// SolanaValidator manages a local solana-test-validator for integration tests.
type SolanaValidator struct {
	cmd    *exec.Cmd
	RPCURL string
	ledger string
}

// StartSolanaValidator starts a local Solana test validator.
func StartSolanaValidator(t *testing.T) *SolanaValidator {
	t.Helper()

	ledgerDir := t.TempDir()
	port := findFreePort(t)
	rpcURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	cmd := exec.Command("solana-test-validator",
		"--ledger", ledgerDir,
		"--rpc-port", fmt.Sprintf("%d", port),
		"--quiet",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start solana-test-validator: %v", err)
	}

	sv := &SolanaValidator{
		cmd:    cmd,
		RPCURL: rpcURL,
		ledger: ledgerDir,
	}

	t.Cleanup(func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})

	if err := waitForSolana(rpcURL, 30*time.Second); err != nil {
		t.Fatalf("solana validator not ready: %v", err)
	}

	return sv
}

// Airdrop sends SOL to an address on the local validator.
func (sv *SolanaValidator) Airdrop(t *testing.T, address string, solAmount float64) {
	t.Helper()

	lamports := int64(solAmount * 1e9)
	payload := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"requestAirdrop","params":["%s",%d]}`, address, lamports)
	resp, err := doJSONRPC(context.Background(), sv.RPCURL, payload)
	if err != nil {
		t.Fatalf("airdrop: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("airdrop rpc error: code=%d msg=%s", resp.Error.Code, resp.Error.Message)
	}

	// Confirm the airdrop transaction.
	var sig string
	if err := json.Unmarshal(resp.Result, &sig); err != nil {
		t.Fatalf("parse airdrop sig: %v", err)
	}
	sv.ConfirmTransaction(t, sig)
}

// GetBalance returns the SOL balance in lamports for an address.
func (sv *SolanaValidator) GetBalance(t *testing.T, address string) uint64 {
	t.Helper()

	payload := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"getBalance","params":["%s"]}`, address)
	resp, err := doJSONRPC(context.Background(), sv.RPCURL, payload)
	if err != nil {
		t.Fatalf("get balance: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("get balance rpc error: code=%d msg=%s", resp.Error.Code, resp.Error.Message)
	}

	var result struct {
		Value uint64 `json:"value"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("parse balance: %v", err)
	}
	return result.Value
}

// ConfirmTransaction waits for a transaction to be confirmed.
func (sv *SolanaValidator) ConfirmTransaction(t *testing.T, signature string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		payload := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"getSignatureStatuses","params":[["%s"],{"searchTransactionHistory":true}]}`, signature)
		resp, err := doJSONRPC(context.Background(), sv.RPCURL, payload)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		var result struct {
			Value []json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(resp.Result, &result); err == nil && len(result.Value) > 0 {
			if string(result.Value[0]) != "null" {
				return // confirmed
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("transaction %s not confirmed within timeout", signature)
}

// CreateSPLToken creates an SPL token using the spl-token CLI and returns the mint address.
func (sv *SolanaValidator) CreateSPLToken(t *testing.T, keypairPath string, decimals int) string {
	t.Helper()

	cmd := exec.Command("spl-token", "create-token",
		"--decimals", fmt.Sprintf("%d", decimals),
		"--keypair", keypairPath,
		"--url", sv.RPCURL,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("create SPL token: %v\n%s", err, out)
	}

	// Parse mint address from output.
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "Creating token") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				return fields[2]
			}
		}
	}
	t.Fatalf("could not parse token mint from output:\n%s", out)
	return ""
}

// CreateTokenAccount creates an associated token account and returns the account address.
func (sv *SolanaValidator) CreateTokenAccount(t *testing.T, mint, keypairPath string) string {
	t.Helper()

	cmd := exec.Command("spl-token", "create-account", mint,
		"--keypair", keypairPath,
		"--url", sv.RPCURL,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("create token account: %v\n%s", err, out)
	}

	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "Creating account") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				return fields[2]
			}
		}
	}
	t.Fatalf("could not parse token account from output:\n%s", out)
	return ""
}

// MintTokens mints SPL tokens to a token account.
func (sv *SolanaValidator) MintTokens(t *testing.T, mint string, amount float64, keypairPath string) {
	t.Helper()

	cmd := exec.Command("spl-token", "mint", mint,
		fmt.Sprintf("%f", amount),
		"--keypair", keypairPath,
		"--url", sv.RPCURL,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("mint tokens: %v\n%s", err, out)
	}
}

// GetTokenBalance returns the token balance for an account.
func (sv *SolanaValidator) GetTokenBalance(t *testing.T, tokenAccount string) float64 {
	t.Helper()

	cmd := exec.Command("spl-token", "balance",
		"--address", tokenAccount,
		"--url", sv.RPCURL,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("get token balance: %v\n%s", err, out)
	}

	var balance float64
	_, err = fmt.Sscanf(strings.TrimSpace(string(out)), "%f", &balance)
	if err != nil {
		t.Fatalf("parse token balance: %v (output: %s)", err, out)
	}
	return balance
}

// SendRawSolanaTx sends a raw serialized transaction to the Solana validator.
func (sv *SolanaValidator) SendRawSolanaTx(t *testing.T, base64Tx string) string {
	t.Helper()

	payload := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"sendTransaction","params":["%s",{"encoding":"base64"}]}`, base64Tx)
	resp, err := doJSONRPC(context.Background(), sv.RPCURL, payload)
	if err != nil {
		t.Fatalf("send tx: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("send tx rpc error: code=%d msg=%s", resp.Error.Code, resp.Error.Message)
	}

	var sig string
	if err := json.Unmarshal(resp.Result, &sig); err != nil {
		t.Fatalf("parse tx sig: %v", err)
	}
	return sig
}

func waitForSolana(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		payload := `{"jsonrpc":"2.0","id":1,"method":"getHealth"}`
		resp, err := doJSONRPC(context.Background(), url, payload)
		if err == nil && resp.Error == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("Solana validator at %s not ready after %v", url, timeout)
}

// GenerateSolanaKeypair creates a temporary Solana keypair file and returns its path and pubkey.
func GenerateSolanaKeypair(t *testing.T) (path string, pubkey string) {
	t.Helper()

	kpDir := t.TempDir()
	kpFile := filepath.Join(kpDir, "keypair.json")
	cmd := exec.Command("solana-keygen", "new", "--no-bip39-passphrase", "--outfile", kpFile, "--force", "--silent")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generate solana keypair: %v\n%s", err, out)
	}

	cmd = exec.Command("solana-keygen", "pubkey", kpFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("get solana pubkey: %v\n%s", err, out)
	}

	return kpFile, strings.TrimSpace(string(out))
}

