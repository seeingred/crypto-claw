package testutil

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// HardhatNode manages a local Hardhat network for EVM integration tests.
type HardhatNode struct {
	cmd     *exec.Cmd
	RPCURL  string
	ChainID int64
	dir     string
}

// StartHardhat starts a Hardhat network node.
// Requires: npm install to have been run in contracts/evm/.
func StartHardhat(t *testing.T, contractsDir string) *HardhatNode {
	t.Helper()

	port := findFreePort(t)
	rpcURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	cmd := exec.Command("npx", "hardhat", "node", "--port", fmt.Sprintf("%d", port))
	cmd.Dir = contractsDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start hardhat: %v", err)
	}

	node := &HardhatNode{
		cmd:     cmd,
		RPCURL:  rpcURL,
		ChainID: 31337,
		dir:     contractsDir,
	}

	t.Cleanup(func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})

	// Wait for the node to be ready.
	if err := waitForRPC(rpcURL, 30*time.Second); err != nil {
		t.Fatalf("hardhat node not ready: %v", err)
	}

	return node
}

// DeployContract deploys a compiled Hardhat contract and returns its address.
// contractName should match the artifact name (e.g. "CclawToken").
func (h *HardhatNode) DeployContract(t *testing.T, contractName string, args ...string) string {
	t.Helper()

	// Build a deploy script dynamically.
	scriptContent := fmt.Sprintf(`
const hre = require("hardhat");
async function main() {
  const Factory = await hre.ethers.getContractFactory("%s");
  const contract = await Factory.deploy(%s);
  await contract.waitForDeployment();
  const addr = await contract.getAddress();
  console.log("DEPLOYED:" + addr);
}
main().catch(console.error).then(() => process.exit(0));
`, contractName, strings.Join(args, ", "))

	scriptPath := filepath.Join(h.dir, "scripts", "deploy-test.js")
	if err := os.MkdirAll(filepath.Dir(scriptPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(scriptPath)

	cmd := exec.Command("npx", "hardhat", "run", scriptPath, "--network", "localhost")
	cmd.Dir = h.dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("deploy %s: %v\n%s", contractName, err, out)
	}

	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "DEPLOYED:") {
			return strings.TrimPrefix(line, "DEPLOYED:")
		}
	}
	t.Fatalf("deploy %s: address not found in output:\n%s", contractName, out)
	return ""
}

// FundAddress sends ETH from a Hardhat account to the given address.
func (h *HardhatNode) FundAddress(t *testing.T, address string, ethAmount string) {
	t.Helper()
	weiAmount := ethToWei(ethAmount)
	payload := fmt.Sprintf(`{"jsonrpc":"2.0","method":"eth_sendTransaction","params":[{"from":"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266","to":"%s","value":"%s"}],"id":1}`, address, weiAmount)
	resp, err := jsonRPCCall(h.RPCURL, payload)
	if err != nil {
		t.Fatalf("fund address: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("fund address rpc error: %v", resp.Error)
	}
}

// GetBalance returns the ETH balance in wei for an address.
func (h *HardhatNode) GetBalance(t *testing.T, address string) *big.Int {
	t.Helper()
	payload := fmt.Sprintf(`{"jsonrpc":"2.0","method":"eth_getBalance","params":["%s","latest"],"id":1}`, address)
	resp, err := jsonRPCCall(h.RPCURL, payload)
	if err != nil {
		t.Fatalf("get balance: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("get balance rpc error: %v", resp.Error)
	}

	var result string
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("parse balance: %v", err)
	}

	bal := new(big.Int)
	bal.SetString(strings.TrimPrefix(result, "0x"), 16)
	return bal
}

// MineBlock mines a single block on the Hardhat network.
func (h *HardhatNode) MineBlock(t *testing.T) {
	t.Helper()
	payload := `{"jsonrpc":"2.0","method":"evm_mine","params":[],"id":1}`
	if _, err := jsonRPCCall(h.RPCURL, payload); err != nil {
		t.Fatalf("mine block: %v", err)
	}
}

// SendRawTx sends a raw signed transaction to the Hardhat network.
func (h *HardhatNode) SendRawTx(t *testing.T, rawTxHex string) string {
	t.Helper()
	payload := fmt.Sprintf(`{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["%s"],"id":1}`, rawTxHex)
	resp, err := jsonRPCCall(h.RPCURL, payload)
	if err != nil {
		t.Fatalf("send raw tx: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("send raw tx rpc error: code=%d msg=%s", resp.Error.Code, resp.Error.Message)
	}

	var txHash string
	if err := json.Unmarshal(resp.Result, &txHash); err != nil {
		t.Fatalf("parse tx hash: %v", err)
	}
	return txHash
}

// JSON-RPC helpers.

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func jsonRPCCall(url, payload string) (*rpcResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := newHTTPRequest(ctx, url, payload)
	if err != nil {
		return nil, err
	}
	_ = req
	// Use net/http for the actual call.
	return doJSONRPC(ctx, url, payload)
}

func ethToWei(eth string) string {
	val := new(big.Float)
	val.SetString(eth)
	wei := new(big.Float).Mul(val, new(big.Float).SetFloat64(1e18))
	result, _ := wei.Int(nil)
	return "0x" + result.Text(16)
}

func waitForRPC(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := doJSONRPC(context.Background(), url, `{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}`)
		if err == nil && resp.Error == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("RPC at %s not ready after %v", url, timeout)
}

func findFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("find free port:", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}
