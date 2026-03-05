package analyzer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// DecodedCall holds the result of ABI-decoding calldata.
type DecodedCall struct {
	MethodName string                 `json:"methodName"`
	Args       map[string]interface{} `json:"args"`
	Verified   bool                   `json:"verified"` // true if ABI was from a verified contract
}

// ABIResolver fetches and caches contract ABIs from block explorers.
type ABIResolver struct {
	explorerKeys map[string]string // chain -> API key
	cache        sync.Map          // address -> *cachedABI
	client       *http.Client
	logger       *slog.Logger
}

type cachedABI struct {
	abi       *abi.ABI
	fetchedAt time.Time
	verified  bool
}

// NewABIResolver creates a resolver with explorer API keys.
func NewABIResolver(explorerKeys map[string]string, logger *slog.Logger) *ABIResolver {
	return &ABIResolver{
		explorerKeys: explorerKeys,
		client:       &http.Client{Timeout: 10 * time.Second},
		logger:       logger,
	}
}

// DecodeCalldata decodes hex calldata for a contract address.
func (r *ABIResolver) DecodeCalldata(ctx context.Context, contractAddr, hexData string) (*DecodedCall, error) {
	data, err := hexToBytes(hexData)
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}
	if len(data) < 4 {
		return nil, fmt.Errorf("calldata too short: %d bytes", len(data))
	}

	contractABI, verified, err := r.getABI(ctx, contractAddr)
	if err != nil {
		return nil, fmt.Errorf("fetch ABI for %s: %w", contractAddr, err)
	}

	method, err := contractABI.MethodById(data[:4])
	if err != nil {
		return nil, fmt.Errorf("unknown method selector %x: %w", data[:4], err)
	}

	args := make(map[string]interface{})
	if err := method.Inputs.UnpackIntoMap(args, data[4:]); err != nil {
		return nil, fmt.Errorf("unpack args: %w", err)
	}

	return &DecodedCall{
		MethodName: method.Name,
		Args:       args,
		Verified:   verified,
	}, nil
}

// getABI returns a cached or freshly fetched ABI.
func (r *ABIResolver) getABI(ctx context.Context, addr string) (*abi.ABI, bool, error) {
	addr = strings.ToLower(addr)

	if cached, ok := r.cache.Load(addr); ok {
		c := cached.(*cachedABI)
		// Cache for 24 hours.
		if time.Since(c.fetchedAt) < 24*time.Hour {
			return c.abi, c.verified, nil
		}
	}

	abiJSON, err := r.fetchABIFromExplorer(ctx, addr)
	if err != nil {
		return nil, false, err
	}

	parsed, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		return nil, false, fmt.Errorf("parse ABI JSON: %w", err)
	}

	r.cache.Store(addr, &cachedABI{
		abi:       &parsed,
		fetchedAt: time.Now(),
		verified:  true,
	})

	return &parsed, true, nil
}

// etherscanResponse is the Etherscan-compatible API response.
type etherscanResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Result  string `json:"result"`
}

// fetchABIFromExplorer fetches an ABI from a block explorer (Etherscan format).
func (r *ABIResolver) fetchABIFromExplorer(ctx context.Context, addr string) (string, error) {
	// Use first available explorer API key.
	var apiKey string
	for _, key := range r.explorerKeys {
		apiKey = key
		break
	}

	url := fmt.Sprintf("https://api.etherscan.io/api?module=contract&action=getabi&address=%s&apikey=%s", addr, apiKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch ABI: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	var result etherscanResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	if result.Status != "1" {
		return "", fmt.Errorf("explorer API error: %s", result.Message)
	}

	return result.Result, nil
}

// hexToBytes converts a "0x"-prefixed hex string to bytes.
func hexToBytes(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return hex.DecodeString(s)
}
