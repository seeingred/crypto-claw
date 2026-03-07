package analyzer

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"
	"strings"

	"github.com/seeingred/crypto-claw/internal/config"
	"github.com/seeingred/crypto-claw/internal/store"
	"github.com/seeingred/crypto-claw/internal/transport"
	"github.com/seeingred/crypto-claw/internal/vm"
)

// Action represents the analyzer's decision.
type Action string

const (
	ActionApprove  Action = "approve"
	ActionReject   Action = "reject"
	ActionEscalate Action = "escalate"
)

// Decision is the result of analyzing a transaction.
type Decision struct {
	Action     Action  `json:"action"`
	Reason     string  `json:"reason"`
	Confidence float64 `json:"confidence"` // 0.0 to 1.0
}

// AnalysisResult holds the complete analysis output.
type AnalysisResult struct {
	Decision        Decision
	DecodedTx       *vm.DecodedTx
	DecodedCall     *DecodedCall
	Whitelisted     bool
	WhitelistLabel  string
	SignableBytesOK bool
	FieldMismatches []string
	Warnings        []string
	Summary         string // human-readable summary for telegram/logs
}

// WhitelistChecker abstracts whitelist lookups for the analyzer.
type WhitelistChecker interface {
	IsWhitelisted(ctx context.Context, address string) (bool, error)
	GetWhitelistEntry(ctx context.Context, address string) (*store.WhitelistEntry, error)
}

// Analyzer evaluates sign requests for safety.
type Analyzer struct {
	cfg       config.AnalyzerConfig
	vmReg     *vm.Registry
	whitelist WhitelistChecker
	abi       *ABIResolver
	llm       *LLMClient
	logger    *slog.Logger
}

// New creates a new Analyzer. LLM is optional — if DisableAI is true or no provider
// is configured, the analyzer works with deterministic checks + whitelist only.
func New(cfg config.AnalyzerConfig, vmReg *vm.Registry, wl WhitelistChecker, logger *slog.Logger) *Analyzer {
	var llm *LLMClient
	if !cfg.DisableAI && cfg.LLM.Provider != "" {
		llm = NewLLMClient(cfg.LLM, logger)
	}
	return &Analyzer{
		cfg:       cfg,
		vmReg:     vmReg,
		whitelist: wl,
		abi:       NewABIResolver(cfg.ExplorerAPIs, logger),
		llm:       llm,
		logger:    logger,
	}
}

// Analyze decodes the unsigned tx, verifies fields, checks the whitelist,
// runs deterministic checks, optionally runs LLM analysis, and returns a
// rich AnalysisResult.
func (a *Analyzer) Analyze(ctx context.Context, req transport.SignRequestPayload) *AnalysisResult {
	result := &AnalysisResult{
		SignableBytesOK: true,
	}

	// --- 1. Decode unsigned tx using the VM adapter ---
	unsignedTxBytes, err := base64.StdEncoding.DecodeString(req.UnsignedTx)
	if err != nil {
		result.Warnings = append(result.Warnings, "failed to decode unsigned tx base64: "+err.Error())
	} else if a.vmReg != nil {
		adapter, ok := a.vmReg.ForPath(req.DerivationPath)
		if ok {
			decoded, decErr := adapter.DecodeTx(unsignedTxBytes)
			if decErr != nil {
				result.Warnings = append(result.Warnings, "failed to decode tx: "+decErr.Error())
			} else {
				result.DecodedTx = decoded
			}

			// --- 2. Verify signable bytes ---
			recomputedBytes, sbErr := adapter.ExtractSignableBytes(unsignedTxBytes)
			if sbErr != nil {
				result.Warnings = append(result.Warnings, "failed to recompute signable bytes: "+sbErr.Error())
			} else {
				claimedBytes, cbErr := base64.StdEncoding.DecodeString(req.SignableBytes)
				if cbErr != nil {
					result.Warnings = append(result.Warnings, "failed to decode claimed signable bytes: "+cbErr.Error())
				} else if !bytesEqual(recomputedBytes, claimedBytes) {
					result.SignableBytesOK = false
				}
			}
		} else {
			result.Warnings = append(result.Warnings, "no VM adapter for derivation path: "+req.DerivationPath)
		}
	}

	// --- 3. Verify claimed fields match decoded tx ---
	if result.DecodedTx != nil {
		result.FieldMismatches = verifyFields(req, result.DecodedTx)
		if len(result.FieldMismatches) > 0 {
			result.Warnings = append(result.Warnings, result.FieldMismatches...)
		}
	}

	// Hard reject on signable bytes mismatch.
	if !result.SignableBytesOK {
		result.Decision = Decision{
			Action:     ActionReject,
			Reason:     "signable bytes mismatch: unsigned tx does not match claimed hash — possible tampering",
			Confidence: 1.0,
		}
		result.Summary = "REJECTED: Signable bytes from Party A do not match the unsigned transaction."
		return result
	}

	// Use decoded fields if available, otherwise fall back to claimed fields.
	effectiveTo := req.To
	effectiveValue := req.Value
	effectiveData := req.Data
	if result.DecodedTx != nil {
		if len(result.DecodedTx.To) > 0 {
			effectiveTo = result.DecodedTx.To
		}
		if result.DecodedTx.Value != "" {
			effectiveValue = result.DecodedTx.Value
		}
		if result.DecodedTx.Data != "" {
			effectiveData = result.DecodedTx.Data
		}
	}

	// --- 4. Check whitelist ---
	if a.whitelist != nil && len(effectiveTo) > 0 {
		for _, addr := range effectiveTo {
			wl, wlErr := a.whitelist.IsWhitelisted(ctx, addr)
			if wlErr == nil && wl {
				result.Whitelisted = true
				entry, _ := a.whitelist.GetWhitelistEntry(ctx, addr)
				if entry != nil {
					result.WhitelistLabel = entry.Label
				}
				break
			}
		}
	}

	// --- 5. Deterministic checks on actual decoded fields ---
	if d, reject := deterministicChecks(effectiveTo, effectiveValue); reject {
		result.Decision = d
		result.Summary = d.Reason
		return result
	}

	// --- 6. Decode calldata (ABI) ---
	if effectiveData != "" && len(effectiveTo) > 0 {
		dc, abiErr := a.abi.DecodeCalldata(ctx, effectiveTo[0], effectiveData)
		if abiErr != nil {
			a.logger.Debug("calldata decode failed", "err", abiErr)
		} else {
			result.DecodedCall = dc
		}
	}

	// --- 7. Build human-readable summary ---
	result.Summary = buildSummary(effectiveTo, effectiveValue, effectiveData,
		req.DerivationPath, result.DecodedTx, result.DecodedCall, result.Whitelisted, result.WhitelistLabel)

	// --- 8. LLM analysis (if configured) ---
	if a.llm != nil {
		llmDecision, llmErr := a.llm.AnalyzeRich(ctx, result)
		if llmErr != nil {
			a.logger.Error("LLM analysis failed", "err", llmErr)
			result.Warnings = append(result.Warnings, "LLM analysis unavailable: "+llmErr.Error())
			if result.Whitelisted {
				result.Decision = Decision{Action: ActionApprove, Reason: "whitelisted address (LLM unavailable)", Confidence: 0.9}
			} else {
				result.Decision = Decision{Action: ActionEscalate, Reason: "LLM unavailable, manual review needed", Confidence: 0.0}
			}
		} else {
			result.Decision = llmDecision
		}
	} else {
		// No LLM — deterministic + whitelist only.
		if result.Whitelisted {
			result.Decision = Decision{Action: ActionApprove, Reason: "whitelisted address", Confidence: 0.9}
		} else {
			result.Decision = Decision{Action: ActionEscalate, Reason: "manual review required (AI disabled)", Confidence: 0.0}
		}
	}

	return result
}

// deterministicChecks runs fast, rule-based checks on the actual tx fields.
func deterministicChecks(to []string, value string) (Decision, bool) {
	if len(to) == 0 {
		return Decision{
			Action:     ActionReject,
			Reason:     "no recipient addresses specified",
			Confidence: 1.0,
		}, true
	}

	for _, addr := range to {
		lower := strings.ToLower(addr)
		if lower == "0x0000000000000000000000000000000000000000" {
			return Decision{
				Action:     ActionReject,
				Reason:     "transaction targets zero address",
				Confidence: 1.0,
			}, true
		}
	}

	if value != "" {
		val, ok := new(big.Int).SetString(value, 10)
		if !ok {
			return Decision{
				Action:     ActionReject,
				Reason:     "invalid value field",
				Confidence: 1.0,
			}, true
		}
		threshold := new(big.Int).Mul(big.NewInt(100), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
		if val.Cmp(threshold) > 0 {
			return Decision{
				Action:     ActionEscalate,
				Reason:     fmt.Sprintf("high-value transfer: %s wei", val.String()),
				Confidence: 0.9,
			}, true
		}
	}

	return Decision{}, false
}

// verifyFields compares claimed fields in the sign request with the decoded tx fields.
func verifyFields(req transport.SignRequestPayload, decoded *vm.DecodedTx) []string {
	var mismatches []string

	if len(decoded.To) > 0 && len(req.To) > 0 {
		claimedTo := strings.ToLower(req.To[0])
		decodedTo := strings.ToLower(decoded.To[0])
		if claimedTo != decodedTo {
			mismatches = append(mismatches, fmt.Sprintf("'to' mismatch: claimed %s, actual %s", claimedTo, decodedTo))
		}
	}

	if decoded.Value != "" && req.Value != "" && decoded.Value != req.Value {
		mismatches = append(mismatches, fmt.Sprintf("'value' mismatch: claimed %s, actual %s", req.Value, decoded.Value))
	}

	return mismatches
}

// buildSummary constructs a human-readable summary of the transaction.
func buildSummary(to []string, value, data, derivationPath string,
	decoded *vm.DecodedTx, call *DecodedCall, whitelisted bool, whitelistLabel string) string {
	var sb strings.Builder

	// Chain identification from derivation path
	chain := identifyChain(derivationPath)
	sb.WriteString(fmt.Sprintf("Chain: %s\n", chain))

	if len(to) > 0 {
		sb.WriteString(fmt.Sprintf("To: %s\n", strings.Join(to, ", ")))
	}

	if value != "" {
		sb.WriteString(fmt.Sprintf("Value: %s", value))
		if humanVal := formatValue(value, chain); humanVal != "" {
			sb.WriteString(fmt.Sprintf(" (%s)", humanVal))
		}
		sb.WriteString("\n")
	}

	if call != nil {
		sb.WriteString(fmt.Sprintf("Method: %s\n", call.MethodName))
		if call.Verified {
			sb.WriteString("Contract: verified\n")
		} else {
			sb.WriteString("Contract: unverified\n")
		}
		for name, val := range call.Args {
			sb.WriteString(fmt.Sprintf("  %s: %v\n", name, val))
		}
	} else if data != "" {
		if len(data) >= 10 {
			sb.WriteString(fmt.Sprintf("Function selector: %s\n", data[:10]))
		}
		sb.WriteString("Contract call (ABI not available)\n")
	}

	if decoded != nil && decoded.GasLimit > 0 {
		sb.WriteString(fmt.Sprintf("Gas limit: %d\n", decoded.GasLimit))
	}
	if decoded != nil && decoded.ChainID != "" {
		sb.WriteString(fmt.Sprintf("Chain ID: %s\n", decoded.ChainID))
	}

	if whitelisted {
		label := whitelistLabel
		if label == "" {
			label = "known address"
		}
		sb.WriteString(fmt.Sprintf("Whitelist: YES (%s)\n", label))
	} else {
		sb.WriteString("Whitelist: NO\n")
	}

	return sb.String()
}

// identifyChain returns a human-readable chain name from a derivation path.
func identifyChain(path string) string {
	if strings.Contains(path, "/60'") || strings.Contains(path, "/60/") {
		return "EVM (Ethereum)"
	}
	if strings.Contains(path, "/501'") || strings.Contains(path, "/501/") {
		return "Solana"
	}
	if strings.Contains(path, "/118'") || strings.Contains(path, "/118/") {
		return "Cosmos"
	}
	return "unknown"
}

// formatValue converts wei to a human-readable ETH value (EVM only).
func formatValue(weiStr, chain string) string {
	if !strings.Contains(chain, "EVM") {
		return ""
	}
	val, ok := new(big.Int).SetString(weiStr, 10)
	if !ok || val.Sign() == 0 {
		return ""
	}
	eth := new(big.Float).Quo(new(big.Float).SetInt(val), new(big.Float).SetFloat64(1e18))
	return fmt.Sprintf("%.6f ETH", eth)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
