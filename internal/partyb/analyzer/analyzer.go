package analyzer

import (
	"context"
	"fmt"
	"log/slog"
	"math/big"
	"strings"

	"github.com/seeingred/crypto-claw/internal/config"
	"github.com/seeingred/crypto-claw/internal/transport"
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

// Analyzer evaluates sign requests for safety.
type Analyzer struct {
	cfg    config.AnalyzerConfig
	abi    *ABIResolver
	llm    *LLMClient
	logger *slog.Logger
}

// New creates a new Analyzer.
func New(cfg config.AnalyzerConfig, logger *slog.Logger) *Analyzer {
	return &Analyzer{
		cfg:    cfg,
		abi:    NewABIResolver(cfg.ExplorerAPIs, logger),
		llm:    NewLLMClient(cfg.LLM, logger),
		logger: logger,
	}
}

// Analyze runs deterministic checks and LLM analysis on a sign request.
func (a *Analyzer) Analyze(ctx context.Context, req transport.SignRequestPayload) Decision {
	// Run deterministic checks first.
	if d, reject := a.deterministicChecks(req); reject {
		return d
	}

	// Decode calldata if present.
	var decodedCall *DecodedCall
	if req.Data != "" && len(req.To) > 0 {
		dc, err := a.abi.DecodeCalldata(ctx, req.To[0], req.Data)
		if err != nil {
			a.logger.Warn("failed to decode calldata", "err", err, "to", req.To[0])
		} else {
			decodedCall = dc
		}
	}

	// Run LLM analysis.
	llmDecision, err := a.llm.Analyze(ctx, req, decodedCall)
	if err != nil {
		a.logger.Error("LLM analysis failed, escalating", "err", err)
		return Decision{
			Action:     ActionEscalate,
			Reason:     fmt.Sprintf("LLM analysis unavailable: %v", err),
			Confidence: 0,
		}
	}

	return llmDecision
}

// deterministicChecks runs fast, rule-based checks.
// Returns (decision, true) if the request should be rejected immediately.
func (a *Analyzer) deterministicChecks(req transport.SignRequestPayload) (Decision, bool) {
	// Reject if no recipients.
	if len(req.To) == 0 {
		return Decision{
			Action:     ActionReject,
			Reason:     "no recipient addresses specified",
			Confidence: 1.0,
		}, true
	}

	// Reject if sending to zero address.
	for _, to := range req.To {
		lower := strings.ToLower(to)
		if lower == "0x0000000000000000000000000000000000000000" {
			return Decision{
				Action:     ActionReject,
				Reason:     "transaction targets zero address",
				Confidence: 1.0,
			}, true
		}
	}

	// Flag extremely large values for escalation.
	if req.Value != "" {
		val, ok := new(big.Int).SetString(req.Value, 10)
		if !ok {
			return Decision{
				Action:     ActionReject,
				Reason:     "invalid value field",
				Confidence: 1.0,
			}, true
		}
		// Escalate transfers > 100 ETH (100e18 wei).
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
