package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/seeingred/crypto-claw/internal/config"
)

// LLMClient handles LLM-based transaction analysis.
type LLMClient struct {
	cfg    config.LLMConfig
	client *http.Client
	logger *slog.Logger
}

// NewLLMClient creates an LLM client based on provider config.
func NewLLMClient(cfg config.LLMConfig, logger *slog.Logger) *LLMClient {
	return &LLMClient{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
		logger: logger,
	}
}

// llmClassification is the expected JSON response from the LLM.
type llmClassification struct {
	Classification string  `json:"classification"` // "safe", "suspicious", "malicious"
	Confidence     float64 `json:"confidence"`      // 0.0 to 1.0
	Reasoning      string  `json:"reasoning"`
}

// AnalyzeRich sends the full analysis context to an LLM and returns a decision.
func (c *LLMClient) AnalyzeRich(ctx context.Context, result *AnalysisResult) (Decision, error) {
	prompt := buildRichPrompt(result)

	classification, err := c.callLLM(ctx, prompt)
	if err != nil {
		return Decision{}, err
	}

	return classificationToDecision(classification), nil
}

// buildRichPrompt constructs a detailed analysis prompt using the decoded tx context.
func buildRichPrompt(result *AnalysisResult) string {
	var sb strings.Builder
	sb.WriteString("You are a blockchain transaction security analyzer for an MPC-TSS signing service.\n")
	sb.WriteString("Analyze this transaction and determine if it is safe to co-sign.\n\n")

	sb.WriteString("=== TRANSACTION DETAILS (decoded from raw unsigned tx) ===\n")
	sb.WriteString(result.Summary)

	if len(result.FieldMismatches) > 0 {
		sb.WriteString("\n=== WARNINGS ===\n")
		for _, m := range result.FieldMismatches {
			sb.WriteString(fmt.Sprintf("- %s\n", m))
		}
	}

	if len(result.Warnings) > 0 {
		sb.WriteString("\n=== ADDITIONAL WARNINGS ===\n")
		for _, w := range result.Warnings {
			sb.WriteString(fmt.Sprintf("- %s\n", w))
		}
	}

	sb.WriteString(`
=== INSTRUCTIONS ===
Based on the decoded transaction data above, classify this transaction.
Consider:
- Is the destination a known protocol or an unknown address?
- Does the function call make sense for the stated purpose?
- Is the value reasonable?
- Are there any signs of a malicious or phishing transaction?
- Is the contract verified?
- Are there field mismatches between what was claimed and what the tx actually does?

Respond ONLY with this JSON (no markdown, no explanation outside the JSON):
{
  "classification": "safe" | "suspicious" | "malicious",
  "confidence": 0.0 to 1.0,
  "reasoning": "brief explanation"
}`)
	return sb.String()
}

// callLLM sends the prompt to the configured LLM provider.
func (c *LLMClient) callLLM(ctx context.Context, prompt string) (*llmClassification, error) {
	var endpoint string
	var reqBody []byte
	var err error

	switch c.cfg.Provider {
	case "openai":
		endpoint = "https://api.openai.com/v1/chat/completions"
		if c.cfg.Endpoint != "" {
			endpoint = c.cfg.Endpoint
		}
		reqBody, err = json.Marshal(openAIRequest{
			Model: c.cfg.Model,
			Messages: []openAIMessage{
				{Role: "system", Content: "You are a blockchain transaction security analyzer. Respond only with JSON."},
				{Role: "user", Content: prompt},
			},
			Temperature: 0.1,
		})
	case "anthropic":
		endpoint = "https://api.anthropic.com/v1/messages"
		if c.cfg.Endpoint != "" {
			endpoint = c.cfg.Endpoint
		}
		reqBody, err = json.Marshal(anthropicRequest{
			Model:     c.cfg.Model,
			MaxTokens: 1024,
			System:    "You are a blockchain transaction security analyzer. Respond only with JSON.",
			Messages: []anthropicMessage{
				{Role: "user", Content: prompt},
			},
		})
	case "local":
		endpoint = c.cfg.Endpoint
		if endpoint == "" {
			return nil, fmt.Errorf("local LLM endpoint not configured")
		}
		reqBody, err = json.Marshal(openAIRequest{
			Model: c.cfg.Model,
			Messages: []openAIMessage{
				{Role: "system", Content: "You are a blockchain transaction security analyzer. Respond only with JSON."},
				{Role: "user", Content: prompt},
			},
			Temperature: 0.1,
		})
	default:
		return nil, fmt.Errorf("unsupported LLM provider: %s", c.cfg.Provider)
	}
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	switch c.cfg.Provider {
	case "openai":
		httpReq.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	case "anthropic":
		httpReq.Header.Set("x-api-key", c.cfg.APIKey)
		httpReq.Header.Set("anthropic-version", "2023-06-01")
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("LLM request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read LLM response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("LLM returned status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	return c.parseResponse(body)
}

// parseResponse extracts the classification from provider-specific response formats.
func (c *LLMClient) parseResponse(body []byte) (*llmClassification, error) {
	var content string

	switch c.cfg.Provider {
	case "openai", "local":
		var resp openAIResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("parse OpenAI response: %w", err)
		}
		if len(resp.Choices) == 0 {
			return nil, fmt.Errorf("no choices in OpenAI response")
		}
		content = resp.Choices[0].Message.Content
	case "anthropic":
		var resp anthropicResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("parse Anthropic response: %w", err)
		}
		if len(resp.Content) == 0 {
			return nil, fmt.Errorf("no content in Anthropic response")
		}
		content = resp.Content[0].Text
	}

	content = extractJSON(content)

	var classification llmClassification
	if err := json.Unmarshal([]byte(content), &classification); err != nil {
		return nil, fmt.Errorf("parse classification JSON: %w (content: %s)", err, truncate(content, 200))
	}

	return &classification, nil
}

// classificationToDecision maps LLM classification to an analyzer Decision.
func classificationToDecision(c *llmClassification) Decision {
	switch {
	case c.Classification == "malicious":
		return Decision{
			Action:     ActionReject,
			Reason:     c.Reasoning,
			Confidence: c.Confidence,
		}
	case c.Classification == "safe" && c.Confidence >= 0.8:
		return Decision{
			Action:     ActionApprove,
			Reason:     c.Reasoning,
			Confidence: c.Confidence,
		}
	default:
		return Decision{
			Action:     ActionEscalate,
			Reason:     c.Reasoning,
			Confidence: c.Confidence,
		}
	}
}

// extractJSON extracts JSON content from potential markdown code blocks.
func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	if idx := strings.Index(s, "```json"); idx != -1 {
		s = s[idx+7:]
		if end := strings.Index(s, "```"); end != -1 {
			s = s[:end]
		}
	} else if idx := strings.Index(s, "```"); idx != -1 {
		s = s[idx+3:]
		if end := strings.Index(s, "```"); end != -1 {
			s = s[:end]
		}
	}
	return strings.TrimSpace(s)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// OpenAI API types.
type openAIRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	Temperature float64         `json:"temperature"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Choices []struct {
		Message openAIMessage `json:"message"`
	} `json:"choices"`
}

// Anthropic API types.
type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
}
