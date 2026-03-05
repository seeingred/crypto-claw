package partyb

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/seeingred/crypto-claw/internal/config"
	"github.com/seeingred/crypto-claw/internal/partyb/analyzer"
	"github.com/seeingred/crypto-claw/internal/partyb/telegram"
	"github.com/seeingred/crypto-claw/internal/store"
	"github.com/seeingred/crypto-claw/internal/transport"
	"github.com/seeingred/crypto-claw/internal/tss"
)

// Service is the Party B orchestration service.
type Service struct {
	cfg       *config.Config
	store     store.Store
	tss       tss.Protocol
	analyzer  *analyzer.Analyzer
	bot       *telegram.Bot
	logger    *slog.Logger

	// Pending escalations awaiting human decision.
	pending   map[string]chan bool
	pendingMu sync.Mutex

	// Cached sign requests for escalated transactions.
	reqCache   map[string]*signContext
	reqCacheMu sync.Mutex
}

// signContext holds the context for an in-flight sign request.
type signContext struct {
	req       transport.SignRequestPayload
	messageID uint64
}

// New creates a new Party B service.
func New(cfg *config.Config, st store.Store, proto tss.Protocol, logger *slog.Logger) (*Service, error) {
	a := analyzer.New(cfg.Analyzer, logger)

	svc := &Service{
		cfg:      cfg,
		store:    st,
		tss:      proto,
		analyzer: a,
		logger:   logger,
		pending:  make(map[string]chan bool),
		reqCache: make(map[string]*signContext),
	}

	if cfg.Telegram.BotToken != "" {
		bot, err := telegram.New(cfg.Telegram, logger)
		if err != nil {
			return nil, fmt.Errorf("init telegram bot: %w", err)
		}
		bot.SetAutoMode(cfg.Analyzer.AutoMode)
		bot.SetDecisionCallback(svc.onTelegramDecision)
		svc.bot = bot
	}

	return svc, nil
}

// Start starts the Telegram bot in the background.
func (s *Service) Start(ctx context.Context) {
	if s.bot != nil {
		go s.bot.Start()
	}
}

// Stop shuts down the service.
func (s *Service) Stop() {
	if s.bot != nil {
		s.bot.Stop()
	}
}

// HandleSignRequest is the main entry point for incoming sign requests.
// It runs the analyzer, decides, and returns a response.
func (s *Service) HandleSignRequest(ctx context.Context, msgID uint64, req transport.SignRequestPayload) transport.SignResponsePayload {
	txID := uuid.New().String()
	s.logger.Info("received sign request", "txID", txID, "to", req.To, "path", req.DerivationPath)

	// Store the transaction.
	txRecord := &store.TxRecord{
		ID:             txID,
		DerivationPath: req.DerivationPath,
		To:             req.To,
		Value:          req.Value,
		Data:           req.Data,
		Status:         store.TxStatusPending,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	if raw, err := base64.StdEncoding.DecodeString(req.UnsignedTx); err == nil {
		txRecord.UnsignedTx = raw
	}
	if err := s.store.SaveTx(ctx, txRecord); err != nil {
		s.logger.Error("failed to save tx", "err", err)
	}

	// Analyze the transaction.
	decision := s.analyzer.Analyze(ctx, req)
	s.logger.Info("analyzer decision", "txID", txID, "action", decision.Action, "confidence", decision.Confidence, "reason", decision.Reason)

	// If bot is in auto mode and decision is approve/reject, act immediately.
	if s.bot != nil && s.bot.AutoMode() && decision.Action != analyzer.ActionEscalate {
		return s.finalizeDecision(ctx, txID, req, decision)
	}

	// If decision is escalate, or we're in manual mode, notify via Telegram.
	if decision.Action == analyzer.ActionEscalate || (s.bot != nil && !s.bot.AutoMode()) {
		return s.escalate(ctx, txID, req, decision.Reason)
	}

	return s.finalizeDecision(ctx, txID, req, decision)
}

// escalate sends a notification to Telegram and waits for human decision.
func (s *Service) escalate(ctx context.Context, txID string, req transport.SignRequestPayload, reason string) transport.SignResponsePayload {
	decisionCh := make(chan bool, 1)

	s.pendingMu.Lock()
	s.pending[txID] = decisionCh
	s.pendingMu.Unlock()

	s.reqCacheMu.Lock()
	s.reqCache[txID] = &signContext{req: req}
	s.reqCacheMu.Unlock()

	defer func() {
		s.pendingMu.Lock()
		delete(s.pending, txID)
		s.pendingMu.Unlock()
		s.reqCacheMu.Lock()
		delete(s.reqCache, txID)
		s.reqCacheMu.Unlock()
	}()

	// Notify via Telegram.
	if s.bot != nil {
		if err := s.bot.NotifyTransaction(txID, req, reason); err != nil {
			s.logger.Error("failed to send telegram notification", "err", err)
		}
	}

	// Wait for human decision or timeout.
	timeout := s.cfg.Telegram.EscalationTimeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	select {
	case approved := <-decisionCh:
		if approved {
			return s.finalizeDecision(ctx, txID, req, analyzer.Decision{
				Action:     analyzer.ActionApprove,
				Reason:     "manually approved via Telegram",
				Confidence: 1.0,
			})
		}
		s.updateTxStatus(ctx, txID, store.TxStatusRejected)
		return transport.SignResponsePayload{
			Decision: string(analyzer.ActionReject),
			Reason:   "manually rejected via Telegram",
		}
	case <-time.After(timeout):
		s.updateTxStatus(ctx, txID, store.TxStatusRejected)
		return transport.SignResponsePayload{
			Decision: string(analyzer.ActionReject),
			Reason:   "escalation timed out",
		}
	case <-ctx.Done():
		s.updateTxStatus(ctx, txID, store.TxStatusRejected)
		return transport.SignResponsePayload{
			Decision: string(analyzer.ActionReject),
			Reason:   "request cancelled",
		}
	}
}

// finalizeDecision handles the final approve/reject flow.
func (s *Service) finalizeDecision(ctx context.Context, txID string, req transport.SignRequestPayload, decision analyzer.Decision) transport.SignResponsePayload {
	if decision.Action == analyzer.ActionReject {
		s.updateTxStatus(ctx, txID, store.TxStatusRejected)
		return transport.SignResponsePayload{
			Decision: string(analyzer.ActionReject),
			Reason:   decision.Reason,
		}
	}

	// Approved - participate in TSS signing.
	s.updateTxStatus(ctx, txID, store.TxStatusApproved)

	sig, err := s.sign(ctx, req)
	if err != nil {
		s.logger.Error("signing failed", "txID", txID, "err", err)
		return transport.SignResponsePayload{
			Decision: string(analyzer.ActionReject),
			Reason:   fmt.Sprintf("signing failed: %v", err),
		}
	}

	s.updateTxStatus(ctx, txID, store.TxStatusSigned)

	sigJSON, _ := json.Marshal(sig)
	return transport.SignResponsePayload{
		Decision: string(analyzer.ActionApprove),
		Reason:   decision.Reason,
		TxID:     base64.StdEncoding.EncodeToString(sigJSON),
	}
}

// sign performs the TSS signing operation.
func (s *Service) sign(ctx context.Context, req transport.SignRequestPayload) (*tss.Signature, error) {
	// Decode the unsigned transaction.
	msgBytes, err := base64.StdEncoding.DecodeString(req.UnsignedTx)
	if err != nil {
		return nil, fmt.Errorf("decode unsigned tx: %w", err)
	}

	// Retrieve key share for derivation path.
	derivedKey, err := s.store.GetDerivedKey(ctx, req.DerivationPath)
	if err != nil {
		return nil, fmt.Errorf("get derived key: %w", err)
	}

	signReq := tss.SignRequest{
		DerivationPath: req.DerivationPath,
		Message:        msgBytes,
		Curve:          derivedKey.Curve,
	}

	parties := []tss.PartyID{
		{ID: "party-a", Index: 0},
		{ID: "party-b", Index: 1},
	}
	partyID := tss.PartyID{ID: "party-b", Index: 1}

	return s.tss.Sign(ctx, signReq, derivedKey.Share, partyID, parties, nil)
}

// onTelegramDecision is the callback from the Telegram bot.
func (s *Service) onTelegramDecision(txID string, approved bool) {
	s.pendingMu.Lock()
	ch, ok := s.pending[txID]
	s.pendingMu.Unlock()

	if ok {
		ch <- approved
	} else {
		s.logger.Warn("received telegram decision for unknown tx", "txID", txID, "approved", approved)
	}
}

// updateTxStatus updates a transaction's status in the store.
func (s *Service) updateTxStatus(ctx context.Context, txID string, status store.TxStatus) {
	if err := s.store.UpdateTxStatus(ctx, txID, status, nil); err != nil {
		s.logger.Error("failed to update tx status", "txID", txID, "status", status, "err", err)
	}
}
