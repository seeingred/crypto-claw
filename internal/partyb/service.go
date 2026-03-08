package partyb

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/seeingred/crypto-claw/internal/config"
	"github.com/seeingred/crypto-claw/internal/partyb/analyzer"
	"github.com/seeingred/crypto-claw/internal/partyb/telegram"
	"github.com/seeingred/crypto-claw/internal/store"
	"github.com/seeingred/crypto-claw/internal/transport"
	"github.com/seeingred/crypto-claw/internal/tss"
	"github.com/seeingred/crypto-claw/internal/vm"
)

// SigningStartedCallback is called when Party B starts TSS signing (approve or escalation-approve).
// The caller (main.go) uses this to set up the ServerRouter and wire TSS round messages.
type SigningStartedCallback func(txID string, req transport.SignRequestPayload) *transport.ServerRouter

// EscalationApprovedCallback is called when an escalated tx is approved via Telegram.
// Party B pushes MsgSignApproved to Party A so Party A starts its side of signing.
type EscalationApprovedCallback func(txID string, derivationPath string)

// Service is the Party B orchestration service.
type Service struct {
	cfg       *config.Config
	store     store.Store
	tss       tss.Protocol
	vmReg     *vm.Registry
	analyzer  *analyzer.Analyzer
	bot       *telegram.Bot
	logger    *slog.Logger

	// Callbacks set by the main wiring code.
	onSigningStarted      SigningStartedCallback
	onEscalationApproved  EscalationApprovedCallback

	// Pending escalations awaiting human decision.
	pending   map[string]chan bool
	pendingMu sync.Mutex

	// Cached sign requests for escalated transactions.
	reqCache   map[string]*signContext
	reqCacheMu sync.Mutex

	// Active TSS signing router (one signing session at a time).
	activeRouter   *transport.ServerRouter
	activeRouterMu sync.Mutex

	// Channels for receiving final signable bytes from Party A (MsgSignReady).
	signReady   map[string]chan []byte
	signReadyMu sync.Mutex
}

// signContext holds the context for an in-flight sign request.
type signContext struct {
	req    transport.SignRequestPayload
	result *analyzer.AnalysisResult
}

// New creates a new Party B service.
func New(cfg *config.Config, st store.Store, proto tss.Protocol, vmReg *vm.Registry, logger *slog.Logger) (*Service, error) {
	a := analyzer.New(cfg.Analyzer, vmReg, st, logger)

	svc := &Service{
		cfg:      cfg,
		store:    st,
		tss:      proto,
		vmReg:    vmReg,
		analyzer: a,
		logger:   logger,
		pending:   make(map[string]chan bool),
		reqCache:  make(map[string]*signContext),
		signReady: make(map[string]chan []byte),
	}

	if cfg.Telegram.BotToken != "" {
		bot, err := telegram.New(cfg.Telegram, logger)
		if err != nil {
			return nil, fmt.Errorf("init telegram bot: %w", err)
		}
		bot.SetAutoMode(cfg.Analyzer.AutoMode)
		bot.SetDecisionCallback(svc.onTelegramDecision)
		bot.SetWhitelistCallback(svc.onTelegramWhitelist)
		svc.bot = bot
	}

	// Seed whitelist from config.
	for _, seed := range cfg.Analyzer.Whitelist {
		entry := &store.WhitelistEntry{
			Address: strings.ToLower(seed.Address),
			Label:   seed.Label,
			AddedAt: time.Now(),
		}
		if err := st.AddWhitelistEntry(context.Background(), entry); err != nil {
			logger.Warn("failed to seed whitelist entry", "address", seed.Address, "err", err)
		}
	}

	return svc, nil
}

// SetSigningStartedCallback sets the callback for when TSS signing begins.
func (s *Service) SetSigningStartedCallback(cb SigningStartedCallback) {
	s.onSigningStarted = cb
}

// SetEscalationApprovedCallback sets the callback for when an escalated tx is approved.
func (s *Service) SetEscalationApprovedCallback(cb EscalationApprovedCallback) {
	s.onEscalationApproved = cb
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

// HandleTSSRound routes an incoming TSS round message to the active signing session.
func (s *Service) HandleTSSRound(from tss.PartyID, payload []byte) {
	s.activeRouterMu.Lock()
	router := s.activeRouter
	s.activeRouterMu.Unlock()

	if router != nil {
		router.FeedMessage(from, payload)
	} else {
		s.logger.Warn("received TSS round message but no active signing session")
	}
}

// HandleSignRequest is the main entry point for incoming sign requests.
// It runs the analyzer, routes the decision, and starts TSS signing if approved.
func (s *Service) HandleSignRequest(ctx context.Context, msgID uint64, req transport.SignRequestPayload) transport.SignResponsePayload {
	txID := uuid.New().String()
	s.logger.Info("received sign request", "txID", txID, "to", req.To, "path", req.DerivationPath)

	// Store the transaction.
	to := req.To
	if to == nil {
		to = []string{}
	}
	txRecord := &store.TxRecord{
		ID:             txID,
		DerivationPath: req.DerivationPath,
		To:             to,
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

	// Run the analyzer (decodes tx, verifies signable bytes, checks whitelist, optionally LLM).
	result := s.analyzer.Analyze(ctx, req)
	s.logger.Info("analyzer result",
		"txID", txID,
		"action", result.Decision.Action,
		"confidence", result.Decision.Confidence,
		"whitelisted", result.Whitelisted,
		"signableBytesOK", result.SignableBytesOK,
		"reason", result.Decision.Reason,
	)

	// --- Decision routing ---

	// Hard reject: signable bytes mismatch or analyzer rejects.
	if result.Decision.Action == analyzer.ActionReject {
		s.updateTxStatus(ctx, txID, store.TxStatusRejected)
		return transport.SignResponsePayload{
			Decision: string(analyzer.ActionReject),
			Reason:   result.Decision.Reason,
		}
	}

	// autoMode=true: whitelisted addresses auto-approve with notification.
	if s.bot != nil && s.bot.AutoMode() && result.Whitelisted {
		s.updateTxStatus(ctx, txID, store.TxStatusApproved)
		s.startSigning(txID, req)

		// Send notification (non-interactive) to user about auto-approved tx.
		if err := s.bot.NotifyAutoApproved(txID, result); err != nil {
			s.logger.Warn("failed to send auto-approve notification", "err", err)
		}

		return transport.SignResponsePayload{
			Decision: string(analyzer.ActionApprove),
			TxID:     txID,
			Reason:   result.Decision.Reason,
		}
	}

	// autoMode=true, not whitelisted: escalate everything to user.
	// autoMode=false: escalate everything to user.
	return s.escalate(ctx, txID, req, result)
}

// startSigning begins the TSS signing protocol for Party B in a background goroutine.
func (s *Service) startSigning(txID string, req transport.SignRequestPayload) {
	if s.onSigningStarted == nil {
		s.logger.Error("no signing started callback configured", "txID", txID)
		return
	}

	router := s.onSigningStarted(txID, req)
	s.activeRouterMu.Lock()
	s.activeRouter = router
	s.activeRouterMu.Unlock()

	go func() {
		defer func() {
			s.activeRouterMu.Lock()
			if s.activeRouter == router {
				s.activeRouter = nil
			}
			s.activeRouterMu.Unlock()
		}()

		sig, err := s.sign(context.Background(), txID, req, router)
		if err != nil {
			s.logger.Error("TSS signing failed", "txID", txID, "err", err)
			s.updateTxStatus(context.Background(), txID, store.TxStatusRejected)
			return
		}

		sigJSON, _ := json.Marshal(sig)
		if err := s.store.UpdateTxStatus(context.Background(), txID, store.TxStatusSigned, sigJSON); err != nil {
			s.logger.Error("failed to store signed tx", "txID", txID, "err", err)
		}
		s.logger.Info("TSS signing completed", "txID", txID)
	}()
}

// escalate sends a notification to Telegram and returns immediately with "escalate" status.
func (s *Service) escalate(ctx context.Context, txID string, req transport.SignRequestPayload, result *analyzer.AnalysisResult) transport.SignResponsePayload {
	if s.bot != nil {
		if err := s.bot.NotifyForReview(txID, result); err != nil {
			s.logger.Error("failed to send telegram notification", "err", err)
			s.updateTxStatus(ctx, txID, store.TxStatusRejected)
			return transport.SignResponsePayload{
				Decision: string(analyzer.ActionReject),
				Reason:   fmt.Sprintf("failed to send Telegram notification: %v", err),
			}
		}
	} else {
		s.updateTxStatus(ctx, txID, store.TxStatusRejected)
		return transport.SignResponsePayload{
			Decision: string(analyzer.ActionReject),
			Reason:   "no Telegram bot configured for escalation",
		}
	}

	// Register pending decision handler.
	decisionCh := make(chan bool, 1)
	s.pendingMu.Lock()
	s.pending[txID] = decisionCh
	s.pendingMu.Unlock()

	s.reqCacheMu.Lock()
	s.reqCache[txID] = &signContext{req: req, result: result}
	s.reqCacheMu.Unlock()

	// Handle the decision asynchronously.
	go func() {
		timeout := s.cfg.Telegram.EscalationTimeout
		if timeout == 0 {
			timeout = 5 * time.Minute
		}

		defer func() {
			s.pendingMu.Lock()
			delete(s.pending, txID)
			s.pendingMu.Unlock()
			s.reqCacheMu.Lock()
			delete(s.reqCache, txID)
			s.reqCacheMu.Unlock()
		}()

		select {
		case approved := <-decisionCh:
			if approved {
				s.logger.Info("tx approved via Telegram", "txID", txID)
				s.updateTxStatus(context.Background(), txID, store.TxStatusApproved)

				// Notify Party A to start its side of signing.
				if s.onEscalationApproved != nil {
					s.onEscalationApproved(txID, req.DerivationPath)
				}

				// Start Party B's side of signing.
				s.startSigning(txID, req)
			} else {
				s.logger.Info("tx rejected via Telegram", "txID", txID)
				s.updateTxStatus(context.Background(), txID, store.TxStatusRejected)
			}
		case <-time.After(timeout):
			s.logger.Warn("escalation timed out", "txID", txID)
			s.updateTxStatus(context.Background(), txID, store.TxStatusRejected)
		}
	}()

	return transport.SignResponsePayload{
		Decision: string(analyzer.ActionEscalate),
		TxID:     txID,
		Reason:   result.Decision.Reason,
	}
}

// HandleSignReady is called when Party A sends MsgSignReady with final signable bytes.
func (s *Service) HandleSignReady(payload transport.SignReadyPayload) {
	s.signReadyMu.Lock()
	ch, ok := s.signReady[payload.TxID]
	s.signReadyMu.Unlock()

	if ok {
		decoded, err := base64.StdEncoding.DecodeString(payload.SignableBytes)
		if err != nil {
			s.logger.Error("failed to decode sign-ready bytes", "txID", payload.TxID, "err", err)
			return
		}
		ch <- decoded
	}
}

// sign performs the TSS signing operation using the provided router.
func (s *Service) sign(ctx context.Context, txID string, req transport.SignRequestPayload, router tss.MessageRouter) (*tss.Signature, error) {
	// Wait for Party A to send final signable bytes (MsgSignReady).
	// This ensures both parties sign the same message, even if Party A
	// modified the transaction (e.g., injected a fresh Solana blockhash).
	ch := make(chan []byte, 1)
	s.signReadyMu.Lock()
	s.signReady[txID] = ch
	s.signReadyMu.Unlock()

	defer func() {
		s.signReadyMu.Lock()
		delete(s.signReady, txID)
		s.signReadyMu.Unlock()
	}()

	var msgBytes []byte
	select {
	case msgBytes = <-ch:
		// Got final signable bytes from Party A.
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("timeout waiting for sign-ready from Party A")
	case <-ctx.Done():
		return nil, ctx.Err()
	}

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

	return s.tss.Sign(ctx, signReq, derivedKey.Share, partyID, parties, router)
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

// onTelegramWhitelist is the callback when user clicks "Approve & Whitelist".
func (s *Service) onTelegramWhitelist(txID string) {
	s.reqCacheMu.Lock()
	sc, ok := s.reqCache[txID]
	s.reqCacheMu.Unlock()

	if !ok {
		s.logger.Warn("whitelist request for unknown tx", "txID", txID)
		return
	}

	// Use decoded tx addresses if available, otherwise claimed.
	addrs := sc.req.To
	if sc.result != nil && sc.result.DecodedTx != nil && len(sc.result.DecodedTx.To) > 0 {
		addrs = sc.result.DecodedTx.To
	}

	for _, addr := range addrs {
		entry := &store.WhitelistEntry{
			Address: strings.ToLower(addr),
			Label:   "approved via Telegram",
			AddedAt: time.Now(),
		}
		if err := s.store.AddWhitelistEntry(context.Background(), entry); err != nil {
			s.logger.Error("failed to whitelist address", "address", addr, "err", err)
		} else {
			s.logger.Info("address whitelisted via Telegram", "address", addr, "txID", txID)
		}
	}
}

// GetTxStatus returns the current status of a transaction.
func (s *Service) GetTxStatus(ctx context.Context, txID string) (*store.TxRecord, error) {
	return s.store.GetTx(ctx, txID)
}

// HandleDeriveRequest derives a child key share and stores it locally.
func (s *Service) HandleDeriveRequest(ctx context.Context, derivationPath string) error {
	// Determine curve from the VM adapter registry.
	curve := tss.CurveSecp256k1
	if s.vmReg != nil {
		if adapter, ok := s.vmReg.ForPath(derivationPath); ok {
			curve = adapter.Curve()
		}
	}

	masterShare, err := s.store.GetMasterShare(ctx, curve)
	if err != nil {
		return fmt.Errorf("get master share: %w", err)
	}

	derived, err := s.tss.DeriveKey(ctx, masterShare, derivationPath)
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}

	record := &store.DerivedKeyRecord{
		DerivationPath: derivationPath,
		Curve:          curve,
		PublicKey:      derived.PublicKey,
		Share:          derived.Share,
		CreatedAt:      time.Now(),
	}
	if err := s.store.SaveDerivedKey(ctx, record); err != nil {
		return fmt.Errorf("save derived key: %w", err)
	}

	s.logger.Info("derived key for path", "path", derivationPath, "curve", curve)
	return nil
}

func (s *Service) updateTxStatus(ctx context.Context, txID string, status store.TxStatus) {
	if err := s.store.UpdateTxStatus(ctx, txID, status, nil); err != nil {
		s.logger.Error("failed to update tx status", "txID", txID, "status", status, "err", err)
	}
}
