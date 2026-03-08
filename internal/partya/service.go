package partya

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/seeingred/crypto-claw/internal/store"
	"github.com/seeingred/crypto-claw/internal/transport"
	"github.com/seeingred/crypto-claw/internal/tss"
	"github.com/seeingred/crypto-claw/internal/vm"
	solanarpc "github.com/seeingred/crypto-claw/internal/vm/solana"
)

// TransportClient abstracts the Party A -> Party B communication.
type TransportClient interface {
	Send(ctx context.Context, msg *transport.Message) error
	SendAndReceive(ctx context.Context, msg *transport.Message) (*transport.Message, error)
	Close() error
}

// Service is the main Party A service orchestrating key derivation and signing.
type Service struct {
	store      store.Store
	transport  TransportClient
	tssRouter  tss.MessageRouter // TSS message router (transport client)
	tssProto   tss.Protocol
	vmRegistry *vm.Registry
	escalation *EscalationQueue
	msgCounter uint64
}

// NewService creates a new Party A service.
func NewService(
	st store.Store,
	tc TransportClient,
	router tss.MessageRouter,
	proto tss.Protocol,
	registry *vm.Registry,
) *Service {
	return &Service{
		store:      st,
		transport:  tc,
		tssRouter:  router,
		tssProto:   proto,
		vmRegistry: registry,
		escalation: NewEscalationQueue(),
	}
}

func (s *Service) nextMsgID() uint64 {
	return atomic.AddUint64(&s.msgCounter, 1)
}

// DeriveResult holds the result of a key derivation.
type DeriveResult struct {
	Address   string `json:"address"`
	PublicKey string `json:"pubKey"` // hex-encoded
}

// Derive derives a new child key for the given derivation path and label.
func (s *Service) Derive(ctx context.Context, derivationPath, label, prefix string) (*DeriveResult, error) {
	// Look up the adapter for this derivation path
	adapter, ok := s.vmRegistry.ForPath(derivationPath)
	if !ok {
		return nil, fmt.Errorf("no adapter registered for path %s", derivationPath)
	}

	// Get master share for the curve
	masterShare, err := s.store.GetMasterShare(ctx, adapter.Curve())
	if err != nil {
		return nil, fmt.Errorf("get master share: %w", err)
	}

	// Derive child key
	derived, err := s.tssProto.DeriveKey(ctx, masterShare, derivationPath)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

	// Derive chain-specific address
	var deriveOpts []vm.DeriveOption
	if prefix != "" {
		deriveOpts = append(deriveOpts, vm.WithPrefix(prefix))
	}
	address, err := adapter.DeriveAddress(derived.PublicKey, deriveOpts...)
	if err != nil {
		return nil, fmt.Errorf("derive address: %w", err)
	}

	// Store the derived key
	record := &store.DerivedKeyRecord{
		DerivationPath: derivationPath,
		Curve:          adapter.Curve(),
		PublicKey:       derived.PublicKey,
		Address:         address,
		Label:           label,
		Share:           derived.Share,
		CreatedAt:       time.Now(),
	}
	if err := s.store.SaveDerivedKey(ctx, record); err != nil {
		return nil, fmt.Errorf("save derived key: %w", err)
	}

	// Notify Party B to derive the same key
	deriveReq, _ := json.Marshal(map[string]string{
		"derivationPath": derivationPath,
	})
	_, _ = s.transport.SendAndReceive(ctx, &transport.Message{
		Type:    transport.MsgDeriveReq,
		ID:      s.nextMsgID(),
		Payload: deriveReq,
	})

	return &DeriveResult{
		Address:   address,
		PublicKey: fmt.Sprintf("0x%x", derived.PublicKey),
	}, nil
}

// SignRequest holds the parameters for a sign request.
type SignRequest struct {
	DerivationPath  string                `json:"derivationPath"`
	To              []string              `json:"to"`
	Value           string                `json:"value,omitempty"`
	Data            []byte                `json:"data,omitempty"`
	ChainID         string                `json:"chainId,omitempty"`
	GasLimit        uint64                `json:"gasLimit,omitempty"`
	GasPrice        string                `json:"gasPrice,omitempty"`
	Nonce           uint64                `json:"nonce,omitempty"`
	RpcURL          string                `json:"rpcUrl,omitempty"`
	Mint            string                `json:"mint,omitempty"`
	Instructions    []vm.SolanaInstruction `json:"instructions,omitempty"`
	Program         string                 `json:"program,omitempty"`
	Method          string                 `json:"method,omitempty"`
	Args            map[string]string      `json:"args,omitempty"`
	Prefix          string                 `json:"prefix,omitempty"`
	Denom           string                 `json:"denom,omitempty"`
	AccountNumber   uint64                 `json:"accountNumber,omitempty"`
	Sequence        uint64                 `json:"sequence,omitempty"`
	Fee             string                 `json:"fee,omitempty"`
	Gas             uint64                 `json:"gas,omitempty"`
	Memo            string                 `json:"memo,omitempty"`
}

// SignResult holds the result of a sign request.
type SignResult struct {
	TxID     string `json:"txId,omitempty"`
	Status   string `json:"status"`
	SignedTx string `json:"signedTx,omitempty"` // 0x-prefixed hex RLP
	Reason   string `json:"reason,omitempty"`
}

// Sign constructs a transaction, sends it to Party B for review, and returns the result.
func (s *Service) Sign(ctx context.Context, req *SignRequest) (*SignResult, error) {
	adapter, ok := s.vmRegistry.ForPath(req.DerivationPath)
	if !ok {
		return nil, fmt.Errorf("no adapter registered for path %s", req.DerivationPath)
	}

	// Get the derived key to find the sender address
	derivedKey, err := s.store.GetDerivedKey(ctx, req.DerivationPath)
	if err != nil {
		return nil, fmt.Errorf("get derived key: %w", err)
	}

	// Build the unsigned transaction
	txReq := &vm.TxRequest{
		From:            derivedKey.Address,
		PubKey:          derivedKey.PublicKey,
		To:              req.To,
		Value:           req.Value,
		Data:            req.Data,
		DerivationPath:  req.DerivationPath,
		Prefix:          req.Prefix,
		Denom:           req.Denom,
		AccountNumber:   req.AccountNumber,
		Sequence:        req.Sequence,
		Fee:             req.Fee,
		Gas:             req.Gas,
		Memo:            req.Memo,
		ChainID:         req.ChainID,
		GasLimit:        req.GasLimit,
		GasPrice:        req.GasPrice,
		Nonce:           req.Nonce,
		RpcURL:          req.RpcURL,
		Mint:            req.Mint,
		Instructions:    req.Instructions,
		Program:         req.Program,
		Method:          req.Method,
		Args:            req.Args,
	}
	unsignedTx, err := adapter.BuildUnsignedTx(ctx, txReq)
	if err != nil {
		return nil, fmt.Errorf("build unsigned tx: %w", err)
	}

	// Extract signable bytes (the hash that both parties must sign).
	signableBytes, err := adapter.ExtractSignableBytes(unsignedTx.RawBytes)
	if err != nil {
		return nil, fmt.Errorf("extract signable bytes: %w", err)
	}

	// Send sign request to Party B
	payload := transport.SignRequestPayload{
		To:             req.To,
		Value:          req.Value,
		Data:           fmt.Sprintf("%x", req.Data),
		DerivationPath: req.DerivationPath,
		UnsignedTx:     base64.StdEncoding.EncodeToString(unsignedTx.RawBytes),
		SignableBytes:  base64.StdEncoding.EncodeToString(signableBytes),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal sign request: %w", err)
	}

	resp, err := s.transport.SendAndReceive(ctx, &transport.Message{
		Type:    transport.MsgSignRequest,
		ID:      s.nextMsgID(),
		Payload: payloadBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("send sign request: %w", err)
	}

	var signResp transport.SignResponsePayload
	if err := json.Unmarshal(resp.Payload, &signResp); err != nil {
		return nil, fmt.Errorf("unmarshal sign response: %w", err)
	}

	switch signResp.Decision {
	case "approve":
		// Party B approved — run TSS signing (Party B is also running its side).
		signedTx, err := s.runTSSSigning(ctx, adapter, derivedKey, unsignedTx, req.RpcURL, signResp.TxID)
		if err != nil {
			return nil, fmt.Errorf("TSS signing: %w", err)
		}

		return &SignResult{
			Status:   "signed",
			SignedTx: "0x" + hex.EncodeToString(signedTx),
			Reason:   signResp.Reason,
		}, nil

	case "reject":
		return &SignResult{
			Status: "rejected",
			Reason: signResp.Reason,
		}, nil

	case "escalate":
		// Store as pending for human review
		txID := signResp.TxID
		s.escalation.Add(txID, signResp.Reason, unsignedTx.RawBytes, req.RpcURL, unsignedTx.ExtraSignerKeys)

		// Persist to store
		to := req.To
		if to == nil {
			to = []string{}
		}
		txRecord := &store.TxRecord{
			ID:             txID,
			DerivationPath: req.DerivationPath,
			To:             to,
			Value:          req.Value,
			UnsignedTx:     unsignedTx.RawBytes,
			Status:         store.TxStatusPending,
			Reason:         signResp.Reason,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}
		if err := s.store.SaveTx(ctx, txRecord); err != nil {
			return nil, fmt.Errorf("save pending tx: %w", err)
		}

		return &SignResult{
			TxID:   txID,
			Status: "pending_review",
			Reason: signResp.Reason,
		}, nil

	default:
		return nil, fmt.Errorf("unknown decision: %s", signResp.Decision)
	}
}

// runTSSSigning executes the TSS signing protocol with Party B and assembles the signed tx.
// For Solana transactions, if rpcURL is set, a fresh blockhash is fetched and injected
// into the transaction right before signing to avoid blockhash expiry.
func (s *Service) runTSSSigning(ctx context.Context, adapter vm.Adapter, derivedKey *store.DerivedKeyRecord, unsignedTx *vm.UnsignedTx, rpcURL string, txID string) ([]byte, error) {
	// For Solana: fetch fresh blockhash and inject before signing.
	if rpcURL != "" && adapter.Name() == "solana" {
		blockhash, err := solanarpc.FetchRecentBlockhash(ctx, rpcURL)
		if err != nil {
			return nil, fmt.Errorf("fetch recent blockhash: %w", err)
		}
		updated, err := solanarpc.InjectBlockhash(unsignedTx.RawBytes, blockhash)
		if err != nil {
			return nil, fmt.Errorf("inject blockhash: %w", err)
		}
		unsignedTx.RawBytes = updated
	}

	signableBytes, err := adapter.ExtractSignableBytes(unsignedTx.RawBytes)
	if err != nil {
		return nil, fmt.Errorf("extract signable bytes: %w", err)
	}

	// Send final signable bytes to Party B so both parties sign the same message.
	readyPayload, _ := json.Marshal(transport.SignReadyPayload{
		TxID:          txID,
		SignableBytes: base64.StdEncoding.EncodeToString(signableBytes),
	})
	if _, err := s.transport.SendAndReceive(ctx, &transport.Message{
		Type:    transport.MsgSignReady,
		ID:      s.nextMsgID(),
		Payload: readyPayload,
	}); err != nil {
		return nil, fmt.Errorf("send sign-ready to Party B: %w", err)
	}

	signReq := tss.SignRequest{
		DerivationPath: derivedKey.DerivationPath,
		Message:        signableBytes,
		Curve:          derivedKey.Curve,
	}

	parties := []tss.PartyID{
		{ID: "party-a", Index: 0},
		{ID: "party-b", Index: 1},
	}
	partyID := tss.PartyID{ID: "party-a", Index: 0}

	sig, err := s.tssProto.Sign(ctx, signReq, derivedKey.Share, partyID, parties, s.tssRouter)
	if err != nil {
		return nil, fmt.Errorf("TSS sign: %w", err)
	}

	// If there are extra signer keys (Solana ephemeral keypairs), use the
	// extended assembly that signs with them too.
	var signedTx []byte
	if len(unsignedTx.ExtraSignerKeys) > 0 && adapter.Name() == "solana" {
		signedTx, err = solanarpc.AssembleSignedTxWithExtra(unsignedTx.RawBytes, sig, unsignedTx.ExtraSignerKeys)
	} else {
		signedTx, err = adapter.AssembleSignedTx(unsignedTx.RawBytes, sig)
	}
	if err != nil {
		return nil, fmt.Errorf("assemble signed tx: %w", err)
	}

	return signedTx, nil
}

// HandleSignApproved is called when Party B pushes a MsgSignApproved notification
// after the user approves an escalated transaction via Telegram.
func (s *Service) HandleSignApproved(ctx context.Context, txID, derivationPath string) {
	// Look up the pending tx.
	pending, ok := s.escalation.Get(txID)
	if !ok {
		slog.Error("sign-approved: pending tx not found in escalation queue", "txID", txID)
		return
	}

	// Look up adapter and key.
	adapter, ok := s.vmRegistry.ForPath(derivationPath)
	if !ok {
		slog.Error("sign-approved: no adapter for path", "txID", txID, "path", derivationPath)
		s.escalation.Update(txID, store.TxStatusRejected, nil)
		return
	}

	derivedKey, err := s.store.GetDerivedKey(ctx, derivationPath)
	if err != nil {
		slog.Error("sign-approved: get derived key failed", "txID", txID, "path", derivationPath, "err", err)
		s.escalation.Update(txID, store.TxStatusRejected, nil)
		return
	}

	unsignedTx := &vm.UnsignedTx{
		RawBytes:        pending.UnsignedTx,
		ExtraSignerKeys: pending.ExtraSignerKeys,
	}

	// Run TSS signing (Party B is also running its side).
	// For Solana, pending.RpcURL is used to fetch a fresh blockhash.
	signedTx, err := s.runTSSSigning(ctx, adapter, derivedKey, unsignedTx, pending.RpcURL, txID)
	if err != nil {
		slog.Error("sign-approved: TSS signing failed", "txID", txID, "err", err)
		s.escalation.Update(txID, store.TxStatusRejected, nil)
		return
	}

	s.escalation.Update(txID, store.TxStatusSigned, signedTx)

	// Also persist to store.
	_ = s.store.UpdateTxStatus(ctx, txID, store.TxStatusSigned, signedTx)
}

// GetSignStatus retrieves the status of an escalated transaction.
func (s *Service) GetSignStatus(ctx context.Context, txID string) (*SignResult, error) {
	// Check in-memory queue first
	if pending, ok := s.escalation.Get(txID); ok {
		// If still pending, query Party B for the latest status.
		if pending.Status == store.TxStatusPending {
			if updated := s.queryPartyBTxStatus(ctx, txID); updated != nil {
				return updated, nil
			}
		}

		result := &SignResult{
			TxID:   txID,
			Status: string(pending.Status),
			Reason: pending.Reason,
		}
		if pending.SignedTx != nil {
			result.SignedTx = "0x" + hex.EncodeToString(pending.SignedTx)
			if pending.Status == store.TxStatusSigned {
				s.escalation.Delete(txID)
			}
		}
		return result, nil
	}

	// Fall back to store
	txRecord, err := s.store.GetTx(ctx, txID)
	if err != nil {
		return nil, fmt.Errorf("get tx: %w", err)
	}

	result := &SignResult{
		TxID:   txRecord.ID,
		Status: string(txRecord.Status),
		Reason: txRecord.Reason,
	}
	if txRecord.SignedTx != nil {
		result.SignedTx = "0x" + hex.EncodeToString(txRecord.SignedTx)
		if txRecord.Status == store.TxStatusSigned {
			_ = s.store.DeleteTx(ctx, txID)
		}
	}
	return result, nil
}

// queryPartyBTxStatus queries Party B for the latest status of an escalated transaction.
func (s *Service) queryPartyBTxStatus(ctx context.Context, txID string) *SignResult {
	reqPayload, _ := json.Marshal(map[string]string{"txId": txID})
	resp, err := s.transport.SendAndReceive(ctx, &transport.Message{
		Type:    transport.MsgTxStatusReq,
		ID:      s.nextMsgID(),
		Payload: reqPayload,
	})
	if err != nil {
		return nil
	}

	var statusResp transport.TxStatusResponsePayload
	if err := json.Unmarshal(resp.Payload, &statusResp); err != nil {
		return nil
	}

	if statusResp.Status == "unknown" {
		return nil
	}

	// Update the in-memory escalation queue with Party B's status.
	var signedTx []byte
	if statusResp.SignedTx != "" {
		signedTx, _ = base64.StdEncoding.DecodeString(statusResp.SignedTx)
	}
	s.escalation.Update(txID, store.TxStatus(statusResp.Status), signedTx)

	result := &SignResult{
		TxID:   txID,
		Status: statusResp.Status,
		Reason: statusResp.Reason,
	}
	if signedTx != nil {
		result.SignedTx = "0x" + hex.EncodeToString(signedTx)
		if statusResp.Status == string(store.TxStatusSigned) {
			s.escalation.Delete(txID)
		}
	}
	return result
}

// KeyInfo holds information about a derived key.
type KeyInfo struct {
	DerivationPath string `json:"-"`
	Address        string `json:"address"`
	PubKey         string `json:"pubKey"`
	Label          string `json:"label"`
}

// ListKeys returns all derived keys.
func (s *Service) ListKeys(ctx context.Context) ([]KeyInfo, error) {
	records, err := s.store.ListDerivedKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("list derived keys: %w", err)
	}

	keys := make([]KeyInfo, len(records))
	for i, r := range records {
		keys[i] = KeyInfo{
			DerivationPath: r.DerivationPath,
			Address:        r.Address,
			PubKey:         fmt.Sprintf("0x%x", r.PublicKey),
			Label:          r.Label,
		}
	}
	return keys, nil
}

// HealthStatus holds the health check result.
type HealthStatus struct {
	Status               string `json:"status"`
	SecureServerConnected bool   `json:"secureServerConnected"`
}

// Health performs a health check including Party B connectivity.
func (s *Service) Health(ctx context.Context) *HealthStatus {
	status := &HealthStatus{
		Status: "ok",
	}

	// Check Party B connectivity
	resp, err := s.transport.SendAndReceive(ctx, &transport.Message{
		Type: transport.MsgHealthCheck,
		ID:   s.nextMsgID(),
	})
	if err != nil || resp == nil {
		status.SecureServerConnected = false
	} else {
		status.SecureServerConnected = true
	}

	return status
}
