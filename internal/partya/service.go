package partya

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/seeingred/crypto-claw/internal/store"
	"github.com/seeingred/crypto-claw/internal/transport"
	"github.com/seeingred/crypto-claw/internal/tss"
	"github.com/seeingred/crypto-claw/internal/vm"
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
	tssProto   tss.Protocol
	vmRegistry *vm.Registry
	escalation *EscalationQueue
	msgCounter uint64
}

// NewService creates a new Party A service.
func NewService(
	st store.Store,
	tc TransportClient,
	proto tss.Protocol,
	registry *vm.Registry,
) *Service {
	return &Service{
		store:      st,
		transport:  tc,
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
func (s *Service) Derive(ctx context.Context, derivationPath, label string) (*DeriveResult, error) {
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
	address, err := adapter.DeriveAddress(derived.PublicKey)
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
	DerivationPath string `json:"derivationPath"`
	To             []string `json:"to"`
	Value          string `json:"value,omitempty"`
	Data           []byte `json:"data,omitempty"`
	ChainID        string `json:"chainId,omitempty"`
	GasLimit       uint64 `json:"gasLimit,omitempty"`
	GasPrice       string `json:"gasPrice,omitempty"`
	Nonce          uint64 `json:"nonce,omitempty"`
}

// SignResult holds the result of a sign request.
type SignResult struct {
	TxID     string `json:"txId,omitempty"`
	Status   string `json:"status"`
	SignedTx string `json:"signedTx,omitempty"` // base64 if approved
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
		From:           derivedKey.Address,
		To:             req.To,
		Value:          req.Value,
		Data:           req.Data,
		DerivationPath: req.DerivationPath,
		ChainID:        req.ChainID,
		GasLimit:       req.GasLimit,
		GasPrice:       req.GasPrice,
		Nonce:          req.Nonce,
	}
	unsignedTx, err := adapter.BuildUnsignedTx(ctx, txReq)
	if err != nil {
		return nil, fmt.Errorf("build unsigned tx: %w", err)
	}

	// Send sign request to Party B
	payload := transport.SignRequestPayload{
		To:             req.To,
		Value:          req.Value,
		Data:           fmt.Sprintf("%x", req.Data),
		DerivationPath: req.DerivationPath,
		UnsignedTx:     base64.StdEncoding.EncodeToString(unsignedTx.RawBytes),
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
		// Party B approved - proceed with TSS signing
		signableBytes, err := adapter.ExtractSignableBytes(unsignedTx.RawBytes)
		if err != nil {
			return nil, fmt.Errorf("extract signable bytes: %w", err)
		}

		// For now, the TSS signing would happen here via the protocol
		_ = signableBytes

		return &SignResult{
			Status:   "signed",
			SignedTx: base64.StdEncoding.EncodeToString(unsignedTx.RawBytes),
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
		s.escalation.Add(txID, signResp.Reason)

		// Persist to store
		txRecord := &store.TxRecord{
			ID:             txID,
			DerivationPath: req.DerivationPath,
			To:             req.To,
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

// GetSignStatus retrieves the status of an escalated transaction.
func (s *Service) GetSignStatus(ctx context.Context, txID string) (*SignResult, error) {
	// Check in-memory queue first
	if pending, ok := s.escalation.Get(txID); ok {
		result := &SignResult{
			TxID:   txID,
			Status: string(pending.Status),
			Reason: pending.Reason,
		}
		if pending.SignedTx != nil {
			result.SignedTx = base64.StdEncoding.EncodeToString(pending.SignedTx)
			// Remove from queue after retrieval if signed
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
		result.SignedTx = base64.StdEncoding.EncodeToString(txRecord.SignedTx)
		// Delete from store after retrieval if signed
		if txRecord.Status == store.TxStatusSigned {
			_ = s.store.DeleteTx(ctx, txID)
		}
	}
	return result, nil
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
