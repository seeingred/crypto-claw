package partya

import (
	"sync"

	"github.com/seeingred/crypto-claw/internal/store"
)

// PendingTx represents an escalated transaction awaiting human review.
type PendingTx struct {
	TxID   string         `json:"txId"`
	Status store.TxStatus `json:"status"`
	Reason string         `json:"reason,omitempty"`
	// SignedTx holds the signed transaction bytes once approved and signed.
	SignedTx []byte `json:"signedTx,omitempty"`
}

// EscalationQueue manages in-memory pending escalated transactions.
type EscalationQueue struct {
	mu      sync.RWMutex
	pending map[string]*PendingTx
}

// NewEscalationQueue creates a new thread-safe escalation queue.
func NewEscalationQueue() *EscalationQueue {
	return &EscalationQueue{
		pending: make(map[string]*PendingTx),
	}
}

// Add adds a new pending transaction to the queue.
func (q *EscalationQueue) Add(txID, reason string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.pending[txID] = &PendingTx{
		TxID:   txID,
		Status: store.TxStatusPending,
		Reason: reason,
	}
}

// Get retrieves a pending transaction by ID.
func (q *EscalationQueue) Get(txID string) (*PendingTx, bool) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	p, ok := q.pending[txID]
	return p, ok
}

// Update updates the status and optionally the signed tx for a pending transaction.
func (q *EscalationQueue) Update(txID string, status store.TxStatus, signedTx []byte) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	p, ok := q.pending[txID]
	if !ok {
		return false
	}
	p.Status = status
	if signedTx != nil {
		p.SignedTx = signedTx
	}
	return true
}

// Delete removes a pending transaction from the queue.
func (q *EscalationQueue) Delete(txID string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.pending, txID)
}

// List returns all pending transactions.
func (q *EscalationQueue) List() []*PendingTx {
	q.mu.RLock()
	defer q.mu.RUnlock()
	result := make([]*PendingTx, 0, len(q.pending))
	for _, p := range q.pending {
		result = append(result, p)
	}
	return result
}
