package store

import (
	"context"
	"time"

	"github.com/seeingred/crypto-claw/internal/tss"
)

// Store defines the persistence interface for key shares, transaction history, and whitelist.
type Store interface {
	KeyStore
	TxStore
	WhitelistStore
	Close() error
}

// KeyStore manages encrypted key shares.
type KeyStore interface {
	// SaveMasterShare stores a master key share (encrypted).
	SaveMasterShare(ctx context.Context, share *tss.KeyShare) error

	// GetMasterShare retrieves a master key share by curve.
	GetMasterShare(ctx context.Context, curve tss.Curve) (*tss.KeyShare, error)

	// SaveDerivedKey stores a derived child key.
	SaveDerivedKey(ctx context.Context, key *DerivedKeyRecord) error

	// GetDerivedKey retrieves a derived key by path.
	GetDerivedKey(ctx context.Context, derivationPath string) (*DerivedKeyRecord, error)

	// ListDerivedKeys returns all derived keys.
	ListDerivedKeys(ctx context.Context) ([]*DerivedKeyRecord, error)

	// UpdateLabel updates the label for a derived key.
	UpdateLabel(ctx context.Context, derivationPath string, label string) error

	// ClearDerivedKeys removes all derived keys (used when master keys change).
	ClearDerivedKeys(ctx context.Context) error
}

// TxStore manages transaction history.
type TxStore interface {
	// SaveTx stores a transaction record.
	SaveTx(ctx context.Context, tx *TxRecord) error

	// GetTx retrieves a transaction by ID.
	GetTx(ctx context.Context, txID string) (*TxRecord, error)

	// UpdateTxStatus updates a transaction's status and optionally its signed data.
	UpdateTxStatus(ctx context.Context, txID string, status TxStatus, signedTx []byte) error

	// ListTxs returns transactions with optional filtering.
	ListTxs(ctx context.Context, filter TxFilter) ([]*TxRecord, error)

	// DeleteTx removes a transaction record (after bot retrieval).
	DeleteTx(ctx context.Context, txID string) error
}

// DerivedKeyRecord is the stored form of a derived key.
type DerivedKeyRecord struct {
	DerivationPath string    `json:"derivationPath"`
	Curve          tss.Curve `json:"curve"`
	PublicKey      []byte    `json:"publicKey"`
	Address        string    `json:"address"`
	Label          string    `json:"label"`
	Share          []byte    `json:"share"` // encrypted child share
	CreatedAt      time.Time `json:"createdAt"`
}

// TxStatus represents the state of a signing request.
type TxStatus string

const (
	TxStatusPending  TxStatus = "pending_review"
	TxStatusApproved TxStatus = "approved"
	TxStatusRejected TxStatus = "rejected"
	TxStatusSigned   TxStatus = "signed"
)

// TxRecord represents a transaction in the store.
type TxRecord struct {
	ID             string    `json:"id"`
	DerivationPath string    `json:"derivationPath"`
	To             []string  `json:"to"`
	Value          string    `json:"value,omitempty"`
	Data           string    `json:"data,omitempty"`
	UnsignedTx     []byte    `json:"unsignedTx"`
	SignedTx       []byte    `json:"signedTx,omitempty"`
	Status         TxStatus  `json:"status"`
	Reason         string    `json:"reason,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// TxFilter controls transaction listing.
type TxFilter struct {
	Status         *TxStatus
	DerivationPath *string
	Limit          int
	Offset         int
}

// WhitelistEntry represents a whitelisted address.
type WhitelistEntry struct {
	Address string    `json:"address"`
	Label   string    `json:"label"`
	AddedAt time.Time `json:"addedAt"`
}

// WhitelistStore manages the address whitelist.
type WhitelistStore interface {
	AddWhitelistEntry(ctx context.Context, entry *WhitelistEntry) error
	RemoveWhitelistEntry(ctx context.Context, address string) error
	IsWhitelisted(ctx context.Context, address string) (bool, error)
	GetWhitelistEntry(ctx context.Context, address string) (*WhitelistEntry, error)
	ListWhitelist(ctx context.Context) ([]*WhitelistEntry, error)
}
