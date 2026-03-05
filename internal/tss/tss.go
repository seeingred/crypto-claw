package tss

import (
	"context"
	"crypto/ecdsa"
	"math/big"
)

// Curve represents the supported elliptic curves.
type Curve string

const (
	CurveSecp256k1 Curve = "secp256k1" // ECDSA for EVM, Cosmos
	CurveEd25519   Curve = "ed25519"   // EdDSA for Solana
)

// PartyID identifies a participant in the TSS protocol.
type PartyID struct {
	ID    string // unique identifier
	Index int    // 0-based index in the party set
}

// KeyShare holds a party's share of the master key after DKG.
type KeyShare struct {
	Curve     Curve    `json:"curve"`
	PartyID   PartyID  `json:"partyId"`
	Share     []byte   `json:"share"`     // serialized tss-lib local party save data
	PublicKey []byte   `json:"publicKey"` // full public key (uncompressed)
	ChainCode []byte  `json:"chainCode"` // for HD derivation (BIP-32 chain code)
}

// DerivedKey holds a child key derived from the master key.
type DerivedKey struct {
	Curve          Curve  `json:"curve"`
	DerivationPath string `json:"derivationPath"`
	Share          []byte `json:"share"`     // derived child share
	PublicKey      []byte `json:"publicKey"` // derived child public key
	Address        string `json:"address"`   // chain-specific address
}

// SignRequest represents a request to sign data.
type SignRequest struct {
	DerivationPath string `json:"derivationPath"`
	Message        []byte `json:"message"` // hash to sign
	Curve          Curve  `json:"curve"`
}

// Signature holds the result of a TSS signing operation.
type Signature struct {
	R     *big.Int `json:"r"`
	S     *big.Int `json:"s"`
	V     byte     `json:"v,omitempty"` // recovery ID for ECDSA
	Bytes []byte   `json:"bytes"`       // full serialized signature
}

// MessageRouter handles sending/receiving TSS protocol messages between parties.
type MessageRouter interface {
	// Send sends a protocol message to the specified party.
	Send(ctx context.Context, to PartyID, msg []byte) error
	// Receive returns a channel for incoming protocol messages.
	Receive() <-chan IncomingMessage
}

// IncomingMessage wraps a received protocol message.
type IncomingMessage struct {
	From    PartyID
	Payload []byte
}

// Protocol defines the TSS operations.
type Protocol interface {
	// DKG runs the distributed key generation ceremony.
	// Returns key shares for this party.
	DKG(ctx context.Context, curve Curve, partyID PartyID, parties []PartyID, router MessageRouter) (*KeyShare, error)

	// DeriveKey derives a child key from a master key share using HD derivation.
	DeriveKey(ctx context.Context, masterShare *KeyShare, derivationPath string) (*DerivedKey, error)

	// Sign performs threshold signing using the derived key share.
	Sign(ctx context.Context, req SignRequest, keyShare []byte, partyID PartyID, parties []PartyID, router MessageRouter) (*Signature, error)

	// Reshare performs key resharing to rotate shares without changing the public key.
	Reshare(ctx context.Context, curve Curve, oldShare *KeyShare, partyID PartyID, oldParties, newParties []PartyID, router MessageRouter) (*KeyShare, error)
}

// ECDSAPublicKey converts an uncompressed public key bytes to an ecdsa.PublicKey.
func ECDSAPublicKey(pubKeyBytes []byte) (*ecdsa.PublicKey, error) {
	if len(pubKeyBytes) != 65 || pubKeyBytes[0] != 0x04 {
		return nil, ErrInvalidPublicKey
	}
	x := new(big.Int).SetBytes(pubKeyBytes[1:33])
	y := new(big.Int).SetBytes(pubKeyBytes[33:65])
	return &ecdsa.PublicKey{
		X: x,
		Y: y,
	}, nil
}

// Errors
var (
	ErrInvalidPublicKey = &TSSError{Code: "INVALID_PUBLIC_KEY", Message: "invalid public key format"}
	ErrDKGFailed        = &TSSError{Code: "DKG_FAILED", Message: "distributed key generation failed"}
	ErrSigningFailed    = &TSSError{Code: "SIGNING_FAILED", Message: "threshold signing failed"}
	ErrDerivationFailed = &TSSError{Code: "DERIVATION_FAILED", Message: "key derivation failed"}
	ErrResharingFailed  = &TSSError{Code: "RESHARING_FAILED", Message: "key resharing failed"}
)

type TSSError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Cause   error  `json:"-"`
}

func (e *TSSError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

func (e *TSSError) Unwrap() error { return e.Cause }

func (e *TSSError) WithCause(err error) *TSSError {
	return &TSSError{Code: e.Code, Message: e.Message, Cause: err}
}
