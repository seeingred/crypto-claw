package tss

import (
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	edkeygen "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// TSSProtocol implements the Protocol interface using bnb-chain/tss-lib.
type TSSProtocol struct {
	Threshold int // t in (t, n) threshold scheme; defaults to n-1 (2-of-2) if 0
	// GetPreParams optionally returns cached pre-params for a party (speeds up DKG in tests).
	GetPreParams func(partyID PartyID) (*keygen.LocalPreParams, error)
}

// NewProtocol creates a new TSS protocol handler.
func NewProtocol(threshold int) *TSSProtocol {
	return &TSSProtocol{Threshold: threshold}
}

// DKG runs distributed key generation for the specified curve.
func (p *TSSProtocol) DKG(ctx context.Context, curve Curve, partyID PartyID, parties []PartyID, router MessageRouter) (*KeyShare, error) {
	threshold := p.Threshold
	if threshold == 0 {
		threshold = len(parties) - 1
	}

	switch curve {
	case CurveSecp256k1:
		return p.dkgECDSA(ctx, partyID, parties, threshold, router)
	case CurveEd25519:
		return p.dkgEdDSA(ctx, partyID, parties, threshold, router)
	default:
		return nil, ErrDKGFailed.WithCause(fmt.Errorf("unsupported curve: %s", curve))
	}
}

func makeSortedPartyIDs(parties []PartyID) tss.SortedPartyIDs {
	// Sort parties by ID for deterministic ordering.
	sorted := make([]PartyID, len(parties))
	copy(sorted, parties)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	unsorted := make(tss.UnSortedPartyIDs, len(sorted))
	for i, p := range sorted {
		key := new(big.Int).SetBytes([]byte(p.ID))
		unsorted[i] = tss.NewPartyID(p.ID, fmt.Sprintf("party-%d", p.Index), key)
		_ = i
	}
	return tss.SortPartyIDs(unsorted)
}

func findPartyID(sortedIDs tss.SortedPartyIDs, id string) *tss.PartyID {
	for _, pid := range sortedIDs {
		if pid.Id == id {
			return pid
		}
	}
	return nil
}

func (p *TSSProtocol) dkgECDSA(ctx context.Context, partyID PartyID, parties []PartyID, threshold int, router MessageRouter) (*KeyShare, error) {
	sortedIDs := makeSortedPartyIDs(parties)
	thisParty := findPartyID(sortedIDs, partyID.ID)
	if thisParty == nil {
		return nil, ErrDKGFailed.WithCause(fmt.Errorf("party %s not found in party list", partyID.ID))
	}

	peerCtx := tss.NewPeerContext(sortedIDs)
	params := tss.NewParameters(tss.S256(), peerCtx, thisParty, len(sortedIDs), threshold)

	outCh := make(chan tss.Message, len(sortedIDs)*20)
	endCh := make(chan *keygen.LocalPartySaveData, 1)
	errCh := make(chan *tss.Error, 1)

	// Get or generate safe primes for key generation.
	var preParams *keygen.LocalPreParams
	if p.GetPreParams != nil {
		var ppErr error
		preParams, ppErr = p.GetPreParams(partyID)
		if ppErr != nil {
			return nil, ErrDKGFailed.WithCause(fmt.Errorf("get pre-params: %w", ppErr))
		}
	} else {
		var ppErr error
		preParams, ppErr = keygen.GeneratePreParams(10 * time.Minute)
		if ppErr != nil {
			return nil, ErrDKGFailed.WithCause(fmt.Errorf("generate pre-params: %w", ppErr))
		}
	}

	party := keygen.NewLocalParty(params, outCh, endCh, *preParams)

	go func() {
		if err := party.Start(); err != nil {
			errCh <- err
		}
	}()

	return p.runDKGLoop(ctx, CurveSecp256k1, party, sortedIDs, outCh, endCh, errCh, router)
}

func (p *TSSProtocol) dkgEdDSA(ctx context.Context, partyID PartyID, parties []PartyID, threshold int, router MessageRouter) (*KeyShare, error) {
	sortedIDs := makeSortedPartyIDs(parties)
	thisParty := findPartyID(sortedIDs, partyID.ID)
	if thisParty == nil {
		return nil, ErrDKGFailed.WithCause(fmt.Errorf("party %s not found in party list", partyID.ID))
	}

	peerCtx := tss.NewPeerContext(sortedIDs)
	params := tss.NewParameters(tss.Edwards(), peerCtx, thisParty, len(sortedIDs), threshold)

	outCh := make(chan tss.Message, len(sortedIDs)*20)
	endCh := make(chan *edkeygen.LocalPartySaveData, 1)
	errCh := make(chan *tss.Error, 1)

	party := edkeygen.NewLocalParty(params, outCh, endCh)

	go func() {
		if err := party.Start(); err != nil {
			errCh <- err
		}
	}()

	return p.runEdDSADKGLoop(ctx, party, sortedIDs, outCh, endCh, errCh, router)
}

func (p *TSSProtocol) runDKGLoop(
	ctx context.Context,
	curve Curve,
	party tss.Party,
	sortedIDs tss.SortedPartyIDs,
	outCh <-chan tss.Message,
	endCh <-chan *keygen.LocalPartySaveData,
	errCh <-chan *tss.Error,
	router MessageRouter,
) (*KeyShare, error) {
	// Route outgoing messages in a dedicated goroutine to prevent deadlock.
	// When UpdateFromBytes triggers a new round, the party sends to outCh.
	// If the main loop is blocked in handleIncoming at that moment, outCh
	// could fill up and block the party, causing a deadlock.
	routeErrCh := make(chan error, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-outCh:
				if !ok {
					return
				}
				if err := routeMessage(ctx, msg, sortedIDs, router); err != nil {
					routeErrCh <- err
					return
				}
			}
		}
	}()

	incoming := router.Receive()

	for {
		select {
		case <-ctx.Done():
			return nil, ErrDKGFailed.WithCause(ctx.Err())

		case err := <-errCh:
			return nil, ErrDKGFailed.WithCause(fmt.Errorf("tss error: %s", err.Error()))

		case err := <-routeErrCh:
			return nil, ErrDKGFailed.WithCause(fmt.Errorf("route error: %w", err))

		case incoming, ok := <-incoming:
			if !ok {
				return nil, ErrDKGFailed.WithCause(fmt.Errorf("incoming channel closed"))
			}
			if err := handleIncoming(party, incoming, sortedIDs); err != nil {
				return nil, ErrDKGFailed.WithCause(err)
			}

		case save := <-endCh:
			return marshalECDSAKeyShare(curve, party.PartyID(), save)
		}
	}
}

func (p *TSSProtocol) runEdDSADKGLoop(
	ctx context.Context,
	party tss.Party,
	sortedIDs tss.SortedPartyIDs,
	outCh <-chan tss.Message,
	endCh <-chan *edkeygen.LocalPartySaveData,
	errCh <-chan *tss.Error,
	router MessageRouter,
) (*KeyShare, error) {
	routeErrCh := make(chan error, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-outCh:
				if !ok {
					return
				}
				if err := routeMessage(ctx, msg, sortedIDs, router); err != nil {
					routeErrCh <- err
					return
				}
			}
		}
	}()

	incoming := router.Receive()

	for {
		select {
		case <-ctx.Done():
			return nil, ErrDKGFailed.WithCause(ctx.Err())

		case err := <-errCh:
			return nil, ErrDKGFailed.WithCause(fmt.Errorf("tss error: %s", err.Error()))

		case err := <-routeErrCh:
			return nil, ErrDKGFailed.WithCause(fmt.Errorf("route error: %w", err))

		case incoming, ok := <-incoming:
			if !ok {
				return nil, ErrDKGFailed.WithCause(fmt.Errorf("incoming channel closed"))
			}
			if err := handleIncoming(party, incoming, sortedIDs); err != nil {
				return nil, ErrDKGFailed.WithCause(err)
			}

		case save := <-endCh:
			return marshalEdDSAKeyShare(party.PartyID(), save)
		}
	}
}

// routeMessage serializes a tss.Message and sends it via the router.
func routeMessage(ctx context.Context, msg tss.Message, sortedIDs tss.SortedPartyIDs, router MessageRouter) error {
	bytes, routing, err := msg.WireBytes()
	if err != nil {
		return fmt.Errorf("wire bytes: %w", err)
	}

	wireMsg := &wireMessage{
		From:        msg.GetFrom().Id,
		IsBroadcast: routing.IsBroadcast,
		Payload:     bytes,
	}
	data, err := json.Marshal(wireMsg)
	if err != nil {
		return fmt.Errorf("marshal wire message: %w", err)
	}

	if routing.IsBroadcast {
		for _, pid := range sortedIDs {
			if pid.Id == msg.GetFrom().Id {
				continue
			}
			if err := router.Send(ctx, PartyID{ID: pid.Id, Index: pid.Index}, data); err != nil {
				return fmt.Errorf("send to %s: %w", pid.Id, err)
			}
		}
	} else {
		for _, to := range routing.To {
			if err := router.Send(ctx, PartyID{ID: to.Id, Index: to.Index}, data); err != nil {
				return fmt.Errorf("send to %s: %w", to.Id, err)
			}
		}
	}
	return nil
}

// handleIncoming deserializes and feeds an incoming message to the party.
func handleIncoming(party tss.Party, incoming IncomingMessage, sortedIDs tss.SortedPartyIDs) error {
	var wireMsg wireMessage
	if err := json.Unmarshal(incoming.Payload, &wireMsg); err != nil {
		return fmt.Errorf("unmarshal wire message: %w", err)
	}

	from := findPartyID(sortedIDs, wireMsg.From)
	if from == nil {
		return fmt.Errorf("unknown sender: %s", wireMsg.From)
	}

	_, err := party.UpdateFromBytes(wireMsg.Payload, from, wireMsg.IsBroadcast)
	if err != nil {
		return fmt.Errorf("update from bytes: %w", err)
	}
	return nil
}

type wireMessage struct {
	From        string `json:"from"`
	IsBroadcast bool   `json:"isBroadcast"`
	Payload     []byte `json:"payload"`
}

func marshalECDSAKeyShare(curve Curve, pid *tss.PartyID, save *keygen.LocalPartySaveData) (*KeyShare, error) {
	shareData, err := json.Marshal(save)
	if err != nil {
		return nil, ErrDKGFailed.WithCause(fmt.Errorf("marshal save data: %w", err))
	}

	// Extract public key in uncompressed format.
	pubKey := save.ECDSAPub
	x, y := pubKey.X(), pubKey.Y()
	pubKeyBytes := elliptic.Marshal(tss.S256(), x, y)

	// Derive chain code deterministically from the public key so both parties
	// compute the same value (required for HD derivation to be consistent).
	chainCode := sha256.Sum256(pubKeyBytes)

	return &KeyShare{
		Curve:     curve,
		PartyID:   PartyID{ID: pid.Id, Index: pid.Index},
		Share:     shareData,
		PublicKey: pubKeyBytes,
		ChainCode: chainCode[:],
	}, nil
}

func marshalEdDSAKeyShare(pid *tss.PartyID, save *edkeygen.LocalPartySaveData) (*KeyShare, error) {
	shareData, err := json.Marshal(save)
	if err != nil {
		return nil, ErrDKGFailed.WithCause(fmt.Errorf("marshal save data: %w", err))
	}

	// Extract EdDSA public key (32 bytes).
	pubKey := save.EDDSAPub
	pubKeyBytes := make([]byte, 32)
	xBytes := pubKey.X().Bytes()
	copy(pubKeyBytes[32-len(xBytes):], xBytes)

	chainCode := sha256.Sum256(pubKeyBytes)

	return &KeyShare{
		Curve:     CurveEd25519,
		PartyID:   PartyID{ID: pid.Id, Index: pid.Index},
		Share:     shareData,
		PublicKey: pubKeyBytes,
		ChainCode: chainCode[:],
	}, nil
}

// generateSafePreParams generates safe primes for ECDSA keygen.
// This is a CPU-intensive operation and should be cached.
func generateSafePreParams() (*keygen.LocalPreParams, error) {
	return keygen.GeneratePreParams(10 * time.Minute)
}

var _ Protocol = (*TSSProtocol)(nil)

// Ensure common is used (it's needed transitively).
var _ = common.GetRandomPositiveInt
