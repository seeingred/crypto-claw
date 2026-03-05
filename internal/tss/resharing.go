package tss

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/resharing"
	edkeygen "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	edresharing "github.com/bnb-chain/tss-lib/v2/eddsa/resharing"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// Reshare performs key resharing to rotate shares without changing the public key.
func (p *TSSProtocol) Reshare(ctx context.Context, curve Curve, oldShare *KeyShare, partyID PartyID, oldParties, newParties []PartyID, router MessageRouter) (*KeyShare, error) {
	threshold := p.Threshold
	if threshold == 0 {
		threshold = len(newParties) - 1
	}

	switch curve {
	case CurveSecp256k1:
		return p.reshareECDSA(ctx, oldShare, partyID, oldParties, newParties, threshold, router)
	case CurveEd25519:
		return p.reshareEdDSA(ctx, oldShare, partyID, oldParties, newParties, threshold, router)
	default:
		return nil, ErrResharingFailed.WithCause(fmt.Errorf("unsupported curve: %s", curve))
	}
}

func (p *TSSProtocol) reshareECDSA(ctx context.Context, oldShare *KeyShare, partyID PartyID, oldParties, newParties []PartyID, threshold int, router MessageRouter) (*KeyShare, error) {
	oldSortedIDs := makeSortedPartyIDs(oldParties)
	newSortedIDs := makeSortedPartyIDs(newParties)

	thisOldParty := findPartyID(oldSortedIDs, partyID.ID)
	thisNewParty := findPartyID(newSortedIDs, partyID.ID)

	// Determine if this party is in the old committee, new committee, or both.
	isOld := thisOldParty != nil
	isNew := thisNewParty != nil

	if !isOld && !isNew {
		return nil, ErrResharingFailed.WithCause(fmt.Errorf("party %s not in old or new committee", partyID.ID))
	}

	oldThreshold := len(oldParties) - 1
	newThreshold := threshold

	outCh := make(chan tss.Message, (len(oldParties)+len(newParties))*20)
	endCh := make(chan *keygen.LocalPartySaveData, 1)
	errCh := make(chan *tss.Error, 1)

	var party tss.Party

	if isOld {
		var save keygen.LocalPartySaveData
		if err := json.Unmarshal(oldShare.Share, &save); err != nil {
			return nil, ErrResharingFailed.WithCause(fmt.Errorf("unmarshal old share: %w", err))
		}

		oldPeerCtx := tss.NewPeerContext(oldSortedIDs)
		newPeerCtx := tss.NewPeerContext(newSortedIDs)
		params := tss.NewReSharingParameters(tss.S256(), oldPeerCtx, newPeerCtx, thisOldParty, len(oldSortedIDs), oldThreshold, len(newSortedIDs), newThreshold)

		party = resharing.NewLocalParty(params, save, outCh, endCh)
	} else {
		// New party with no old share.
		oldPeerCtx := tss.NewPeerContext(oldSortedIDs)
		newPeerCtx := tss.NewPeerContext(newSortedIDs)
		params := tss.NewReSharingParameters(tss.S256(), oldPeerCtx, newPeerCtx, thisNewParty, len(oldSortedIDs), oldThreshold, len(newSortedIDs), newThreshold)

		save := keygen.NewLocalPartySaveData(len(newSortedIDs))
		party = resharing.NewLocalParty(params, save, outCh, endCh)
	}

	go func() {
		if err := party.Start(); err != nil {
			errCh <- err
		}
	}()

	allSortedIDs := mergeSortedPartyIDs(oldSortedIDs, newSortedIDs)

	return p.runReshareECDSALoop(ctx, party, allSortedIDs, oldShare, outCh, endCh, errCh, router)
}

func (p *TSSProtocol) reshareEdDSA(ctx context.Context, oldShare *KeyShare, partyID PartyID, oldParties, newParties []PartyID, threshold int, router MessageRouter) (*KeyShare, error) {
	oldSortedIDs := makeSortedPartyIDs(oldParties)
	newSortedIDs := makeSortedPartyIDs(newParties)

	thisOldParty := findPartyID(oldSortedIDs, partyID.ID)
	thisNewParty := findPartyID(newSortedIDs, partyID.ID)

	isOld := thisOldParty != nil
	isNew := thisNewParty != nil

	if !isOld && !isNew {
		return nil, ErrResharingFailed.WithCause(fmt.Errorf("party %s not in old or new committee", partyID.ID))
	}

	oldThreshold := len(oldParties) - 1
	newThreshold := threshold

	outCh := make(chan tss.Message, (len(oldParties)+len(newParties))*20)
	endCh := make(chan *edkeygen.LocalPartySaveData, 1)
	errCh := make(chan *tss.Error, 1)

	var party tss.Party

	if isOld {
		var save edkeygen.LocalPartySaveData
		if err := json.Unmarshal(oldShare.Share, &save); err != nil {
			return nil, ErrResharingFailed.WithCause(fmt.Errorf("unmarshal old share: %w", err))
		}

		oldPeerCtx := tss.NewPeerContext(oldSortedIDs)
		newPeerCtx := tss.NewPeerContext(newSortedIDs)
		params := tss.NewReSharingParameters(tss.Edwards(), oldPeerCtx, newPeerCtx, thisOldParty, len(oldSortedIDs), oldThreshold, len(newSortedIDs), newThreshold)

		party = edresharing.NewLocalParty(params, save, outCh, endCh)
	} else {
		_ = isNew
		oldPeerCtx := tss.NewPeerContext(oldSortedIDs)
		newPeerCtx := tss.NewPeerContext(newSortedIDs)
		params := tss.NewReSharingParameters(tss.Edwards(), oldPeerCtx, newPeerCtx, thisNewParty, len(oldSortedIDs), oldThreshold, len(newSortedIDs), newThreshold)

		save := edkeygen.NewLocalPartySaveData(len(newSortedIDs))
		party = edresharing.NewLocalParty(params, save, outCh, endCh)
	}

	go func() {
		if err := party.Start(); err != nil {
			errCh <- err
		}
	}()

	allSortedIDs := mergeSortedPartyIDs(oldSortedIDs, newSortedIDs)

	return p.runReshareEdDSALoop(ctx, party, allSortedIDs, oldShare, outCh, endCh, errCh, router)
}

func (p *TSSProtocol) runReshareECDSALoop(
	ctx context.Context,
	party tss.Party,
	allSortedIDs tss.SortedPartyIDs,
	oldShare *KeyShare,
	outCh <-chan tss.Message,
	endCh <-chan *keygen.LocalPartySaveData,
	errCh <-chan *tss.Error,
	router MessageRouter,
) (*KeyShare, error) {
	incoming := router.Receive()

	for {
		select {
		case <-ctx.Done():
			return nil, ErrResharingFailed.WithCause(ctx.Err())

		case err := <-errCh:
			return nil, ErrResharingFailed.WithCause(fmt.Errorf("tss error: %s", err.Error()))

		case msg := <-outCh:
			if err := routeMessage(ctx, msg, allSortedIDs, router); err != nil {
				return nil, ErrResharingFailed.WithCause(err)
			}

		case in, ok := <-incoming:
			if !ok {
				return nil, ErrResharingFailed.WithCause(fmt.Errorf("incoming channel closed"))
			}
			if err := handleIncoming(party, in, allSortedIDs); err != nil {
				return nil, ErrResharingFailed.WithCause(err)
			}

		case save := <-endCh:
			ks, err := marshalECDSAKeyShare(oldShare.Curve, party.PartyID(), save)
			if err != nil {
				return nil, ErrResharingFailed.WithCause(err)
			}
			// Preserve chain code from original key.
			ks.ChainCode = oldShare.ChainCode
			return ks, nil
		}
	}
}

func (p *TSSProtocol) runReshareEdDSALoop(
	ctx context.Context,
	party tss.Party,
	allSortedIDs tss.SortedPartyIDs,
	oldShare *KeyShare,
	outCh <-chan tss.Message,
	endCh <-chan *edkeygen.LocalPartySaveData,
	errCh <-chan *tss.Error,
	router MessageRouter,
) (*KeyShare, error) {
	incoming := router.Receive()

	for {
		select {
		case <-ctx.Done():
			return nil, ErrResharingFailed.WithCause(ctx.Err())

		case err := <-errCh:
			return nil, ErrResharingFailed.WithCause(fmt.Errorf("tss error: %s", err.Error()))

		case msg := <-outCh:
			if err := routeMessage(ctx, msg, allSortedIDs, router); err != nil {
				return nil, ErrResharingFailed.WithCause(err)
			}

		case in, ok := <-incoming:
			if !ok {
				return nil, ErrResharingFailed.WithCause(fmt.Errorf("incoming channel closed"))
			}
			if err := handleIncoming(party, in, allSortedIDs); err != nil {
				return nil, ErrResharingFailed.WithCause(err)
			}

		case save := <-endCh:
			ks, err := marshalEdDSAKeyShare(party.PartyID(), save)
			if err != nil {
				return nil, ErrResharingFailed.WithCause(err)
			}
			ks.ChainCode = oldShare.ChainCode
			return ks, nil
		}
	}
}

// mergeSortedPartyIDs merges two sorted party ID lists, deduplicating by ID.
func mergeSortedPartyIDs(a, b tss.SortedPartyIDs) tss.SortedPartyIDs {
	seen := make(map[string]bool)
	var merged tss.UnSortedPartyIDs
	for _, p := range a {
		if !seen[p.Id] {
			seen[p.Id] = true
			merged = append(merged, p)
		}
	}
	for _, p := range b {
		if !seen[p.Id] {
			seen[p.Id] = true
			merged = append(merged, p)
		}
	}
	return tss.SortPartyIDs(merged)
}
