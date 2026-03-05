package tss

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	edkeygen "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	edsigning "github.com/bnb-chain/tss-lib/v2/eddsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"

	"github.com/bnb-chain/tss-lib/v2/common"
)

// Sign performs threshold signing using the key share.
func (p *TSSProtocol) Sign(ctx context.Context, req SignRequest, keyShareData []byte, partyID PartyID, parties []PartyID, router MessageRouter) (*Signature, error) {
	threshold := p.Threshold
	if threshold == 0 {
		threshold = len(parties) - 1
	}

	switch req.Curve {
	case CurveSecp256k1:
		return p.signECDSA(ctx, req.Message, keyShareData, partyID, parties, threshold, router)
	case CurveEd25519:
		return p.signEdDSA(ctx, req.Message, keyShareData, partyID, parties, threshold, router)
	default:
		return nil, ErrSigningFailed.WithCause(fmt.Errorf("unsupported curve: %s", req.Curve))
	}
}

func (p *TSSProtocol) signECDSA(ctx context.Context, message, keyShareData []byte, partyID PartyID, parties []PartyID, threshold int, router MessageRouter) (*Signature, error) {
	var save keygen.LocalPartySaveData
	if err := json.Unmarshal(keyShareData, &save); err != nil {
		return nil, ErrSigningFailed.WithCause(fmt.Errorf("unmarshal key share: %w", err))
	}

	sortedIDs := makeSortedPartyIDs(parties)
	thisParty := findPartyID(sortedIDs, partyID.ID)
	if thisParty == nil {
		return nil, ErrSigningFailed.WithCause(fmt.Errorf("party %s not found", partyID.ID))
	}

	peerCtx := tss.NewPeerContext(sortedIDs)
	params := tss.NewParameters(tss.S256(), peerCtx, thisParty, len(sortedIDs), threshold)

	msgInt := new(big.Int).SetBytes(message)

	outCh := make(chan tss.Message, len(sortedIDs)*20)
	endCh := make(chan *common.SignatureData, 1)
	errCh := make(chan *tss.Error, 1)

	party := signing.NewLocalParty(msgInt, params, save, outCh, endCh)

	go func() {
		if err := party.Start(); err != nil {
			errCh <- err
		}
	}()

	return p.runSignLoop(ctx, party, sortedIDs, outCh, endCh, errCh, router)
}

func (p *TSSProtocol) signEdDSA(ctx context.Context, message, keyShareData []byte, partyID PartyID, parties []PartyID, threshold int, router MessageRouter) (*Signature, error) {
	var save edkeygen.LocalPartySaveData
	if err := json.Unmarshal(keyShareData, &save); err != nil {
		return nil, ErrSigningFailed.WithCause(fmt.Errorf("unmarshal key share: %w", err))
	}

	sortedIDs := makeSortedPartyIDs(parties)
	thisParty := findPartyID(sortedIDs, partyID.ID)
	if thisParty == nil {
		return nil, ErrSigningFailed.WithCause(fmt.Errorf("party %s not found", partyID.ID))
	}

	peerCtx := tss.NewPeerContext(sortedIDs)
	params := tss.NewParameters(tss.Edwards(), peerCtx, thisParty, len(sortedIDs), threshold)

	msgInt := new(big.Int).SetBytes(message)

	outCh := make(chan tss.Message, len(sortedIDs)*20)
	endCh := make(chan *common.SignatureData, 1)
	errCh := make(chan *tss.Error, 1)

	party := edsigning.NewLocalParty(msgInt, params, save, outCh, endCh)

	go func() {
		if err := party.Start(); err != nil {
			errCh <- err
		}
	}()

	return p.runSignLoop(ctx, party, sortedIDs, outCh, endCh, errCh, router)
}

func (p *TSSProtocol) runSignLoop(
	ctx context.Context,
	party tss.Party,
	sortedIDs tss.SortedPartyIDs,
	outCh <-chan tss.Message,
	endCh <-chan *common.SignatureData,
	errCh <-chan *tss.Error,
	router MessageRouter,
) (*Signature, error) {
	incoming := router.Receive()

	for {
		select {
		case <-ctx.Done():
			return nil, ErrSigningFailed.WithCause(ctx.Err())

		case err := <-errCh:
			return nil, ErrSigningFailed.WithCause(fmt.Errorf("tss error: %s", err.Error()))

		case msg := <-outCh:
			if err := routeMessage(ctx, msg, sortedIDs, router); err != nil {
				return nil, ErrSigningFailed.WithCause(err)
			}

		case in, ok := <-incoming:
			if !ok {
				return nil, ErrSigningFailed.WithCause(fmt.Errorf("incoming channel closed"))
			}
			if err := handleIncoming(party, in, sortedIDs); err != nil {
				return nil, ErrSigningFailed.WithCause(err)
			}

		case sigData := <-endCh:
			return convertSignature(sigData), nil
		}
	}
}

func convertSignature(sigData *common.SignatureData) *Signature {
	r := new(big.Int).SetBytes(sigData.R)
	s := new(big.Int).SetBytes(sigData.S)

	sig := &Signature{
		R:     r,
		S:     s,
		Bytes: sigData.Signature,
	}

	// Set recovery ID if available.
	if len(sigData.SignatureRecovery) > 0 {
		sig.V = sigData.SignatureRecovery[0]
	}

	return sig
}
