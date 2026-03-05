package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"

	"github.com/seeingred/crypto-claw/internal/tss"
)

// DKGResult holds the results of a DKG ceremony for one curve.
type DKGResult struct {
	ShareA *tss.KeyShare
	ShareB *tss.KeyShare
}

// inMemoryRouter is an in-process message router connecting two parties
// for the installer DKG ceremony without requiring network transport.
type inMemoryRouter struct {
	channels map[string]chan tss.IncomingMessage
	mu       sync.RWMutex
}

func newInMemoryRouter() *inMemoryRouter {
	return &inMemoryRouter{
		channels: make(map[string]chan tss.IncomingMessage),
	}
}

// forParty returns a MessageRouter scoped to the given party.
func (r *inMemoryRouter) forParty(id tss.PartyID) tss.MessageRouter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.channels[id.ID]; !ok {
		r.channels[id.ID] = make(chan tss.IncomingMessage, 1024)
	}
	return &inMemoryPartyRouter{router: r, self: id}
}

type inMemoryPartyRouter struct {
	router *inMemoryRouter
	self   tss.PartyID
}

func (p *inMemoryPartyRouter) Send(_ context.Context, to tss.PartyID, msg []byte) error {
	p.router.mu.RLock()
	ch, ok := p.router.channels[to.ID]
	p.router.mu.RUnlock()
	if !ok {
		return fmt.Errorf("no channel for party %s", to.ID)
	}
	ch <- tss.IncomingMessage{From: p.self, Payload: msg}
	return nil
}

func (p *inMemoryPartyRouter) Receive() <-chan tss.IncomingMessage {
	p.router.mu.RLock()
	defer p.router.mu.RUnlock()
	return p.router.channels[p.self.ID]
}

// RunInstallerDKG runs DKG for both ECDSA (secp256k1) and EdDSA (ed25519)
// using two in-process parties. Returns the DKG results for both curves.
func RunInstallerDKG(ctx context.Context) (*DKGResult, *DKGResult, error) {
	partyA := tss.PartyID{ID: "party-a", Index: 0}
	partyB := tss.PartyID{ID: "party-b", Index: 1}
	parties := []tss.PartyID{partyA, partyB}

	// Generate ECDSA pre-params for both parties in parallel.
	// This is CPU-intensive (generating safe primes) but must be done before DKG.
	slog.Info("generating ECDSA safe primes (this may take a few minutes)...")

	var ppA, ppB *keygen.LocalPreParams
	var ppErrA, ppErrB error
	var ppWg sync.WaitGroup
	ppWg.Add(2)
	go func() {
		defer ppWg.Done()
		ppA, ppErrA = keygen.GeneratePreParams(10 * time.Minute)
	}()
	go func() {
		defer ppWg.Done()
		ppB, ppErrB = keygen.GeneratePreParams(10 * time.Minute)
	}()
	ppWg.Wait()

	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	if ppErrA != nil {
		return nil, nil, fmt.Errorf("generate pre-params for party-a: %w", ppErrA)
	}
	if ppErrB != nil {
		return nil, nil, fmt.Errorf("generate pre-params for party-b: %w", ppErrB)
	}

	preParams := map[string]*keygen.LocalPreParams{
		"party-a": ppA,
		"party-b": ppB,
	}

	protocol := tss.NewProtocol(0) // 2-of-2 threshold
	protocol.GetPreParams = func(pid tss.PartyID) (*keygen.LocalPreParams, error) {
		pp, ok := preParams[pid.ID]
		if !ok {
			return nil, fmt.Errorf("no pre-params for party %s", pid.ID)
		}
		return pp, nil
	}

	// Run ECDSA DKG.
	slog.Info("running ECDSA (secp256k1) DKG ceremony")
	ecdsaResult, err := runDKGForCurve(ctx, protocol, tss.CurveSecp256k1, partyA, partyB, parties)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDSA DKG: %w", err)
	}
	slog.Info("ECDSA DKG complete", "pubKey", fmt.Sprintf("%x", ecdsaResult.ShareA.PublicKey[:8]))

	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}

	// Run EdDSA DKG (no pre-params needed for EdDSA).
	slog.Info("running EdDSA (ed25519) DKG ceremony")
	eddsaResult, err := runDKGForCurve(ctx, protocol, tss.CurveEd25519, partyA, partyB, parties)
	if err != nil {
		return nil, nil, fmt.Errorf("EdDSA DKG: %w", err)
	}
	slog.Info("EdDSA DKG complete", "pubKey", fmt.Sprintf("%x", eddsaResult.ShareA.PublicKey[:8]))

	return ecdsaResult, eddsaResult, nil
}

// runDKGForCurve runs DKG for a single curve with two in-process parties.
func runDKGForCurve(
	ctx context.Context,
	protocol *tss.TSSProtocol,
	curve tss.Curve,
	partyA, partyB tss.PartyID,
	parties []tss.PartyID,
) (*DKGResult, error) {
	router := newInMemoryRouter()

	var wg sync.WaitGroup
	var shareA, shareB *tss.KeyShare
	var errA, errB error

	wg.Add(2)
	go func() {
		defer wg.Done()
		shareA, errA = protocol.DKG(ctx, curve, partyA, parties, router.forParty(partyA))
	}()
	go func() {
		defer wg.Done()
		shareB, errB = protocol.DKG(ctx, curve, partyB, parties, router.forParty(partyB))
	}()

	wg.Wait()

	if errA != nil {
		return nil, fmt.Errorf("party A: %w", errA)
	}
	if errB != nil {
		return nil, fmt.Errorf("party B: %w", errB)
	}

	return &DKGResult{
		ShareA: shareA,
		ShareB: shareB,
	}, nil
}
