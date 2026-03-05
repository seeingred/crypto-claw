package tss

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	edkeygen "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// DealerSetupECDSA constructs valid LocalPartySaveData for each party from a
// known private key using Shamir secret sharing. This replaces the interactive
// DKG protocol when the installer already possesses the full private key.
//
// Each party still needs its own LocalPreParams (Paillier keys + safe primes)
// for threshold signing to work later.
func DealerSetupECDSA(
	privateKey *big.Int,
	pubKeyBytes []byte,
	chainCode []byte,
	parties []PartyID,
	preParams []*keygen.LocalPreParams,
) ([]*KeyShare, error) {
	if len(parties) != len(preParams) {
		return nil, fmt.Errorf("parties and preParams length mismatch")
	}

	sortedIDs := makeSortedPartyIDs(parties)
	curve := tss.S256()
	n := curve.Params().N
	threshold := len(parties) - 1 // 2-of-2 → t=1

	// Extract ShareIDs (the big.Int key for each party).
	shareIDs := make([]*big.Int, len(sortedIDs))
	for i, pid := range sortedIDs {
		shareIDs[i] = pid.KeyInt()
	}

	// Shamir secret sharing: f(x) = privateKey + a1*x + ... + at*x^t
	shares, err := shamirSplit(privateKey, shareIDs, threshold, n)
	if err != nil {
		return nil, fmt.Errorf("shamir split: %w", err)
	}

	// Compute public key shares: BigXj[i] = shares[i] * G
	bigXj := make([]*crypto.ECPoint, len(parties))
	for i, xi := range shares {
		x, y := curve.ScalarBaseMult(xi.Bytes())
		pt, err := crypto.NewECPoint(curve, x, y)
		if err != nil {
			return nil, fmt.Errorf("compute BigXj[%d]: %w", i, err)
		}
		bigXj[i] = pt
	}

	// Reconstruct the full public key as ECPoint.
	pubX := new(big.Int).SetBytes(pubKeyBytes[1:33])
	pubY := new(big.Int).SetBytes(pubKeyBytes[33:65])
	ecdsaPub, err := crypto.NewECPoint(curve, pubX, pubY)
	if err != nil {
		return nil, fmt.Errorf("construct ECDSA pub point: %w", err)
	}

	// Collect cross-party Paillier/ZK data.
	paillierPKs := make([]*crypto.ECPoint, len(parties)) // placeholder for type
	_ = paillierPKs
	pPKs := make([]interface{}, len(parties))
	_ = pPKs
	nTildej := make([]*big.Int, len(parties))
	h1j := make([]*big.Int, len(parties))
	h2j := make([]*big.Int, len(parties))

	for i, pp := range preParams {
		nTildej[i] = pp.NTildei
		h1j[i] = pp.H1i
		h2j[i] = pp.H2i
	}

	// Build KeyShare for each party.
	keyShares := make([]*KeyShare, len(parties))
	for i := range parties {
		save := keygen.NewLocalPartySaveData(len(parties))
		save.LocalPreParams = *preParams[i]
		save.Xi = shares[i]
		save.ShareID = shareIDs[i]

		for j := range parties {
			save.Ks[j] = shareIDs[j]
			save.NTildej[j] = nTildej[j]
			save.H1j[j] = h1j[j]
			save.H2j[j] = h2j[j]
			save.BigXj[j] = bigXj[j]
			save.PaillierPKs[j] = &preParams[j].PaillierSK.PublicKey
		}
		save.ECDSAPub = ecdsaPub

		shareData, err := json.Marshal(save)
		if err != nil {
			return nil, fmt.Errorf("marshal save data for party %d: %w", i, err)
		}

		keyShares[i] = &KeyShare{
			Curve:     CurveSecp256k1,
			PartyID:   PartyID{ID: sortedIDs[i].Id, Index: sortedIDs[i].Index},
			Share:     shareData,
			PublicKey: pubKeyBytes,
			ChainCode: chainCode,
		}
	}

	return keyShares, nil
}

// DealerSetupEdDSA constructs EdDSA LocalPartySaveData for each party from a
// known signing scalar. EdDSA doesn't need Paillier keys or safe primes.
func DealerSetupEdDSA(
	signingScalar *big.Int,
	pubKeyBytes []byte,
	chainCode []byte,
	parties []PartyID,
) ([]*KeyShare, error) {
	sortedIDs := makeSortedPartyIDs(parties)
	curve := tss.Edwards()
	n := curve.Params().N
	threshold := len(parties) - 1

	shareIDs := make([]*big.Int, len(sortedIDs))
	for i, pid := range sortedIDs {
		shareIDs[i] = pid.KeyInt()
	}

	shares, err := shamirSplit(signingScalar, shareIDs, threshold, n)
	if err != nil {
		return nil, fmt.Errorf("shamir split: %w", err)
	}

	// Compute public key shares on the Edwards curve.
	bigXj := make([]*crypto.ECPoint, len(parties))
	for i, xi := range shares {
		x, y := curve.ScalarBaseMult(xi.Bytes())
		pt, err := crypto.NewECPoint(curve, x, y)
		if err != nil {
			return nil, fmt.Errorf("compute BigXj[%d]: %w", i, err)
		}
		bigXj[i] = pt
	}

	// Compute full EdDSA public key point from the signing scalar.
	edX, edY := curve.ScalarBaseMult(signingScalar.Bytes())
	eddsaPub, err := crypto.NewECPoint(curve, edX, edY)
	if err != nil {
		return nil, fmt.Errorf("construct EdDSA pub point: %w", err)
	}

	keyShares := make([]*KeyShare, len(parties))
	for i := range parties {
		save := edkeygen.NewLocalPartySaveData(len(parties))
		save.Xi = shares[i]
		save.ShareID = shareIDs[i]

		for j := range parties {
			save.Ks[j] = shareIDs[j]
			save.BigXj[j] = bigXj[j]
		}
		save.EDDSAPub = eddsaPub

		shareData, err := json.Marshal(save)
		if err != nil {
			return nil, fmt.Errorf("marshal save data for party %d: %w", i, err)
		}

		keyShares[i] = &KeyShare{
			Curve:     CurveEd25519,
			PartyID:   PartyID{ID: sortedIDs[i].Id, Index: sortedIDs[i].Index},
			Share:     shareData,
			PublicKey: pubKeyBytes,
			ChainCode: chainCode,
		}
	}

	return keyShares, nil
}

// shamirSplit splits secret into shares using Shamir's secret sharing.
// f(x) = secret + a1*x + a2*x^2 + ... + at*x^t, where t = threshold.
// Each party gets f(shareID_i).
func shamirSplit(secret *big.Int, shareIDs []*big.Int, threshold int, modulus *big.Int) ([]*big.Int, error) {
	// Generate random polynomial coefficients a1..at.
	coeffs := make([]*big.Int, threshold)
	for i := range coeffs {
		c, err := rand.Int(rand.Reader, modulus)
		if err != nil {
			return nil, fmt.Errorf("generate random coefficient: %w", err)
		}
		coeffs[i] = c
	}

	// Evaluate polynomial at each share ID.
	shares := make([]*big.Int, len(shareIDs))
	for i, k := range shareIDs {
		// f(k) = secret + a1*k + a2*k^2 + ...
		xi := new(big.Int).Set(secret)
		kPower := new(big.Int).Set(k)
		for _, c := range coeffs {
			term := new(big.Int).Mul(c, kPower)
			term.Mod(term, modulus)
			xi.Add(xi, term)
			xi.Mod(xi, modulus)
			kPower.Mul(kPower, k)
			kPower.Mod(kPower, modulus)
		}
		shares[i] = xi
	}

	return shares, nil
}
