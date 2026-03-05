package tss

import (
	"context"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// BIP-32 constants
const (
	hardenedOffset = 0x80000000
)

// DeriveKey derives a child key from a master key share using BIP-32 HD derivation.
func (p *TSSProtocol) DeriveKey(ctx context.Context, masterShare *KeyShare, derivationPath string) (*DerivedKey, error) {
	if masterShare.Curve != CurveSecp256k1 {
		return nil, ErrDerivationFailed.WithCause(fmt.Errorf(
			"BIP-32 derivation only supported for secp256k1, got %s (EdDSA keys use a different derivation scheme)",
			masterShare.Curve,
		))
	}

	indices, err := parsePath(derivationPath)
	if err != nil {
		return nil, ErrDerivationFailed.WithCause(err)
	}

	var save keygen.LocalPartySaveData
	if err := json.Unmarshal(masterShare.Share, &save); err != nil {
		return nil, ErrDerivationFailed.WithCause(fmt.Errorf("unmarshal share: %w", err))
	}

	// Start with master key data.
	curveParams := tss.S256()
	parentPubX := save.ECDSAPub.X()
	parentPubY := save.ECDSAPub.Y()
	parentChainCode := masterShare.ChainCode
	childShareXi := save.Xi

	// Derive through each level of the path.
	for _, idx := range indices {
		var data []byte
		if idx >= hardenedOffset {
			// Hardened child: use private key data.
			// For TSS, we use the share itself as the "private key" component.
			privBytes := childShareXi.Bytes()
			padded := make([]byte, 33)
			copy(padded[33-len(privBytes):], privBytes)
			data = append(data, padded...)
		} else {
			// Normal child: use compressed public key.
			compressed := compressPublicKey(parentPubX, parentPubY, curveParams)
			data = append(data, compressed...)
		}
		indexBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(indexBytes, idx)
		data = append(data, indexBytes...)

		mac := hmac.New(sha512.New, parentChainCode)
		mac.Write(data)
		il_ir := mac.Sum(nil)
		il := il_ir[:32]
		ir := il_ir[32:]

		// il as big.Int, add to parent share mod n.
		ilInt := new(big.Int).SetBytes(il)
		n := curveParams.Params().N

		if ilInt.Cmp(n) >= 0 {
			return nil, ErrDerivationFailed.WithCause(fmt.Errorf("derived key >= curve order at index %d", idx))
		}

		// child_share = parent_share + il mod n
		childShareXi = new(big.Int).Add(childShareXi, ilInt)
		childShareXi.Mod(childShareXi, n)

		// child_pub = parent_pub + il*G
		ilGx, ilGy := curveParams.ScalarBaseMult(il)
		parentPubX, parentPubY = curveParams.Add(parentPubX, parentPubY, ilGx, ilGy)
		parentChainCode = ir
	}

	// Build uncompressed public key bytes.
	pubKeyBytes := make([]byte, 65)
	pubKeyBytes[0] = 0x04
	xBytes := parentPubX.Bytes()
	yBytes := parentPubY.Bytes()
	copy(pubKeyBytes[33-len(xBytes):33], xBytes)
	copy(pubKeyBytes[65-len(yBytes):65], yBytes)

	// Build derived share data: clone save and update Xi and public key.
	derivedSave := save
	derivedSave.Xi = childShareXi

	derivedShareData, err := json.Marshal(&derivedSave)
	if err != nil {
		return nil, ErrDerivationFailed.WithCause(fmt.Errorf("marshal derived share: %w", err))
	}

	return &DerivedKey{
		Curve:          masterShare.Curve,
		DerivationPath: derivationPath,
		Share:          derivedShareData,
		PublicKey:      pubKeyBytes,
	}, nil
}

// parsePath parses a BIP-32 derivation path like "m/44'/60'/0'/0/0".
func parsePath(path string) ([]uint32, error) {
	path = strings.TrimPrefix(path, "m/")
	if path == "" {
		return nil, fmt.Errorf("empty derivation path")
	}

	parts := strings.Split(path, "/")
	indices := make([]uint32, 0, len(parts))

	for _, part := range parts {
		if part == "" {
			continue
		}

		hardened := false
		if strings.HasSuffix(part, "'") || strings.HasSuffix(part, "h") || strings.HasSuffix(part, "H") {
			hardened = true
			part = part[:len(part)-1]
		}

		idx, err := strconv.ParseUint(part, 10, 31)
		if err != nil {
			return nil, fmt.Errorf("invalid path component %q: %w", part, err)
		}

		index := uint32(idx)
		if hardened {
			index += hardenedOffset
		}
		indices = append(indices, index)
	}

	return indices, nil
}

// compressPublicKey converts an uncompressed public key point to compressed format.
func compressPublicKey(x, y *big.Int, curve ellipticCurve) []byte {
	compressed := make([]byte, 33)
	if y.Bit(0) == 0 {
		compressed[0] = 0x02
	} else {
		compressed[0] = 0x03
	}
	xBytes := x.Bytes()
	copy(compressed[33-len(xBytes):], xBytes)
	return compressed
}

// ellipticCurve is a minimal interface for the curve operations we need.
type ellipticCurve = elliptic.Curve
