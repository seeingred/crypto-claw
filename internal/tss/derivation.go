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

	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	edkeygen "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// BIP-32 constants
const (
	hardenedOffset = 0x80000000
)

// DeriveKey derives a child key from a master key share using BIP-32 style HD derivation.
// Works for both secp256k1 (ECDSA) and ed25519 (EdDSA) using non-hardened derivation
// with the compressed public key. Standard hardened derivation requires the full private
// key which no single party holds in TSS — the hardened bit in the index is preserved
// for BIP-44 path compatibility but does not change the derivation method.
func (p *TSSProtocol) DeriveKey(ctx context.Context, masterShare *KeyShare, derivationPath string) (*DerivedKey, error) {
	indices, err := parsePath(derivationPath)
	if err != nil {
		return nil, ErrDerivationFailed.WithCause(err)
	}

	switch masterShare.Curve {
	case CurveSecp256k1:
		return deriveECDSA(masterShare, derivationPath, indices)
	case CurveEd25519:
		return deriveEdDSA(masterShare, derivationPath, indices)
	default:
		return nil, ErrDerivationFailed.WithCause(fmt.Errorf(
			"derivation not supported for curve %s", masterShare.Curve,
		))
	}
}

// deriveECDSA performs BIP-32 style non-hardened derivation on secp256k1 shares.
func deriveECDSA(masterShare *KeyShare, derivationPath string, indices []uint32) (*DerivedKey, error) {
	var save keygen.LocalPartySaveData
	if err := json.Unmarshal(masterShare.Share, &save); err != nil {
		return nil, ErrDerivationFailed.WithCause(fmt.Errorf("unmarshal share: %w", err))
	}

	curveParams := tss.S256()
	parentPubX := save.ECDSAPub.X()
	parentPubY := save.ECDSAPub.Y()
	parentChainCode := masterShare.ChainCode
	childShareXi := new(big.Int).Set(save.Xi)

	// Deep copy BigXj for modification during derivation.
	bigXj := make([]*crypto.ECPoint, len(save.BigXj))
	for i, pt := range save.BigXj {
		if pt != nil {
			bigXj[i], _ = crypto.NewECPoint(curveParams, new(big.Int).Set(pt.X()), new(big.Int).Set(pt.Y()))
		}
	}

	for _, idx := range indices {
		compressed := compressPublicKey(parentPubX, parentPubY, curveParams)
		var data []byte
		data = append(data, compressed...)
		indexBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(indexBytes, idx)
		data = append(data, indexBytes...)

		mac := hmac.New(sha512.New, parentChainCode)
		mac.Write(data)
		il_ir := mac.Sum(nil)
		il := il_ir[:32]
		ir := il_ir[32:]

		ilInt := new(big.Int).SetBytes(il)
		n := curveParams.Params().N

		if ilInt.Cmp(n) >= 0 {
			return nil, ErrDerivationFailed.WithCause(fmt.Errorf("derived key >= curve order at index %d", idx))
		}

		childShareXi = new(big.Int).Add(childShareXi, ilInt)
		childShareXi.Mod(childShareXi, n)

		ilGx, ilGy := curveParams.ScalarBaseMult(il)
		parentPubX, parentPubY = curveParams.Add(parentPubX, parentPubY, ilGx, ilGy)
		parentChainCode = ir

		for j := range bigXj {
			if bigXj[j] != nil {
				newX, newY := curveParams.Add(bigXj[j].X(), bigXj[j].Y(), ilGx, ilGy)
				bigXj[j], _ = crypto.NewECPoint(curveParams, newX, newY)
			}
		}
	}

	// Build uncompressed public key bytes.
	pubKeyBytes := make([]byte, 65)
	pubKeyBytes[0] = 0x04
	xBytes := parentPubX.Bytes()
	yBytes := parentPubY.Bytes()
	copy(pubKeyBytes[33-len(xBytes):33], xBytes)
	copy(pubKeyBytes[65-len(yBytes):65], yBytes)

	// Build derived save data.
	derivedSave := save
	derivedSave.Xi = childShareXi
	derivedSave.BigXj = bigXj

	derivedPub, err := crypto.NewECPoint(curveParams, parentPubX, parentPubY)
	if err != nil {
		return nil, ErrDerivationFailed.WithCause(fmt.Errorf("create derived public key point: %w", err))
	}
	derivedSave.ECDSAPub = derivedPub

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

// deriveEdDSA performs BIP-32 style non-hardened derivation on ed25519 shares.
// Uses the same HMAC-SHA512 derivation as ECDSA but on the edwards25519 curve.
// child_share = parent_share + il mod l, child_pub = parent_pub + il*B.
func deriveEdDSA(masterShare *KeyShare, derivationPath string, indices []uint32) (*DerivedKey, error) {
	var save edkeygen.LocalPartySaveData
	if err := json.Unmarshal(masterShare.Share, &save); err != nil {
		return nil, ErrDerivationFailed.WithCause(fmt.Errorf("unmarshal share: %w", err))
	}

	curveParams := tss.Edwards()
	parentPubX := save.EDDSAPub.X()
	parentPubY := save.EDDSAPub.Y()
	parentChainCode := masterShare.ChainCode
	childShareXi := new(big.Int).Set(save.Xi)

	// Deep copy BigXj.
	bigXj := make([]*crypto.ECPoint, len(save.BigXj))
	for i, pt := range save.BigXj {
		if pt != nil {
			bigXj[i], _ = crypto.NewECPoint(curveParams, new(big.Int).Set(pt.X()), new(big.Int).Set(pt.Y()))
		}
	}

	for _, idx := range indices {
		compressed := compressPublicKey(parentPubX, parentPubY, curveParams)
		var data []byte
		data = append(data, compressed...)
		indexBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(indexBytes, idx)
		data = append(data, indexBytes...)

		mac := hmac.New(sha512.New, parentChainCode)
		mac.Write(data)
		il_ir := mac.Sum(nil)
		il := il_ir[:32]
		ir := il_ir[32:]

		// Reduce il mod l. For ed25519, l ≈ 2^252.6 while il is 256 bits,
		// so il >= l roughly 90% of the time. Unlike secp256k1 (where the
		// BIP-32 spec says to skip invalid indices because it's astronomically
		// unlikely), we reduce mod l which is standard for ed25519 derivation.
		ilInt := new(big.Int).SetBytes(il)
		n := curveParams.Params().N
		ilInt.Mod(ilInt, n)

		// child_share = parent_share + il mod l
		childShareXi = new(big.Int).Add(childShareXi, ilInt)
		childShareXi.Mod(childShareXi, n)

		// child_pub = parent_pub + il*B
		ilBytes := make([]byte, 32)
		ilB := ilInt.Bytes()
		copy(ilBytes[32-len(ilB):], ilB)
		ilBx, ilBy := curveParams.ScalarBaseMult(ilBytes)
		parentPubX, parentPubY = curveParams.Add(parentPubX, parentPubY, ilBx, ilBy)
		parentChainCode = ir

		// Update BigXj: each party's public share shifts by il*B.
		for j := range bigXj {
			if bigXj[j] != nil {
				newX, newY := curveParams.Add(bigXj[j].X(), bigXj[j].Y(), ilBx, ilBy)
				bigXj[j], _ = crypto.NewECPoint(curveParams, newX, newY)
			}
		}
	}

	// Standard ed25519 public key: Y little-endian with sign of X in bit 255.
	pubKeyBytes := edwardsPointToEd25519PubKey(parentPubX, parentPubY)

	// Build derived save data.
	derivedSave := save
	derivedSave.Xi = childShareXi
	derivedSave.BigXj = bigXj

	derivedPub, err := crypto.NewECPoint(curveParams, parentPubX, parentPubY)
	if err != nil {
		return nil, ErrDerivationFailed.WithCause(fmt.Errorf("create derived public key point: %w", err))
	}
	derivedSave.EDDSAPub = derivedPub

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

// edwardsPointToEd25519PubKey converts Edwards curve point coordinates (X, Y)
// to standard 32-byte ed25519 public key encoding: Y as little-endian with the
// sign (low bit) of X stored in bit 255 (high bit of byte 31).
func edwardsPointToEd25519PubKey(x, y *big.Int) []byte {
	yBytes := y.Bytes() // big-endian
	pubKey := make([]byte, 32)
	// Reverse Y to little-endian
	for i := 0; i < len(yBytes); i++ {
		pubKey[i] = yBytes[len(yBytes)-1-i]
	}
	// Set the sign bit of X in the high bit of the last byte
	if x.Bit(0) == 1 {
		pubKey[31] |= 0x80
	}
	return pubKey
}

// ellipticCurve is a minimal interface for the curve operations we need.
type ellipticCurve = elliptic.Curve
