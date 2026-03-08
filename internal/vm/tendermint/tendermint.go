package tendermint

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	signingtypes "github.com/cosmos/cosmos-sdk/types/tx/signing"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/cosmos/gogoproto/proto"

	"github.com/seeingred/crypto-claw/internal/tss"
	"github.com/seeingred/crypto-claw/internal/vm"
)

// Adapter implements the vm.Adapter interface for Cosmos/Tendermint chains.
type Adapter struct {
	Prefix string // bech32 prefix, e.g. "cosmos"
	Denom  string // native denom, e.g. "uatom"
}

var _ vm.Adapter = (*Adapter)(nil)

func New(prefix, denom string) *Adapter {
	if prefix == "" {
		prefix = "cosmos"
	}
	if denom == "" {
		denom = "uatom"
	}
	return &Adapter{Prefix: prefix, Denom: denom}
}

func (a *Adapter) Name() string     { return "tendermint" }
func (a *Adapter) Curve() tss.Curve { return tss.CurveSecp256k1 }

// DeriveAddress derives a bech32 Cosmos address from an uncompressed secp256k1 public key.
func (a *Adapter) DeriveAddress(pubKey []byte, opts ...vm.DeriveOption) (string, error) {
	o := vm.ApplyDeriveOpts(opts)
	prefix := a.Prefix
	if o.Prefix != "" {
		prefix = o.Prefix
	}

	compressed, err := compressPubKey(pubKey)
	if err != nil {
		return "", err
	}

	pk := &secp256k1.PubKey{Key: compressed}
	addr := pk.Address()

	bech, err := bech32.ConvertAndEncode(prefix, addr)
	if err != nil {
		return "", fmt.Errorf("tendermint: bech32 encode: %w", err)
	}
	return bech, nil
}

// unsignedTxEnvelope is stored as RawBytes — it contains everything needed to
// reconstruct the SignDoc and assemble the final TxRaw.
type unsignedTxEnvelope struct {
	BodyBytes     []byte `json:"bodyBytes"`
	AuthInfoBytes []byte `json:"authInfoBytes"`
	ChainID       string `json:"chainId"`
	AccountNumber uint64 `json:"accountNumber"`
	// Keep human-readable fields for DecodeTx / Party B analysis.
	From  string `json:"from"`
	To    string `json:"to"`
	Value string `json:"value"`
	Denom string `json:"denom"`
	Memo  string `json:"memo,omitempty"`
}

// BuildUnsignedTx constructs a Cosmos SDK transaction (protobuf-based).
func (a *Adapter) BuildUnsignedTx(_ context.Context, req *vm.TxRequest) (*vm.UnsignedTx, error) {
	if len(req.To) == 0 {
		return nil, fmt.Errorf("tendermint: at least one recipient required")
	}

	denom := a.Denom
	if req.Denom != "" {
		denom = req.Denom
	}

	amount, err := strconv.ParseInt(req.Value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("tendermint: invalid value %q: %w", req.Value, err)
	}
	coin := sdk.NewInt64Coin(denom, amount)

	// Build message based on method.
	var msgAny *codectypes.Any
	method := req.Method
	if method == "" {
		method = "send"
	}
	switch method {
	case "send":
		msgAny, err = codectypes.NewAnyWithValue(&banktypes.MsgSend{
			FromAddress: req.From,
			ToAddress:   req.To[0],
			Amount:      sdk.NewCoins(coin),
		})
	case "delegate":
		msgAny, err = codectypes.NewAnyWithValue(&stakingtypes.MsgDelegate{
			DelegatorAddress: req.From,
			ValidatorAddress: req.To[0],
			Amount:           coin,
		})
	case "undelegate":
		msgAny, err = codectypes.NewAnyWithValue(&stakingtypes.MsgUndelegate{
			DelegatorAddress: req.From,
			ValidatorAddress: req.To[0],
			Amount:           coin,
		})
	case "redelegate":
		if len(req.To) < 2 {
			return nil, fmt.Errorf("tendermint: redelegate requires two addresses in to (src_validator, dst_validator)")
		}
		msgAny, err = codectypes.NewAnyWithValue(&stakingtypes.MsgBeginRedelegate{
			DelegatorAddress:    req.From,
			ValidatorSrcAddress: req.To[0],
			ValidatorDstAddress: req.To[1],
			Amount:              coin,
		})
	default:
		return nil, fmt.Errorf("tendermint: unknown method %q (supported: send, delegate, undelegate, redelegate)", method)
	}
	if err != nil {
		return nil, fmt.Errorf("tendermint: pack msg: %w", err)
	}

	// Build TxBody.
	body := &txtypes.TxBody{
		Messages: []*codectypes.Any{msgAny},
		Memo:     req.Memo,
	}
	bodyBytes, err := proto.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("tendermint: marshal body: %w", err)
	}

	// Build AuthInfo with signer's public key.
	compressed, err := compressPubKey(req.PubKey)
	if err != nil {
		return nil, fmt.Errorf("tendermint: compress pubkey: %w", err)
	}
	pubKeyProto := &secp256k1.PubKey{Key: compressed}
	pubKeyAny, err := codectypes.NewAnyWithValue(pubKeyProto)
	if err != nil {
		return nil, fmt.Errorf("tendermint: pack pubkey: %w", err)
	}

	// Fee defaults.
	gas := req.Gas
	if gas == 0 {
		gas = 200000
	}
	feeAmount := req.Fee
	if feeAmount == "" {
		feeAmount = "5000"
	}
	feeAmountInt, err := strconv.ParseInt(feeAmount, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("tendermint: invalid fee %q: %w", feeAmount, err)
	}

	authInfo := &txtypes.AuthInfo{
		SignerInfos: []*txtypes.SignerInfo{
			{
				PublicKey: pubKeyAny,
				ModeInfo: &txtypes.ModeInfo{
					Sum: &txtypes.ModeInfo_Single_{
						Single: &txtypes.ModeInfo_Single{
							Mode: signingtypes.SignMode_SIGN_MODE_DIRECT,
						},
					},
				},
				Sequence: req.Sequence,
			},
		},
		Fee: &txtypes.Fee{
			Amount:   sdk.NewCoins(sdk.NewInt64Coin(denom, feeAmountInt)),
			GasLimit: gas,
		},
	}
	authInfoBytes, err := proto.Marshal(authInfo)
	if err != nil {
		return nil, fmt.Errorf("tendermint: marshal auth_info: %w", err)
	}

	// Build SignDoc — this is what gets signed.
	signDoc := &txtypes.SignDoc{
		BodyBytes:     bodyBytes,
		AuthInfoBytes: authInfoBytes,
		ChainId:       req.ChainID,
		AccountNumber: req.AccountNumber,
	}
	signDocBytes, err := proto.Marshal(signDoc)
	if err != nil {
		return nil, fmt.Errorf("tendermint: marshal sign_doc: %w", err)
	}
	hash := sha256.Sum256(signDocBytes)

	// Store as envelope so we can reconstruct later.
	env := unsignedTxEnvelope{
		BodyBytes:     bodyBytes,
		AuthInfoBytes: authInfoBytes,
		ChainID:       req.ChainID,
		AccountNumber: req.AccountNumber,
		From:          req.From,
		To:            req.To[0],
		Value:         req.Value,
		Denom:         denom,
		Memo:          req.Memo,
	}
	rawBytes, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("tendermint: marshal envelope: %w", err)
	}

	return &vm.UnsignedTx{
		RawBytes: rawBytes,
		Hash:     hash[:],
		To:       req.To,
		Value:    req.Value,
	}, nil
}

// ExtractSignableBytes reconstructs the SignDoc and returns its sha256 hash.
func (a *Adapter) ExtractSignableBytes(unsignedTx []byte) ([]byte, error) {
	var env unsignedTxEnvelope
	if err := json.Unmarshal(unsignedTx, &env); err != nil {
		return nil, fmt.Errorf("tendermint: decode envelope: %w", err)
	}
	signDoc := &txtypes.SignDoc{
		BodyBytes:     env.BodyBytes,
		AuthInfoBytes: env.AuthInfoBytes,
		ChainId:       env.ChainID,
		AccountNumber: env.AccountNumber,
	}
	signDocBytes, err := proto.Marshal(signDoc)
	if err != nil {
		return nil, fmt.Errorf("tendermint: marshal sign_doc: %w", err)
	}
	hash := sha256.Sum256(signDocBytes)
	return hash[:], nil
}

// AssembleSignedTx produces a protobuf-encoded TxRaw ready for broadcast.
func (a *Adapter) AssembleSignedTx(unsignedTx []byte, sig *tss.Signature) ([]byte, error) {
	var env unsignedTxEnvelope
	if err := json.Unmarshal(unsignedTx, &env); err != nil {
		return nil, fmt.Errorf("tendermint: decode envelope: %w", err)
	}

	// Cosmos signature: 64-byte R||S (no recovery byte).
	rBytes := make([]byte, 32)
	sBytes := make([]byte, 32)
	rB := sig.R.Bytes()
	sB := sig.S.Bytes()
	copy(rBytes[32-len(rB):], rB)
	copy(sBytes[32-len(sB):], sB)
	sigBytes := append(rBytes, sBytes...)

	txRaw := &txtypes.TxRaw{
		BodyBytes:     env.BodyBytes,
		AuthInfoBytes: env.AuthInfoBytes,
		Signatures:    [][]byte{sigBytes},
	}

	raw, err := proto.Marshal(txRaw)
	if err != nil {
		return nil, fmt.Errorf("tendermint: marshal tx_raw: %w", err)
	}
	return raw, nil
}

// DecodeTx decodes an unsigned tx envelope for analysis.
func (a *Adapter) DecodeTx(txBytes []byte) (*vm.DecodedTx, error) {
	var env unsignedTxEnvelope
	if err := json.Unmarshal(txBytes, &env); err != nil {
		return nil, fmt.Errorf("tendermint: decode tx: %w", err)
	}
	return &vm.DecodedTx{
		From:    env.From,
		To:      []string{env.To},
		Value:   env.Value,
		ChainID: env.ChainID,
	}, nil
}

// compressPubKey compresses an uncompressed secp256k1 public key to 33 bytes.
func compressPubKey(pubKey []byte) ([]byte, error) {
	switch len(pubKey) {
	case 65:
		if pubKey[0] != 0x04 {
			return nil, fmt.Errorf("tendermint: invalid uncompressed key prefix")
		}
		compressed := make([]byte, 33)
		if pubKey[64]%2 == 0 {
			compressed[0] = 0x02
		} else {
			compressed[0] = 0x03
		}
		copy(compressed[1:], pubKey[1:33])
		return compressed, nil
	case 33:
		return pubKey, nil
	default:
		return nil, fmt.Errorf("tendermint: expected 33 or 65-byte public key, got %d bytes", len(pubKey))
	}
}
