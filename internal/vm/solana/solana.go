package solana

import (
	"bytes"
	"context"
	crypto_ed25519 "crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"

	"github.com/seeingred/crypto-claw/internal/tss"
	"github.com/seeingred/crypto-claw/internal/vm"
)

// ed25519PrivKey is an alias for crypto/ed25519.PrivateKey.
type ed25519PrivKey = crypto_ed25519.PrivateKey

// Adapter implements the vm.Adapter interface for Solana.
type Adapter struct{}

var _ vm.Adapter = (*Adapter)(nil)

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string     { return "solana" }
func (a *Adapter) Curve() tss.Curve { return tss.CurveEd25519 }

// DeriveAddress returns the base58-encoded address from a 32-byte ed25519 public key.
func (a *Adapter) DeriveAddress(pubKey []byte) (string, error) {
	if len(pubKey) != 32 {
		return "", fmt.Errorf("solana: expected 32-byte ed25519 public key, got %d bytes", len(pubKey))
	}
	pk := solana.PublicKeyFromBytes(pubKey)
	return pk.String(), nil
}

// txEnvelope is the serialization wrapper for Solana unsigned transactions.
type txEnvelope struct {
	Type       string `json:"type"`       // "sol_transfer" or "spl_transfer"
	From       string `json:"from"`
	To         string `json:"to"`
	Amount     uint64 `json:"amount"`
	Mint       string `json:"mint,omitempty"`       // SPL token mint
	RecentHash string `json:"recentHash,omitempty"` // recent blockhash
}

// BuildUnsignedTx constructs a Solana transaction for SOL transfers, SPL token
// transfers, or arbitrary program instructions.
func (a *Adapter) BuildUnsignedTx(ctx context.Context, req *vm.TxRequest) (*vm.UnsignedTx, error) {
	from := solana.MustPublicKeyFromBase58(req.From)

	var instructions []solana.Instruction

	var extraSigners []ed25519PrivKey

	if req.Program != "" && req.Method != "" {
		// Anchor program call: fetch IDL, resolve accounts, build instruction.
		result, err := BuildAnchorTx(ctx, req, from)
		if err != nil {
			return nil, fmt.Errorf("solana: anchor: %w", err)
		}
		instructions = result.Instructions
		for _, priv := range result.ExtraSigners {
			extraSigners = append(extraSigners, ed25519PrivKey(priv))
		}
	} else if len(req.Instructions) > 0 {
		// Raw instructions mode: build from caller-provided instructions.
		for i, ix := range req.Instructions {
			programID := solana.MustPublicKeyFromBase58(ix.ProgramID)
			accounts := make([]*solana.AccountMeta, len(ix.Accounts))
			for j, acc := range ix.Accounts {
				accounts[j] = &solana.AccountMeta{
					PublicKey:  solana.MustPublicKeyFromBase58(acc.Pubkey),
					IsSigner:   acc.IsSigner,
					IsWritable: acc.IsWritable,
				}
			}
			data, err := base64.StdEncoding.DecodeString(ix.Data)
			if err != nil {
				return nil, fmt.Errorf("solana: instruction[%d] invalid base64 data: %w", i, err)
			}
			instructions = append(instructions, solana.NewInstruction(programID, accounts, data))
		}
	} else {
		// Legacy transfer mode
		if len(req.To) == 0 {
			return nil, fmt.Errorf("solana: at least one recipient required")
		}
		to := solana.MustPublicKeyFromBase58(req.To[0])

		var amount uint64
		if req.Value != "" {
			if _, err := fmt.Sscanf(req.Value, "%d", &amount); err != nil {
				return nil, fmt.Errorf("solana: invalid value %q: %w", req.Value, err)
			}
		}

		if req.Mint != "" {
			// SPL token transfer: detect token program (legacy vs Token-2022) via RPC.
			mint := solana.MustPublicKeyFromBase58(req.Mint)

			tokenProgramID := solana.TokenProgramID // default to legacy
			if req.RpcURL != "" {
				detected, err := detectTokenProgram(ctx, req.RpcURL, mint)
				if err != nil {
					return nil, fmt.Errorf("solana: detect token program: %w", err)
				}
				tokenProgramID = detected
			}

			fromATA, _, err := findATA(from, mint, tokenProgramID)
			if err != nil {
				return nil, fmt.Errorf("solana: find from ATA: %w", err)
			}
			toATA, _, err := findATA(to, mint, tokenProgramID)
			if err != nil {
				return nil, fmt.Errorf("solana: find to ATA: %w", err)
			}

			// Create recipient ATA if it doesn't exist (idempotent).
			// Instruction discriminator 1 = CreateIdempotent.
			instructions = append(instructions, solana.NewInstruction(
				solana.SPLAssociatedTokenAccountProgramID,
				[]*solana.AccountMeta{
					{PublicKey: from, IsSigner: true, IsWritable: true},
					{PublicKey: toATA, IsSigner: false, IsWritable: true},
					{PublicKey: to, IsSigner: false, IsWritable: false},
					{PublicKey: mint, IsSigner: false, IsWritable: false},
					{PublicKey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
					{PublicKey: tokenProgramID, IsSigner: false, IsWritable: false},
				},
				[]byte{1}, // CreateIdempotent
			))

			// SPL Transfer: discriminator 3 + uint64 amount (little-endian).
			transferData := make([]byte, 9)
			transferData[0] = 3
			binary.LittleEndian.PutUint64(transferData[1:], amount)
			instructions = append(instructions, solana.NewInstruction(
				tokenProgramID,
				[]*solana.AccountMeta{
					{PublicKey: fromATA, IsSigner: false, IsWritable: true},
					{PublicKey: toATA, IsSigner: false, IsWritable: true},
					{PublicKey: from, IsSigner: true, IsWritable: false},
				},
				transferData,
			))
		} else {
			// Simple SOL transfer
			instructions = append(instructions,
				system.NewTransferInstruction(amount, from, to).Build(),
			)
		}
	}

	tx, err := solana.NewTransaction(
		instructions,
		solana.Hash{}, // placeholder; fresh blockhash injected at sign time
		solana.TransactionPayer(from),
	)
	if err != nil {
		return nil, fmt.Errorf("solana: build tx: %w", err)
	}

	// Collect ephemeral private keys for later signing (after blockhash injection).
	var extraSignerKeys [][]byte
	for _, priv := range extraSigners {
		extraSignerKeys = append(extraSignerKeys, []byte(priv))
	}

	msgBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("solana: serialize message: %w", err)
	}

	rawBytes, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("solana: serialize tx: %w", err)
	}

	return &vm.UnsignedTx{
		RawBytes:        rawBytes,
		Hash:            msgBytes,
		To:              req.To,
		Value:           req.Value,
		ExtraSignerKeys: extraSignerKeys,
	}, nil
}

// ExtractSignableBytes returns the transaction message bytes to be signed.
func (a *Adapter) ExtractSignableBytes(unsignedTx []byte) ([]byte, error) {
	tx, err := solana.TransactionFromBytes(unsignedTx)
	if err != nil {
		return nil, fmt.Errorf("solana: decode tx: %w", err)
	}
	msgBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("solana: serialize message: %w", err)
	}
	return msgBytes, nil
}

// AssembleSignedTx places the ed25519 signature into the transaction.
func (a *Adapter) AssembleSignedTx(unsignedTx []byte, sig *tss.Signature) ([]byte, error) {
	return AssembleSignedTxWithExtra(unsignedTx, sig, nil)
}

// AssembleSignedTxWithExtra places the TSS signature and signs with any extra
// ephemeral private keys, placing all signatures at their correct indices.
func AssembleSignedTxWithExtra(unsignedTx []byte, sig *tss.Signature, extraKeys [][]byte) ([]byte, error) {
	tx, err := solana.TransactionFromBytes(unsignedTx)
	if err != nil {
		return nil, fmt.Errorf("solana: decode tx: %w", err)
	}

	if len(sig.Bytes) != 64 {
		return nil, fmt.Errorf("solana: expected 64-byte ed25519 signature, got %d", len(sig.Bytes))
	}

	numSigs := int(tx.Message.Header.NumRequiredSignatures)
	if numSigs < 1 {
		numSigs = 1
	}
	tx.Signatures = make([]solana.Signature, numSigs)

	// Slot 0 = payer (TSS signature).
	copy(tx.Signatures[0][:], sig.Bytes)

	// Sign with ephemeral private keys and place at correct indices.
	if len(extraKeys) > 0 {
		msgBytes, err := tx.Message.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("solana: serialize message for extra signers: %w", err)
		}
		for _, privBytes := range extraKeys {
			priv := crypto_ed25519.PrivateKey(privBytes)
			pub := priv.Public().(crypto_ed25519.PublicKey)
			pk := solana.PublicKeyFromBytes(pub)
			// Find signature index.
			for i, key := range tx.Message.AccountKeys {
				if key == pk && i > 0 && i < numSigs {
					sigBytes := crypto_ed25519.Sign(priv, msgBytes)
					copy(tx.Signatures[i][:], sigBytes)
					break
				}
			}
		}
	}

	raw, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("solana: serialize signed tx: %w", err)
	}
	return raw, nil
}

// DecodeTx decodes a serialized Solana transaction into human-readable form.
func (a *Adapter) DecodeTx(txBytes []byte) (*vm.DecodedTx, error) {
	tx, err := solana.TransactionFromBytes(txBytes)
	if err != nil {
		// Try as JSON envelope
		var env txEnvelope
		if jsonErr := json.Unmarshal(txBytes, &env); jsonErr == nil {
			return &vm.DecodedTx{
				From:  env.From,
				To:    []string{env.To},
				Value: fmt.Sprintf("%d", env.Amount),
			}, nil
		}
		return nil, fmt.Errorf("solana: decode tx: %w", err)
	}

	decoded := &vm.DecodedTx{}
	if len(tx.Message.AccountKeys) > 0 {
		decoded.From = tx.Message.AccountKeys[0].String()
	}
	if len(tx.Message.AccountKeys) > 1 {
		decoded.To = []string{tx.Message.AccountKeys[1].String()}
	}
	return decoded, nil
}

// InjectBlockhash replaces the blockhash in a serialized unsigned Solana transaction
// and returns the updated serialized bytes.
func InjectBlockhash(unsignedTx []byte, blockhash string) ([]byte, error) {
	tx, err := solana.TransactionFromBytes(unsignedTx)
	if err != nil {
		return nil, fmt.Errorf("solana: decode tx for blockhash injection: %w", err)
	}
	tx.Message.RecentBlockhash = solana.MustHashFromBase58(blockhash)
	raw, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("solana: re-serialize tx: %w", err)
	}
	return raw, nil
}

// FetchRecentBlockhash fetches a recent blockhash from a Solana JSON-RPC endpoint.
// Performs SSRF validation: resolves DNS first, blocks private/reserved IP ranges.
func FetchRecentBlockhash(ctx context.Context, rpcURL string) (string, error) {
	if !allowLocalRPC {
		if err := validateRPCURL(rpcURL); err != nil {
			return "", fmt.Errorf("solana rpc: %w", err)
		}
	}

	body := `{"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash","params":[{"commitment":"finalized"}]}`
	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader([]byte(body)))
	if err != nil {
		return "", fmt.Errorf("solana rpc: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("solana rpc: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", fmt.Errorf("solana rpc: read response: %w", err)
	}

	var rpcResp struct {
		Result struct {
			Value struct {
				Blockhash string `json:"blockhash"`
			} `json:"value"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return "", fmt.Errorf("solana rpc: parse response: %w", err)
	}
	if rpcResp.Error != nil {
		return "", fmt.Errorf("solana rpc: %s", rpcResp.Error.Message)
	}
	if rpcResp.Result.Value.Blockhash == "" {
		return "", fmt.Errorf("solana rpc: empty blockhash in response")
	}
	return rpcResp.Result.Value.Blockhash, nil
}

// validateRPCURL checks the URL for SSRF: resolves DNS, blocks private/reserved IPs.
func validateRPCURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https, got %q", u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("empty hostname")
	}

	// Resolve DNS to get the actual IP(s).
	ips, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("DNS resolution failed for %q: %w", host, err)
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return fmt.Errorf("invalid IP %q", ipStr)
		}
		if isPrivateIP(ip) {
			return fmt.Errorf("blocked: %q resolves to private/reserved IP %s", host, ipStr)
		}
	}
	return nil
}

// isPrivateIP returns true if the IP is in a private or reserved range.
func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"127.0.0.0/8",    // loopback
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"169.254.0.0/16", // link-local
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 unique local
		"fe80::/10",      // IPv6 link-local
	}
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// allowLocalRPC controls whether local/private IPs are allowed for RPC.
// Set via ALLOW_LOCAL_RPC=1 environment variable for dev/testing.
var allowLocalRPC = os.Getenv("ALLOW_LOCAL_RPC") == "1"

// findATA derives the Associated Token Account for a wallet+mint using the given token program.
func findATA(wallet, mint, tokenProgramID solana.PublicKey) (solana.PublicKey, uint8, error) {
	return solana.FindProgramAddress(
		[][]byte{
			wallet[:],
			tokenProgramID[:],
			mint[:],
		},
		solana.SPLAssociatedTokenAccountProgramID,
	)
}

// detectTokenProgram queries the Solana RPC to determine which token program owns the mint.
// Returns TokenProgramID or Token2022ProgramID.
func detectTokenProgram(ctx context.Context, rpcURL string, mint solana.PublicKey) (solana.PublicKey, error) {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":["%s",{"encoding":"jsonParsed"}]}`, mint.String())

	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader([]byte(body)))
	if err != nil {
		return solana.PublicKey{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return solana.PublicKey{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return solana.PublicKey{}, fmt.Errorf("read response: %w", err)
	}

	var rpcResp struct {
		Result struct {
			Value *struct {
				Owner string `json:"owner"`
			} `json:"value"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return solana.PublicKey{}, fmt.Errorf("parse response: %w", err)
	}
	if rpcResp.Result.Value == nil {
		return solana.PublicKey{}, fmt.Errorf("mint account not found: %s", mint)
	}

	owner := rpcResp.Result.Value.Owner
	switch owner {
	case solana.Token2022ProgramID.String():
		return solana.Token2022ProgramID, nil
	default:
		return solana.TokenProgramID, nil
	}
}
