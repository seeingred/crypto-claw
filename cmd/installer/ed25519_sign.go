package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"encoding/base64"

	"filippo.io/edwards25519"
	"github.com/bnb-chain/tss-lib/v2/tss"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/tyler-smith/go-bip39"
)

func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// signEd25519WithScalar signs a message using a raw ed25519 scalar (big.Int, big-endian)
// and returns a standard 64-byte ed25519 signature.
// This bypasses the standard seed→SHA-512→clamp path, signing directly with the scalar.
// Nonce is derived deterministically: r = SHA-512(scalar_le || message).
func signEd25519WithScalar(scalar *big.Int, pubKey []byte, message []byte) ([]byte, error) {
	// Reduce scalar mod l (ed25519 curve order) to ensure canonical encoding.
	// TSS-derived scalars are already reduced, but clamped master scalars may not be.
	l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	reduced := new(big.Int).Mod(scalar, l)

	// Convert to little-endian 32 bytes
	scalarBE := reduced.Bytes()
	scalarLE := make([]byte, 32)
	for i := 0; i < len(scalarBE) && i < 32; i++ {
		scalarLE[i] = scalarBE[len(scalarBE)-1-i]
	}

	s, err := edwards25519.NewScalar().SetCanonicalBytes(scalarLE)
	if err != nil {
		return nil, fmt.Errorf("set scalar: %w", err)
	}

	// Deterministic nonce: r = SHA-512(scalar || message) mod l
	mh := sha512.New()
	mh.Write(scalarLE)
	mh.Write(message)
	messageDigest := mh.Sum(nil)
	r, err := edwards25519.NewScalar().SetUniformBytes(messageDigest)
	if err != nil {
		return nil, fmt.Errorf("set nonce: %w", err)
	}

	// R = r * B
	R := (&edwards25519.Point{}).ScalarBaseMult(r)

	// k = SHA-512(R || pubKey || message)
	kh := sha512.New()
	kh.Write(R.Bytes())
	kh.Write(pubKey)
	kh.Write(message)
	hramDigest := kh.Sum(nil)
	k, err := edwards25519.NewScalar().SetUniformBytes(hramDigest)
	if err != nil {
		return nil, fmt.Errorf("set hram: %w", err)
	}

	// S = r + k * s
	S := edwards25519.NewScalar().MultiplyAdd(k, s, r)

	sig := make([]byte, 64)
	copy(sig[:32], R.Bytes())
	copy(sig[32:], S.Bytes())
	return sig, nil
}

// sweepSOL transfers all SOL from a TSS-derived address to a destination.
// It uses the raw scalar to sign, bypassing the standard ed25519 seed path.
func sweepSOL(ctx context.Context, mnemonic, path, destination, rpcURL string) (string, error) {
	// Derive the scalar and pubkey at the given path
	scalar, pubKey, err := deriveScalarAtPath(mnemonic, path)
	if err != nil {
		return "", fmt.Errorf("derive key: %w", err)
	}

	from := solana.PublicKeyFromBytes(pubKey)
	to := solana.MustPublicKeyFromBase58(destination)

	// Get balance
	balance, err := getSOLBalance(ctx, rpcURL, from.String())
	if err != nil {
		return "", fmt.Errorf("get balance: %w", err)
	}
	if balance == 0 {
		return "", fmt.Errorf("zero balance at %s", from)
	}

	// Reserve 5000 lamports for fee
	const fee uint64 = 5000
	if balance <= fee {
		return "", fmt.Errorf("balance %d lamports is too low to cover fee", balance)
	}
	amount := balance - fee

	// Build transfer instruction
	tx, err := solana.NewTransaction(
		[]solana.Instruction{
			system.NewTransferInstruction(amount, from, to).Build(),
		},
		solana.Hash{}, // placeholder
		solana.TransactionPayer(from),
	)
	if err != nil {
		return "", fmt.Errorf("build tx: %w", err)
	}

	// Fetch recent blockhash
	blockhash, err := fetchBlockhash(ctx, rpcURL)
	if err != nil {
		return "", fmt.Errorf("fetch blockhash: %w", err)
	}
	tx.Message.RecentBlockhash = solana.MustHashFromBase58(blockhash)

	// Serialize message for signing
	msgBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("serialize message: %w", err)
	}

	// Sign with raw scalar
	sig, err := signEd25519WithScalar(scalar, pubKey, msgBytes)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	// Verify the signature locally before broadcasting
	if !ed25519.Verify(pubKey, msgBytes, sig) {
		return "", fmt.Errorf("local signature verification failed")
	}

	// Place signature in transaction
	var solSig solana.Signature
	copy(solSig[:], sig)
	tx.Signatures = []solana.Signature{solSig}

	// Serialize and broadcast
	txBytes, err := tx.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("serialize signed tx: %w", err)
	}

	txid, err := sendTransaction(ctx, rpcURL, txBytes)
	if err != nil {
		return "", fmt.Errorf("send tx: %w", err)
	}

	return txid, nil
}

// sweepSPLToken transfers all of an SPL token from a TSS-derived address to a destination.
// Handles both legacy Token Program and Token-2022.
func sweepSPLToken(ctx context.Context, mnemonic, path, destination, mint, rpcURL string) (string, error) {
	scalar, pubKey, err := deriveScalarAtPath(mnemonic, path)
	if err != nil {
		return "", fmt.Errorf("derive key: %w", err)
	}

	from := solana.PublicKeyFromBytes(pubKey)
	to := solana.MustPublicKeyFromBase58(destination)
	mintPK := solana.MustPublicKeyFromBase58(mint)

	// Detect token program (legacy vs Token-2022)
	tokenProgramID, err := detectTokenProgramRPC(ctx, rpcURL, mintPK)
	if err != nil {
		return "", fmt.Errorf("detect token program: %w", err)
	}

	// Find source ATA
	fromATA, _, err := solana.FindProgramAddress(
		[][]byte{from[:], tokenProgramID[:], mintPK[:]},
		solana.SPLAssociatedTokenAccountProgramID,
	)
	if err != nil {
		return "", fmt.Errorf("find from ATA: %w", err)
	}

	// Get token balance
	balance, err := getTokenBalance(ctx, rpcURL, fromATA.String())
	if err != nil {
		return "", fmt.Errorf("get token balance: %w", err)
	}
	if balance == 0 {
		return "", fmt.Errorf("zero token balance at %s", fromATA)
	}

	// Find destination ATA
	toATA, _, err := solana.FindProgramAddress(
		[][]byte{to[:], tokenProgramID[:], mintPK[:]},
		solana.SPLAssociatedTokenAccountProgramID,
	)
	if err != nil {
		return "", fmt.Errorf("find to ATA: %w", err)
	}

	var instructions []solana.Instruction

	// CreateAssociatedTokenAccountIdempotent for destination
	instructions = append(instructions, solana.NewInstruction(
		solana.SPLAssociatedTokenAccountProgramID,
		[]*solana.AccountMeta{
			{PublicKey: from, IsSigner: true, IsWritable: true},
			{PublicKey: toATA, IsSigner: false, IsWritable: true},
			{PublicKey: to, IsSigner: false, IsWritable: false},
			{PublicKey: mintPK, IsSigner: false, IsWritable: false},
			{PublicKey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
			{PublicKey: tokenProgramID, IsSigner: false, IsWritable: false},
		},
		[]byte{1}, // CreateIdempotent
	))

	// SPL Transfer: discriminator 3 + uint64 amount (little-endian)
	transferData := make([]byte, 9)
	transferData[0] = 3
	binary.LittleEndian.PutUint64(transferData[1:], balance)
	instructions = append(instructions, solana.NewInstruction(
		tokenProgramID,
		[]*solana.AccountMeta{
			{PublicKey: fromATA, IsSigner: false, IsWritable: true},
			{PublicKey: toATA, IsSigner: false, IsWritable: true},
			{PublicKey: from, IsSigner: true, IsWritable: false},
		},
		transferData,
	))

	tx, err := solana.NewTransaction(
		instructions,
		solana.Hash{},
		solana.TransactionPayer(from),
	)
	if err != nil {
		return "", fmt.Errorf("build tx: %w", err)
	}

	blockhash, err := fetchBlockhash(ctx, rpcURL)
	if err != nil {
		return "", fmt.Errorf("fetch blockhash: %w", err)
	}
	tx.Message.RecentBlockhash = solana.MustHashFromBase58(blockhash)

	msgBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("serialize message: %w", err)
	}

	sig, err := signEd25519WithScalar(scalar, pubKey, msgBytes)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	if !ed25519.Verify(pubKey, msgBytes, sig) {
		return "", fmt.Errorf("local signature verification failed")
	}

	var solSig solana.Signature
	copy(solSig[:], sig)
	tx.Signatures = []solana.Signature{solSig}

	txBytes, err := tx.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("serialize signed tx: %w", err)
	}

	txid, err := sendTransaction(ctx, rpcURL, txBytes)
	if err != nil {
		return "", fmt.Errorf("send tx: %w", err)
	}

	return txid, nil
}

// getTokenBalance fetches the token balance for an ATA address.
func getTokenBalance(ctx context.Context, rpcURL, ataAddress string) (uint64, error) {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"getTokenAccountBalance","params":["%s"]}`, ataAddress)
	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader([]byte(body)))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return 0, err
	}

	var rpcResp struct {
		Result struct {
			Value struct {
				Amount string `json:"amount"`
			} `json:"value"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return 0, err
	}
	if rpcResp.Error != nil {
		return 0, fmt.Errorf("%s", rpcResp.Error.Message)
	}

	var amount uint64
	fmt.Sscanf(rpcResp.Result.Value.Amount, "%d", &amount)
	return amount, nil
}

// getTokenAccounts fetches all SPL token accounts owned by an address.
func getTokenAccounts(ctx context.Context, rpcURL, owner string) ([]TokenAccountInfo, error) {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"getTokenAccountsByOwner","params":["%s",{"programId":"%s"},{"encoding":"jsonParsed"}]}`,
		owner, solana.TokenProgramID.String())

	// Also fetch Token-2022 accounts
	body2022 := fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"getTokenAccountsByOwner","params":["%s",{"programId":"%s"},{"encoding":"jsonParsed"}]}`,
		owner, solana.Token2022ProgramID.String())

	var all []TokenAccountInfo
	for _, b := range []string{body, body2022} {
		accounts, err := fetchTokenAccountsRPC(ctx, rpcURL, b)
		if err != nil {
			continue // best effort
		}
		all = append(all, accounts...)
	}
	return all, nil
}

// TokenAccountInfo holds info about an SPL token account.
type TokenAccountInfo struct {
	Mint    string `json:"mint"`
	Amount  string `json:"amount"`
	Program string `json:"program"` // "spl-token" or "spl-token-2022"
}

func fetchTokenAccountsRPC(ctx context.Context, rpcURL, body string) ([]TokenAccountInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader([]byte(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, err
	}

	var rpcResp struct {
		Result struct {
			Value []struct {
				Account struct {
					Data struct {
						Parsed struct {
							Info struct {
								Mint        string `json:"mint"`
								TokenAmount struct {
									Amount string `json:"amount"`
								} `json:"tokenAmount"`
							} `json:"info"`
							Type string `json:"type"`
						} `json:"parsed"`
						Program string `json:"program"`
					} `json:"data"`
				} `json:"account"`
			} `json:"value"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, err
	}

	var accounts []TokenAccountInfo
	for _, v := range rpcResp.Result.Value {
		info := v.Account.Data.Parsed.Info
		if info.TokenAmount.Amount != "" && info.TokenAmount.Amount != "0" {
			accounts = append(accounts, TokenAccountInfo{
				Mint:    info.Mint,
				Amount:  info.TokenAmount.Amount,
				Program: v.Account.Data.Program,
			})
		}
	}
	return accounts, nil
}

// detectTokenProgramRPC queries the Solana RPC to determine which token program owns a mint.
func detectTokenProgramRPC(ctx context.Context, rpcURL string, mint solana.PublicKey) (solana.PublicKey, error) {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":["%s",{"encoding":"jsonParsed"}]}`, mint.String())
	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader([]byte(body)))
	if err != nil {
		return solana.PublicKey{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return solana.PublicKey{}, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return solana.PublicKey{}, err
	}

	var rpcResp struct {
		Result struct {
			Value *struct {
				Owner string `json:"owner"`
			} `json:"value"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return solana.PublicKey{}, err
	}
	if rpcResp.Result.Value == nil {
		return solana.PublicKey{}, fmt.Errorf("mint account not found: %s", mint)
	}

	if rpcResp.Result.Value.Owner == solana.Token2022ProgramID.String() {
		return solana.Token2022ProgramID, nil
	}
	return solana.TokenProgramID, nil
}

// deriveScalarAtPath derives the ed25519 scalar and public key at a derivation path,
// replicating the TSS-style non-hardened BIP-32 derivation.
func deriveScalarAtPath(mnemonic, path string) (*big.Int, []byte, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, nil, fmt.Errorf("invalid mnemonic")
	}

	indices, err := parseBIP32Path(path)
	if err != nil {
		return nil, nil, fmt.Errorf("parse path: %w", err)
	}

	seed := bip39.NewSeed(mnemonic, "")
	masterSeed, masterPub, masterCC, err := deriveEdDSAMaster(seed)
	if err != nil {
		return nil, nil, fmt.Errorf("derive master: %w", err)
	}

	// Clamp the master scalar
	h := sha512.Sum512(masterSeed)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	reversed := make([]byte, 32)
	for i := 0; i < 32; i++ {
		reversed[i] = h[31-i]
	}
	scalar := new(big.Int).SetBytes(reversed)

	curve := tss.Edwards()
	n := curve.Params().N

	pubX, pubY := decodeEd25519PubKey(masterPub, curve)
	chainCode := masterCC

	for _, idx := range indices {
		compressed := compressEdwardsPubKey(pubX, pubY)
		data := make([]byte, 37)
		copy(data[:33], compressed)
		binary.BigEndian.PutUint32(data[33:], idx)

		mac := hmac.New(sha512.New, chainCode)
		mac.Write(data)
		ilIr := mac.Sum(nil)
		il := ilIr[:32]
		ir := ilIr[32:]

		ilInt := new(big.Int).SetBytes(il)
		ilInt.Mod(ilInt, n)

		scalar = new(big.Int).Add(scalar, ilInt)
		scalar.Mod(scalar, n)

		ilBytes := make([]byte, 32)
		ilB := ilInt.Bytes()
		copy(ilBytes[32-len(ilB):], ilB)
		ilBx, ilBy := curve.ScalarBaseMult(ilBytes)
		pubX, pubY = curve.Add(pubX, pubY, ilBx, ilBy)
		chainCode = ir
	}

	pubKey := edwardsToEd25519PubKey(pubX, pubY)
	return scalar, pubKey, nil
}

// getSOLBalance fetches the SOL balance (in lamports) for a Solana address.
func getSOLBalance(ctx context.Context, rpcURL, address string) (uint64, error) {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"getBalance","params":["%s"]}`, address)
	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader([]byte(body)))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return 0, err
	}

	var rpcResp struct {
		Result struct {
			Value uint64 `json:"value"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return 0, err
	}
	if rpcResp.Error != nil {
		return 0, fmt.Errorf("%s", rpcResp.Error.Message)
	}
	return rpcResp.Result.Value, nil
}

// fetchBlockhash fetches a recent blockhash from a Solana RPC endpoint.
func fetchBlockhash(ctx context.Context, rpcURL string) (string, error) {
	body := `{"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash","params":[{"commitment":"finalized"}]}`
	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader([]byte(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
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
		return "", err
	}
	if rpcResp.Error != nil {
		return "", fmt.Errorf("%s", rpcResp.Error.Message)
	}
	if rpcResp.Result.Value.Blockhash == "" {
		return "", fmt.Errorf("empty blockhash")
	}
	return rpcResp.Result.Value.Blockhash, nil
}

// sendTransaction broadcasts a signed transaction to a Solana RPC endpoint.
func sendTransaction(ctx context.Context, rpcURL string, txBytes []byte) (string, error) {
	// Base64 encode the transaction
	encoded := base64Encode(txBytes)
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"sendTransaction","params":["%s",{"encoding":"base64","preflightCommitment":"confirmed"}]}`, encoded)

	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader([]byte(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}

	var rpcResp struct {
		Result string `json:"result"`
		Error  *struct {
			Message string      `json:"message"`
			Data    interface{} `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return "", err
	}
	if rpcResp.Error != nil {
		return "", fmt.Errorf("%s", rpcResp.Error.Message)
	}
	return rpcResp.Result, nil
}
