package solana

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"sync"

	solanago "github.com/gagliardetto/solana-go"

	"github.com/seeingred/crypto-claw/internal/vm"
)

// ------------------------------------------------------------------
// Program account store: saves ephemeral account addresses created
// during initialize so they can be resolved in stake/redeem calls.
// Key format: "programID:mint:accountName"
// ------------------------------------------------------------------

var (
	programAccounts   = make(map[string]solanago.PublicKey)
	programAccountsMu sync.RWMutex
)

func programAccountKey(programID string, mint string, accountName string) string {
	return programID + ":" + mint + ":" + toSnakeCase(accountName)
}

func storeProgramAccount(programID, mint, accountName string, pubkey solanago.PublicKey) {
	programAccountsMu.Lock()
	programAccounts[programAccountKey(programID, mint, accountName)] = pubkey
	programAccountsMu.Unlock()
}

func lookupProgramAccount(programID, mint, accountName string) (solanago.PublicKey, bool) {
	programAccountsMu.RLock()
	pk, ok := programAccounts[programAccountKey(programID, mint, accountName)]
	programAccountsMu.RUnlock()
	return pk, ok
}

// AnchorResult holds the built instructions plus any ephemeral keypairs
// that must also sign the transaction.
type AnchorResult struct {
	Instructions []solanago.Instruction
	ExtraSigners []ed25519.PrivateKey // ephemeral keypairs (e.g. new accounts)
}

// ataResolution tracks an ATA that was derived during account resolution,
// so we can prepend CreateIdempotent instructions for them.
type ataResolution struct {
	ata       solanago.PublicKey
	owner     solanago.PublicKey
	mint      solanago.PublicKey
	tokenProg solanago.PublicKey
}

// Well-known Solana program addresses.
var knownPrograms = map[string]solanago.PublicKey{
	"system_program":            solanago.SystemProgramID,
	"systemProgram":             solanago.SystemProgramID,
	"token_program":             solanago.TokenProgramID,
	"tokenProgram":              solanago.TokenProgramID,
	"associated_token_program":  solanago.SPLAssociatedTokenAccountProgramID,
	"associatedTokenProgram":    solanago.SPLAssociatedTokenAccountProgramID,
	"rent":                      solanago.SysVarRentPubkey,
	"clock":                     solanago.SysVarClockPubkey,
}

// BuildAnchorInstructions builds Solana instructions from an Anchor IDL, method
// name, and arguments. It resolves all accounts (PDAs, ATAs, system programs)
// automatically. Non-payer signer accounts get ephemeral keypairs.
func BuildAnchorInstructions(
	ctx context.Context,
	rpcURL string,
	programID solanago.PublicKey,
	idl *AnchorIDL,
	method string,
	args map[string]string,
	signer solanago.PublicKey,
	mint *solanago.PublicKey,
) (*AnchorResult, error) {
	// Find instruction in IDL (match by name, snake_case, or camelCase).
	var ixDef *IDLInstruction
	methodSnake := toSnakeCase(method)
	for _, ix := range idl.Instructions {
		if ix.Name == method || toSnakeCase(ix.Name) == methodSnake {
			ixDef = ix
			break
		}
	}
	if ixDef == nil {
		available := make([]string, 0, len(idl.Instructions))
		for _, ix := range idl.Instructions {
			available = append(available, ix.Name)
		}
		return nil, fmt.Errorf("instruction %q not found in IDL (available: %s)", method, strings.Join(available, ", "))
	}

	// Generate ephemeral keypairs for non-payer signer accounts that can't be
	// resolved as PDAs. Accounts with PDA annotations or that match common PDA
	// seed patterns are PDAs (program signs internally), not external signers.
	ephemeralKeys := make(map[string]ed25519.PrivateKey)
	ephemeralPubs := make(map[string]solanago.PublicKey)
	for _, acc := range ixDef.Accounts {
		if !acc.Signer || acc.Address != "" {
			continue
		}
		nameSnake := toSnakeCase(acc.Name)
		// Skip the payer/authority/user — that's the TSS key.
		if nameSnake == "authority" || nameSnake == "user" || nameSnake == "payer" ||
			nameSnake == "signer" || nameSnake == "owner" || nameSnake == "initializer" {
			continue
		}
		// Skip if the account has PDA annotations — the program signs via invoke_signed.
		if acc.PDA != nil {
			continue
		}
		// Skip if the account resolves as a common PDA pattern.
		if isProbablyPDA(nameSnake, programID, signer, mint) {
			continue
		}
		// This is an additional signer (e.g. a new account keypair).
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ephemeral keypair for %q: %w", acc.Name, err)
		}
		ephemeralKeys[acc.Name] = priv
		ephemeralPubs[acc.Name] = solanago.PublicKeyFromBytes(pub)
	}

	// Resolve accounts — this computes PDA bumps we may need for args.
	mintStr := ""
	if mint != nil {
		mintStr = mint.String()
	}
	accounts, bumps, atas, err := resolveAccountsWithEphemeral(ctx, rpcURL, programID, ixDef, signer, mint, args, ephemeralPubs, mintStr)
	if err != nil {
		return nil, fmt.Errorf("resolve accounts: %w", err)
	}

	// Auto-fill bump args the user didn't provide.
	mergedArgs := make(map[string]string, len(args))
	for k, v := range args {
		mergedArgs[k] = v
	}
	for _, f := range ixDef.Args {
		if _, provided := mergedArgs[f.Name]; provided {
			continue
		}
		nameSnake := toSnakeCase(f.Name)
		alreadyProvided := false
		for k := range mergedArgs {
			if toSnakeCase(k) == nameSnake {
				alreadyProvided = true
				break
			}
		}
		if alreadyProvided {
			continue
		}
		if f.Type.Primitive == "u8" && strings.Contains(nameSnake, "bump") {
			if b, ok := findBump(nameSnake, bumps); ok {
				mergedArgs[f.Name] = fmt.Sprintf("%d", b)
			}
		}
	}

	// Serialize instruction data: discriminator + borsh-encoded args.
	argBytes, err := serializeBorshArgs(ixDef.Args, mergedArgs, idl.Types)
	if err != nil {
		return nil, fmt.Errorf("serialize args: %w", err)
	}
	ixData := append(ixDef.Discriminator, argBytes...)

	// Prepend CreateIdempotent instructions for any ATAs that may not exist.
	var instructions []solanago.Instruction
	for _, a := range atas {
		instructions = append(instructions, solanago.NewInstruction(
			solanago.SPLAssociatedTokenAccountProgramID,
			[]*solanago.AccountMeta{
				{PublicKey: signer, IsSigner: true, IsWritable: true},
				{PublicKey: a.ata, IsSigner: false, IsWritable: true},
				{PublicKey: a.owner, IsSigner: false, IsWritable: false},
				{PublicKey: a.mint, IsSigner: false, IsWritable: false},
				{PublicKey: solanago.SystemProgramID, IsSigner: false, IsWritable: false},
				{PublicKey: a.tokenProg, IsSigner: false, IsWritable: false},
			},
			[]byte{1}, // CreateIdempotent
		))
	}
	instructions = append(instructions, solanago.NewInstruction(programID, accounts, ixData))

	result := &AnchorResult{
		Instructions: instructions,
	}
	for _, priv := range ephemeralKeys {
		result.ExtraSigners = append(result.ExtraSigners, priv)
	}

	// Store ephemeral account addresses for future lookups (stake/redeem
	// need the vault address created during initialize).
	for name, pk := range ephemeralPubs {
		storeProgramAccount(programID.String(), mintStr, name, pk)
	}

	return result, nil
}

// findBump finds the best matching bump for a bump arg name.
// "bump" matches any bump; "vault_bump" matches "vault" specifically.
func findBump(argNameSnake string, bumps map[string]uint8) (uint8, bool) {
	// Exact match: "vault_bump" → bumps["vault"]
	prefix := strings.TrimSuffix(argNameSnake, "_bump")
	if prefix != argNameSnake {
		if b, ok := bumps[prefix]; ok {
			return b, true
		}
		for name, b := range bumps {
			if toSnakeCase(name) == prefix {
				return b, true
			}
		}
	}
	// Generic "bump" → return any bump (first PDA found).
	if argNameSnake == "bump" {
		for _, b := range bumps {
			return b, true
		}
	}
	return 0, false
}

// resolveAccountsWithEphemeral resolves all account metas, using ephemeral pubkeys
// for additional signer accounts.
func resolveAccountsWithEphemeral(
	ctx context.Context,
	rpcURL string,
	programID solanago.PublicKey,
	ix *IDLInstruction,
	signer solanago.PublicKey,
	mint *solanago.PublicKey,
	args map[string]string,
	ephemeralPubs map[string]solanago.PublicKey,
	mintStr string,
) ([]*solanago.AccountMeta, map[string]uint8, []ataResolution, error) {
	resolved := make(map[string]solanago.PublicKey)
	bumps := make(map[string]uint8)
	var atas []ataResolution

	// Pre-populate with ephemeral keypair pubkeys.
	for name, pk := range ephemeralPubs {
		resolved[name] = pk
	}

	// Pre-resolve fixed-address accounts (e.g. token_program with Token-2022
	// address) so they're available for ATA derivation in the first pass.
	for _, acc := range ix.Accounts {
		if acc.Address != "" {
			if _, ok := resolved[acc.Name]; !ok {
				resolved[acc.Name] = solanago.MustPublicKeyFromBase58(acc.Address)
			}
		}
	}

	// Multi-pass resolution: some PDAs/heuristics depend on other accounts.
	for pass := 0; pass < 4; pass++ {
		for _, acc := range ix.Accounts {
			if _, ok := resolved[acc.Name]; ok {
				continue
			}
			pk, bump, ata, err := resolveOneAccount(ctx, rpcURL, acc, programID, signer, mint, resolved, args, mintStr)
			if err != nil {
				if pass < 3 {
					continue // retry on next pass
				}
				return nil, nil, nil, fmt.Errorf("account %q: %w", acc.Name, err)
			}
			resolved[acc.Name] = pk
			if bump > 0 {
				bumps[acc.Name] = bump
			}
			if ata != nil {
				atas = append(atas, *ata)
			}
		}
	}

	// Build final account meta list in IDL order.
	result := make([]*solanago.AccountMeta, 0, len(ix.Accounts))
	for _, acc := range ix.Accounts {
		pk, ok := resolved[acc.Name]
		if !ok {
			return nil, nil, nil, fmt.Errorf("account %q could not be resolved", acc.Name)
		}
		result = append(result, &solanago.AccountMeta{
			PublicKey:  pk,
			IsSigner:   acc.Signer,
			IsWritable: acc.Writable,
		})
	}
	return result, bumps, atas, nil
}

// resolveOneAccount returns (pubkey, bump, ataInfo, error). bump is non-zero only for PDAs.
// ataInfo is non-nil when the account was resolved as an ATA (so we can create it if needed).
func resolveOneAccount(
	ctx context.Context,
	rpcURL string,
	acc *IDLAccount,
	programID solanago.PublicKey,
	signer solanago.PublicKey,
	mint *solanago.PublicKey,
	resolved map[string]solanago.PublicKey,
	args map[string]string,
	mintStr string,
) (solanago.PublicKey, uint8, *ataResolution, error) {
	// 1. Fixed address.
	if acc.Address != "" {
		return solanago.MustPublicKeyFromBase58(acc.Address), 0, nil, nil
	}

	// 2. Signer.
	if acc.Signer {
		return signer, 0, nil, nil
	}

	// 3. Well-known program names.
	if pk, ok := knownPrograms[acc.Name]; ok {
		return pk, 0, nil, nil
	}

	// 4. Account named "mint" — use the mint from the request.
	nameSnake := toSnakeCase(acc.Name)
	if (nameSnake == "mint" || nameSnake == "token_mint") && mint != nil {
		return *mint, 0, nil, nil
	}

	// 5. PDA derivation.
	if acc.PDA != nil {
		pk, bump, err := derivePDA(acc.PDA, programID, signer, mint, resolved, args)
		return pk, bump, nil, err
	}

	// 6. Heuristic: token account → derive ATA.
	if mint != nil && isTokenAccountName(nameSnake) {
		owner, err := inferTokenOwner(nameSnake, signer, resolved)
		if err != nil {
			return solanago.PublicKey{}, 0, nil, err
		}
		// Detect token program: prefer IDL fixed address, then RPC mint owner check,
		// then fall back to legacy SPL Token.
		tokenProg := solanago.TokenProgramID
		if tp, ok := resolved["token_program"]; ok {
			tokenProg = tp
		} else if tp, ok := resolved["tokenProgram"]; ok {
			tokenProg = tp
		} else if rpcURL != "" {
			if detected, err := detectTokenProgram(ctx, rpcURL, *mint); err == nil {
				tokenProg = detected
			}
		}
		ata, bump, err := findATA(owner, *mint, tokenProg)
		if err != nil {
			return solanago.PublicKey{}, 0, nil, fmt.Errorf("derive ATA: %w", err)
		}
		return ata, bump, &ataResolution{
			ata:       ata,
			owner:     owner,
			mint:      *mint,
			tokenProg: tokenProg,
		}, nil
	}

	// 7. Heuristic: *_authority → PDA derived from the base account.
	// Common Anchor pattern: seeds = [b"base_name", base_account.key()]
	if strings.HasSuffix(nameSnake, "_authority") {
		baseName := strings.TrimSuffix(nameSnake, "_authority")
		// Find the base account pubkey.
		var basePK *solanago.PublicKey
		if pk, ok := resolved[baseName]; ok {
			basePK = &pk
		} else {
			for name, pk := range resolved {
				if toSnakeCase(name) == baseName {
					basePK = &pk
					break
				}
			}
		}
		if basePK != nil {
			// Try: seeds = ["base_name", base_key] (most common Anchor pattern)
			if pk, bump, err := solanago.FindProgramAddress([][]byte{[]byte(baseName), basePK.Bytes()}, programID); err == nil {
				return pk, bump, nil, nil
			}
			// Try: seeds = [base_key]
			if pk, bump, err := solanago.FindProgramAddress([][]byte{basePK.Bytes()}, programID); err == nil {
				return pk, bump, nil, nil
			}
		}
	}

	// 8. Heuristic: try common PDA seed patterns.
	// Many Anchor programs use seeds = [b"account_name", mint.key()] or [b"account_name"].
	if mint != nil {
		if pk, bump, err := solanago.FindProgramAddress([][]byte{[]byte(nameSnake), mint.Bytes()}, programID); err == nil {
			return pk, bump, nil, nil
		}
	}
	if pk, bump, err := solanago.FindProgramAddress([][]byte{[]byte(nameSnake), signer.Bytes()}, programID); err == nil {
		return pk, bump, nil, nil
	}
	if pk, bump, err := solanago.FindProgramAddress([][]byte{[]byte(nameSnake)}, programID); err == nil {
		return pk, bump, nil, nil
	}

	// 9. Look up previously stored account (e.g. vault created during initialize).
	if pk, ok := lookupProgramAccount(programID.String(), mintStr, acc.Name); ok {
		return pk, 0, nil, nil
	}

	return solanago.PublicKey{}, 0, nil, fmt.Errorf("no resolution strategy")
}

func derivePDA(
	pda *IDLPDA,
	programID solanago.PublicKey,
	signer solanago.PublicKey,
	mint *solanago.PublicKey,
	resolved map[string]solanago.PublicKey,
	args map[string]string,
) (solanago.PublicKey, uint8, error) {
	seeds := make([][]byte, 0, len(pda.Seeds))
	for _, s := range pda.Seeds {
		switch s.Kind {
		case "const":
			seeds = append(seeds, s.Value)
		case "account":
			ref := s.Path
			// Check if it refers to the signer by common names.
			refSnake := toSnakeCase(ref)
			if refSnake == "mint" || refSnake == "token_mint" {
				if mint == nil {
					return solanago.PublicKey{}, 0, fmt.Errorf("PDA seed references mint but no mint provided")
				}
				seeds = append(seeds, mint.Bytes())
				continue
			}
			// Check resolved accounts.
			if pk, ok := resolved[ref]; ok {
				seeds = append(seeds, pk.Bytes())
				continue
			}
			// Try snake_case match.
			found := false
			for name, pk := range resolved {
				if toSnakeCase(name) == refSnake {
					seeds = append(seeds, pk.Bytes())
					found = true
					break
				}
			}
			if !found {
				// Try well-known programs.
				if pk, ok := knownPrograms[ref]; ok {
					seeds = append(seeds, pk.Bytes())
					continue
				}
				return solanago.PublicKey{}, 0, fmt.Errorf("PDA seed references unresolved account %q", ref)
			}
		case "arg":
			argVal, ok := args[s.Path]
			if !ok {
				// Try snake_case match.
				for k, v := range args {
					if toSnakeCase(k) == toSnakeCase(s.Path) {
						argVal = v
						ok = true
						break
					}
				}
			}
			if !ok {
				return solanago.PublicKey{}, 0, fmt.Errorf("PDA seed references unknown arg %q", s.Path)
			}
			seeds = append(seeds, []byte(argVal))
		default:
			return solanago.PublicKey{}, 0, fmt.Errorf("unknown PDA seed kind %q", s.Kind)
		}
	}

	// Determine which program to derive against.
	pdaProgram := programID
	if pda.Program != nil {
		switch pda.Program.Kind {
		case "const":
			if len(pda.Program.Value) == 32 {
				pdaProgram = solanago.PublicKeyFromBytes(pda.Program.Value)
			}
		case "account":
			if pk, ok := resolved[pda.Program.Path]; ok {
				pdaProgram = pk
			} else if pk, ok := knownPrograms[pda.Program.Path]; ok {
				pdaProgram = pk
			}
		}
	}

	pk, bump, err := solanago.FindProgramAddress(seeds, pdaProgram)
	if err != nil {
		return solanago.PublicKey{}, 0, fmt.Errorf("FindProgramAddress: %w", err)
	}
	return pk, bump, nil
}

// isProbablyPDA checks if an account name matches common PDA seed patterns.
// Used to avoid generating ephemeral keypairs for accounts that are actually PDAs.
func isProbablyPDA(nameSnake string, programID solanago.PublicKey, signer solanago.PublicKey, mint *solanago.PublicKey) bool {
	// Try: seeds = ["name", mint]
	if mint != nil {
		if _, _, err := solanago.FindProgramAddress([][]byte{[]byte(nameSnake), mint.Bytes()}, programID); err == nil {
			return true
		}
	}
	// Try: seeds = ["name", signer]
	if _, _, err := solanago.FindProgramAddress([][]byte{[]byte(nameSnake), signer.Bytes()}, programID); err == nil {
		return true
	}
	// Try: seeds = ["name"]
	if _, _, err := solanago.FindProgramAddress([][]byte{[]byte(nameSnake)}, programID); err == nil {
		return true
	}
	return false
}

// isTokenAccountName returns true if the name looks like a token account.
func isTokenAccountName(snake string) bool {
	return strings.Contains(snake, "token_account") ||
		strings.HasSuffix(snake, "_ata") ||
		strings.HasSuffix(snake, "_token")
}

// inferTokenOwner guesses the token account owner from the name.
func inferTokenOwner(nameSnake string, signer solanago.PublicKey, resolved map[string]solanago.PublicKey) (solanago.PublicKey, error) {
	// "user_token_account" → owner is signer
	// "vault_token_account" → owner is resolved["vault"]
	prefix := strings.TrimSuffix(nameSnake, "_token_account")
	prefix = strings.TrimSuffix(prefix, "_ata")
	prefix = strings.TrimSuffix(prefix, "_token")

	if prefix == "user" || prefix == "authority" || prefix == "signer" || prefix == "payer" || prefix == nameSnake {
		return signer, nil
	}

	// Look for the prefix in resolved accounts.
	if pk, ok := resolved[prefix]; ok {
		return pk, nil
	}
	for name, pk := range resolved {
		if toSnakeCase(name) == prefix {
			return pk, nil
		}
	}
	return signer, nil // default to signer
}

// ------------------------------------------------------------------
// Borsh argument serialization
// ------------------------------------------------------------------

func serializeBorshArgs(fields []*IDLField, args map[string]string, types []*IDLTypeDef) ([]byte, error) {
	var buf []byte
	for _, f := range fields {
		val, ok := args[f.Name]
		if !ok {
			// Try snake_case match.
			for k, v := range args {
				if toSnakeCase(k) == toSnakeCase(f.Name) {
					val = v
					ok = true
					break
				}
			}
		}
		if !ok {
			return nil, fmt.Errorf("missing arg %q", f.Name)
		}
		b, err := serializeBorshValue(val, &f.Type, types)
		if err != nil {
			return nil, fmt.Errorf("arg %q: %w", f.Name, err)
		}
		buf = append(buf, b...)
	}
	return buf, nil
}

func serializeBorshValue(val string, typ *IDLType, types []*IDLTypeDef) ([]byte, error) {
	switch {
	case typ.Primitive != "":
		return serializePrimitive(val, typ.Primitive)
	case typ.OptionInner != nil:
		if val == "" || val == "null" || val == "none" {
			return []byte{0}, nil
		}
		inner, err := serializeBorshValue(val, typ.OptionInner, types)
		if err != nil {
			return nil, err
		}
		return append([]byte{1}, inner...), nil
	case typ.DefinedName != "":
		// Find the type definition and serialize as a struct.
		for _, td := range types {
			if td.Name == typ.DefinedName {
				return serializeBorshArgs(td.Fields, map[string]string{td.Fields[0].Name: val}, types)
			}
		}
		return nil, fmt.Errorf("unknown type %q", typ.DefinedName)
	default:
		return nil, fmt.Errorf("unsupported type for serialization")
	}
}

func serializePrimitive(val, prim string) ([]byte, error) {
	switch prim {
	case "u8":
		n, ok := new(big.Int).SetString(val, 10)
		if !ok {
			return nil, fmt.Errorf("invalid u8: %s", val)
		}
		return []byte{byte(n.Uint64())}, nil
	case "u16":
		n, ok := new(big.Int).SetString(val, 10)
		if !ok {
			return nil, fmt.Errorf("invalid u16: %s", val)
		}
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, uint16(n.Uint64()))
		return b, nil
	case "u32":
		n, ok := new(big.Int).SetString(val, 10)
		if !ok {
			return nil, fmt.Errorf("invalid u32: %s", val)
		}
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(n.Uint64()))
		return b, nil
	case "u64":
		n, ok := new(big.Int).SetString(val, 10)
		if !ok {
			return nil, fmt.Errorf("invalid u64: %s", val)
		}
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, n.Uint64())
		return b, nil
	case "u128":
		n, ok := new(big.Int).SetString(val, 10)
		if !ok {
			return nil, fmt.Errorf("invalid u128: %s", val)
		}
		b := make([]byte, 16)
		fillLE(b, n)
		return b, nil
	case "i8":
		n, ok := new(big.Int).SetString(val, 10)
		if !ok {
			return nil, fmt.Errorf("invalid i8: %s", val)
		}
		return []byte{byte(n.Int64())}, nil
	case "i16":
		n, ok := new(big.Int).SetString(val, 10)
		if !ok {
			return nil, fmt.Errorf("invalid i16: %s", val)
		}
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, uint16(n.Int64()))
		return b, nil
	case "i32":
		n, ok := new(big.Int).SetString(val, 10)
		if !ok {
			return nil, fmt.Errorf("invalid i32: %s", val)
		}
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(n.Int64()))
		return b, nil
	case "i64":
		n, ok := new(big.Int).SetString(val, 10)
		if !ok {
			return nil, fmt.Errorf("invalid i64: %s", val)
		}
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, uint64(n.Int64()))
		return b, nil
	case "bool":
		if val == "true" || val == "1" {
			return []byte{1}, nil
		}
		return []byte{0}, nil
	case "string":
		b := make([]byte, 4+len(val))
		binary.LittleEndian.PutUint32(b, uint32(len(val)))
		copy(b[4:], val)
		return b, nil
	case "publicKey", "pubkey":
		pk := solanago.MustPublicKeyFromBase58(val)
		return pk.Bytes(), nil
	case "bytes":
		// Expect hex-encoded bytes.
		return hexDecodeBytes(val)
	default:
		return nil, fmt.Errorf("unsupported primitive type %q", prim)
	}
}

func fillLE(dst []byte, n *big.Int) {
	b := n.Bytes()
	// big.Int.Bytes() is big-endian; reverse into dst.
	for i, j := 0, len(b)-1; j >= 0 && i < len(dst); i, j = i+1, j-1 {
		dst[i] = b[j]
	}
}

func hexDecodeBytes(s string) ([]byte, error) {
	if strings.HasPrefix(s, "0x") {
		s = s[2:]
	}
	if len(s)%2 != 0 {
		s = "0" + s
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		high := hexDigit(s[i])
		low := hexDigit(s[i+1])
		if high == 0xFF || low == 0xFF {
			return nil, fmt.Errorf("invalid hex byte at position %d", i)
		}
		b[i/2] = high<<4 | low
	}
	return b, nil
}

func hexDigit(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0xFF
	}
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

// toSnakeCase converts camelCase/PascalCase to snake_case.
func toSnakeCase(s string) string {
	var result []byte
	for i, c := range s {
		if c >= 'A' && c <= 'Z' {
			if i > 0 {
				result = append(result, '_')
			}
			result = append(result, byte(c+'a'-'A'))
		} else {
			result = append(result, byte(c))
		}
	}
	return string(result)
}

// BuildAnchorTx is the high-level entry point: fetches IDL, builds instructions.
func BuildAnchorTx(
	ctx context.Context,
	req *vm.TxRequest,
	from solanago.PublicKey,
) (*AnchorResult, error) {
	programID := solanago.MustPublicKeyFromBase58(req.Program)

	idl, err := FetchIDL(ctx, req.RpcURL, programID)
	if err != nil {
		return nil, fmt.Errorf("fetch IDL for %s: %w", req.Program, err)
	}

	var mint *solanago.PublicKey
	if req.Mint != "" {
		m := solanago.MustPublicKeyFromBase58(req.Mint)
		mint = &m
	}

	return BuildAnchorInstructions(ctx, req.RpcURL, programID, idl, req.Method, req.Args, from, mint)
}
