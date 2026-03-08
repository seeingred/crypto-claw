package solana

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	solanago "github.com/gagliardetto/solana-go"
)

// AnchorIDL is the unified representation of an Anchor program IDL.
type AnchorIDL struct {
	Name         string
	Instructions []*IDLInstruction
	Types        []*IDLTypeDef
}

// IDLInstruction describes a single instruction in the IDL.
type IDLInstruction struct {
	Name          string
	Discriminator []byte // 8 bytes
	Accounts      []*IDLAccount
	Args          []*IDLField
}

// IDLAccount describes an account input for an instruction.
type IDLAccount struct {
	Name     string
	Writable bool
	Signer   bool
	Address  string  // known fixed address (system programs, etc.)
	PDA      *IDLPDA // PDA derivation info
}

// IDLPDA holds PDA derivation seeds and optional program override.
type IDLPDA struct {
	Seeds   []*IDLSeed
	Program *IDLSeedRef // nil = use the instruction's program
}

// IDLSeed describes a single PDA seed.
type IDLSeed struct {
	Kind  string // "const", "account", "arg"
	Value []byte // for "const": literal bytes
	Path  string // for "account"/"arg": reference name
}

// IDLSeedRef references a program for PDA derivation.
type IDLSeedRef struct {
	Kind  string // "const" or "account"
	Value []byte // for "const"
	Path  string // for "account"
}

// IDLField is a named typed field (instruction arg or struct field).
type IDLField struct {
	Name string
	Type IDLType
}

// IDLTypeDef is a user-defined type in the IDL.
type IDLTypeDef struct {
	Name   string
	Fields []*IDLField
}

// IDLType represents an IDL type. Exactly one variant is populated.
type IDLType struct {
	Primitive   string   // "u8","u16","u32","u64","u128","i8",...,"bool","string","publicKey","bytes"
	OptionInner *IDLType // Option<T>
	VecInner    *IDLType // Vec<T>
	DefinedName string   // reference to a named type
	ArrayElem   *IDLType // fixed-size array element type
	ArrayLen    int      // fixed-size array length
}

func (t *IDLType) UnmarshalJSON(data []byte) error {
	// Try as string (primitive).
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		t.Primitive = s
		return nil
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("invalid IDL type: %s", string(data))
	}

	if raw, ok := obj["option"]; ok {
		var inner IDLType
		if err := json.Unmarshal(raw, &inner); err != nil {
			return err
		}
		t.OptionInner = &inner
		return nil
	}
	if raw, ok := obj["vec"]; ok {
		var inner IDLType
		if err := json.Unmarshal(raw, &inner); err != nil {
			return err
		}
		t.VecInner = &inner
		return nil
	}
	if raw, ok := obj["defined"]; ok {
		// New format: {"defined":{"name":"TypeName"}} or old: {"defined":"TypeName"}
		var name string
		if err := json.Unmarshal(raw, &name); err == nil {
			t.DefinedName = name
			return nil
		}
		var def struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(raw, &def); err != nil {
			return err
		}
		t.DefinedName = def.Name
		return nil
	}
	if raw, ok := obj["array"]; ok {
		// {"array":["u8",32]}
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			return err
		}
		if len(arr) != 2 {
			return fmt.Errorf("invalid array type")
		}
		var elem IDLType
		if err := json.Unmarshal(arr[0], &elem); err != nil {
			return err
		}
		var length int
		if err := json.Unmarshal(arr[1], &length); err != nil {
			return err
		}
		t.ArrayElem = &elem
		t.ArrayLen = length
		return nil
	}

	return fmt.Errorf("unknown IDL type: %s", string(data))
}

// ------------------------------------------------------------------
// IDL JSON formats (old v0.20-0.29 and new v0.30+)
// ------------------------------------------------------------------

// rawIDLNew is the Anchor v0.30+ IDL JSON format.
type rawIDLNew struct {
	Address  string `json:"address"`
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Instructions []rawIxNew    `json:"instructions"`
	Types        []rawTypeDef  `json:"types"`
	Accounts     []rawTypeDef  `json:"accounts"` // account types
}

type rawIxNew struct {
	Name          string           `json:"name"`
	Discriminator []byte           `json:"discriminator"`
	Accounts      []rawAccountNew  `json:"accounts"`
	Args          []rawField       `json:"args"`
}

type rawAccountNew struct {
	Name     string      `json:"name"`
	Writable bool        `json:"writable"`
	Signer   bool        `json:"signer"`
	Address  string      `json:"address"`
	PDA      *rawPDANew  `json:"pda"`
}

type rawPDANew struct {
	Seeds   []rawSeedNew     `json:"seeds"`
	Program *json.RawMessage `json:"program"` // optional program override
}

type rawSeedNew struct {
	Kind  string          `json:"kind"`
	Value json.RawMessage `json:"value"` // for "const": byte array; for "account"/"arg": string path
	Path  string          `json:"path"`  // alternative for "account"/"arg"
}

type rawField struct {
	Name string  `json:"name"`
	Type IDLType `json:"type"`
}

type rawTypeDef struct {
	Name string `json:"name"`
	Type struct {
		Kind   string     `json:"kind"`
		Fields []rawField `json:"fields"`
	} `json:"type"`
}

// rawIDLOld is the Anchor v0.20-0.29 IDL JSON format.
type rawIDLOld struct {
	Name         string        `json:"name"`
	Version      string        `json:"version"`
	Instructions []rawIxOld    `json:"instructions"`
	Types        []rawTypeDef  `json:"types"`
	Accounts     []rawTypeDef  `json:"accounts"`
}

type rawIxOld struct {
	Name     string          `json:"name"`
	Accounts []rawAccountOld `json:"accounts"`
	Args     []rawField      `json:"args"`
}

type rawAccountOld struct {
	Name     string `json:"name"`
	IsMut    bool   `json:"isMut"`
	IsSigner bool   `json:"isSigner"`
}

// ------------------------------------------------------------------
// Parsing
// ------------------------------------------------------------------

func parseIDL(data []byte) (*AnchorIDL, error) {
	// Detect format: new has "metadata", old has "version".
	var probe struct {
		Metadata *json.RawMessage `json:"metadata"`
		Version  string           `json:"version"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("probe IDL format: %w", err)
	}

	if probe.Metadata != nil {
		return parseIDLNew(data)
	}
	return parseIDLOld(data)
}

func parseIDLNew(data []byte) (*AnchorIDL, error) {
	var raw rawIDLNew
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse new IDL: %w", err)
	}

	idl := &AnchorIDL{Name: raw.Metadata.Name}

	// Parse types.
	for _, rt := range append(raw.Types, raw.Accounts...) {
		if rt.Type.Kind != "struct" || len(rt.Type.Fields) == 0 {
			continue
		}
		td := &IDLTypeDef{Name: rt.Name}
		for _, f := range rt.Type.Fields {
			td.Fields = append(td.Fields, &IDLField{Name: f.Name, Type: f.Type})
		}
		idl.Types = append(idl.Types, td)
	}

	// Parse instructions.
	for _, rix := range raw.Instructions {
		ix := &IDLInstruction{
			Name:          rix.Name,
			Discriminator: rix.Discriminator,
		}
		if len(ix.Discriminator) == 0 {
			ix.Discriminator = anchorDiscriminator(rix.Name)
		}
		for _, f := range rix.Args {
			ix.Args = append(ix.Args, &IDLField{Name: f.Name, Type: f.Type})
		}
		for _, ra := range rix.Accounts {
			acc := &IDLAccount{
				Name:     ra.Name,
				Writable: ra.Writable,
				Signer:   ra.Signer,
				Address:  ra.Address,
			}
			if ra.PDA != nil {
				acc.PDA = parsePDANew(ra.PDA)
			}
			ix.Accounts = append(ix.Accounts, acc)
		}
		idl.Instructions = append(idl.Instructions, ix)
	}

	return idl, nil
}

func parsePDANew(raw *rawPDANew) *IDLPDA {
	pda := &IDLPDA{}
	for _, rs := range raw.Seeds {
		seed := &IDLSeed{Kind: rs.Kind, Path: rs.Path}
		if rs.Kind == "const" && len(rs.Value) > 0 {
			// Value is a JSON byte array like [118,97,117,108,116].
			var bArr []byte
			if err := json.Unmarshal(rs.Value, &bArr); err != nil {
				// Might be a string.
				var s string
				if err := json.Unmarshal(rs.Value, &s); err == nil {
					seed.Value = []byte(s)
				}
			} else {
				seed.Value = bArr
			}
		}
		if rs.Kind == "account" && seed.Path == "" {
			// Some IDLs put the path in "value" as a string.
			var s string
			if json.Unmarshal(rs.Value, &s) == nil {
				seed.Path = s
			}
		}
		pda.Seeds = append(pda.Seeds, seed)
	}
	if raw.Program != nil {
		var progObj struct {
			Kind  string          `json:"kind"`
			Value json.RawMessage `json:"value"`
			Path  string          `json:"path"`
		}
		if json.Unmarshal(*raw.Program, &progObj) == nil {
			ref := &IDLSeedRef{Kind: progObj.Kind, Path: progObj.Path}
			if progObj.Kind == "const" {
				var bArr []byte
				if json.Unmarshal(progObj.Value, &bArr) == nil {
					ref.Value = bArr
				}
			}
			pda.Program = ref
		}
	}
	return pda
}

func parseIDLOld(data []byte) (*AnchorIDL, error) {
	var raw rawIDLOld
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse old IDL: %w", err)
	}

	idl := &AnchorIDL{Name: raw.Name}

	for _, rt := range append(raw.Types, raw.Accounts...) {
		if rt.Type.Kind != "struct" || len(rt.Type.Fields) == 0 {
			continue
		}
		td := &IDLTypeDef{Name: rt.Name}
		for _, f := range rt.Type.Fields {
			td.Fields = append(td.Fields, &IDLField{Name: f.Name, Type: f.Type})
		}
		idl.Types = append(idl.Types, td)
	}

	for _, rix := range raw.Instructions {
		ix := &IDLInstruction{
			Name:          rix.Name,
			Discriminator: anchorDiscriminator(rix.Name),
		}
		for _, f := range rix.Args {
			ix.Args = append(ix.Args, &IDLField{Name: f.Name, Type: f.Type})
		}
		for _, ra := range rix.Accounts {
			ix.Accounts = append(ix.Accounts, &IDLAccount{
				Name:     ra.Name,
				Writable: ra.IsMut,
				Signer:   ra.IsSigner,
			})
		}
		idl.Instructions = append(idl.Instructions, ix)
	}

	return idl, nil
}

// anchorDiscriminator computes sha256("global:<name>")[:8].
func anchorDiscriminator(name string) []byte {
	h := sha256.Sum256([]byte("global:" + toSnakeCase(name)))
	return h[:8]
}

// ------------------------------------------------------------------
// On-chain IDL fetching
// ------------------------------------------------------------------

var (
	idlCache   = make(map[string]*AnchorIDL)
	idlCacheMu sync.RWMutex
)

// Program Metadata Program (Anchor 0.31+).
var programMetadataID = solanago.MustPublicKeyFromBase58("pmetaypqG6SiB47xMigYVMAkuHDWeSDXcv3zzDrmcht")

// FetchIDL fetches and parses the Anchor IDL for a program from the Solana chain.
// It tries the new Program Metadata PDA (0.31+) first, then falls back to the
// legacy create_with_seed approach (0.29/0.30).
func FetchIDL(ctx context.Context, rpcURL string, programID solanago.PublicKey) (*AnchorIDL, error) {
	key := programID.String()
	idlCacheMu.RLock()
	if cached, ok := idlCache[key]; ok {
		idlCacheMu.RUnlock()
		return cached, nil
	}
	idlCacheMu.RUnlock()

	// Try 1: Program Metadata PDA (Anchor 0.31+)
	// seeds = [program_id, "idl"], program = programMetadataID
	if idl, err := fetchIDLFromMetadata(ctx, rpcURL, programID); err == nil {
		idlCacheMu.Lock()
		idlCache[key] = idl
		idlCacheMu.Unlock()
		return idl, nil
	}

	// Try 2: Legacy Anchor IDL account (0.29/0.30)
	// Step 1: programSigner = find_program_address([], programID)
	// Step 2: idlAddr = create_with_seed(programSigner, "anchor:idl", programID)
	if idl, err := fetchIDLLegacy(ctx, rpcURL, programID); err == nil {
		idlCacheMu.Lock()
		idlCache[key] = idl
		idlCacheMu.Unlock()
		return idl, nil
	}

	return nil, fmt.Errorf("IDL not found for program %s: tried Program Metadata PDA and legacy create_with_seed", programID)
}

// fetchIDLFromMetadata fetches the IDL using the Program Metadata program (Anchor 0.31+).
func fetchIDLFromMetadata(ctx context.Context, rpcURL string, programID solanago.PublicKey) (*AnchorIDL, error) {
	idlAddr, _, err := solanago.FindProgramAddress(
		[][]byte{programID.Bytes(), []byte("idl")},
		programMetadataID,
	)
	if err != nil {
		return nil, fmt.Errorf("compute metadata PDA: %w", err)
	}

	accountData, err := fetchAccountDataRaw(ctx, rpcURL, idlAddr.String())
	if err != nil {
		return nil, err
	}

	// Program Metadata account layout:
	// Discriminator (8) + data_type (1) + authority (32) + program (32) +
	// encoding (1) + compression (1) + format (1) + data_source (1) + data_len (4) + data
	const metadataHeaderSize = 8 + 1 + 32 + 32 + 1 + 1 + 1 + 1 + 4
	if len(accountData) < metadataHeaderSize {
		return nil, fmt.Errorf("metadata account too short: %d bytes", len(accountData))
	}

	compression := accountData[8+1+32+32+1] // compression byte
	dataLen := binary.LittleEndian.Uint32(accountData[metadataHeaderSize-4 : metadataHeaderSize])
	payload := accountData[metadataHeaderSize:]
	if uint32(len(payload)) < dataLen {
		return nil, fmt.Errorf("metadata truncated: want %d, have %d", dataLen, len(payload))
	}
	payload = payload[:dataLen]

	idlJSON, err := decompressIDL(payload, compression)
	if err != nil {
		return nil, err
	}

	return parseIDL(idlJSON)
}

// fetchIDLLegacy fetches the IDL using the legacy Anchor approach (0.29/0.30).
// PDA: create_with_seed(find_program_address([], programID), "anchor:idl", programID)
func fetchIDLLegacy(ctx context.Context, rpcURL string, programID solanago.PublicKey) (*AnchorIDL, error) {
	// Step 1: derive the program signer PDA (empty seeds).
	programSigner, _, err := solanago.FindProgramAddress([][]byte{}, programID)
	if err != nil {
		return nil, fmt.Errorf("compute program signer: %w", err)
	}

	// Step 2: create_with_seed(programSigner, "anchor:idl", programID)
	// = SHA256(base || seed || owner)
	h := sha256.Sum256(append(append(programSigner.Bytes(), []byte("anchor:idl")...), programID.Bytes()...))
	idlAddr := solanago.PublicKeyFromBytes(h[:])

	accountData, err := fetchAccountDataRaw(ctx, rpcURL, idlAddr.String())
	if err != nil {
		return nil, err
	}

	// Layout: 8-byte discriminator + 32-byte authority + 4-byte data_len + data
	if len(accountData) < 44 {
		return nil, fmt.Errorf("legacy IDL account too short: %d bytes", len(accountData))
	}
	dataLen := binary.LittleEndian.Uint32(accountData[40:44])
	payload := accountData[44:]
	if uint32(len(payload)) < dataLen {
		return nil, fmt.Errorf("legacy IDL truncated: want %d, have %d", dataLen, len(payload))
	}
	payload = payload[:dataLen]

	idlJSON, err := decompressIDL(payload, 1) // legacy always uses zlib
	if err != nil {
		// Might be uncompressed in very old versions.
		idlJSON = payload
	}

	return parseIDL(idlJSON)
}

// decompressIDL decompresses IDL payload based on the compression flag.
// 0 = none, 1 = zlib, 2 = gzip
func decompressIDL(data []byte, compression byte) ([]byte, error) {
	switch compression {
	case 0:
		return data, nil
	case 1:
		r, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("zlib open: %w", err)
		}
		defer r.Close()
		return io.ReadAll(io.LimitReader(r, 2<<20)) // 2 MB decompression limit
	default:
		// Try zlib; fall back to raw.
		if r, err := zlib.NewReader(bytes.NewReader(data)); err == nil {
			decompressed, err := io.ReadAll(io.LimitReader(r, 2<<20))
			r.Close()
			if err == nil {
				return decompressed, nil
			}
		}
		return data, nil
	}
}

// fetchAccountDataRaw fetches raw account data via Solana JSON-RPC.
func fetchAccountDataRaw(ctx context.Context, rpcURL, address string) ([]byte, error) {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":["%s",{"encoding":"base64"}]}`, address)

	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader([]byte(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB limit
	if err != nil {
		return nil, err
	}

	var rpcResp struct {
		Result struct {
			Value *struct {
				Data []string `json:"data"` // [base64data, "base64"]
			} `json:"value"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("parse RPC response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error: %s", rpcResp.Error.Message)
	}
	if rpcResp.Result.Value == nil || len(rpcResp.Result.Value.Data) < 1 {
		return nil, fmt.Errorf("account not found: %s", address)
	}

	return base64.StdEncoding.DecodeString(rpcResp.Result.Value.Data[0])
}
