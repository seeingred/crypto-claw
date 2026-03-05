package tests

import (
	"context"
	"testing"
	"time"

	"github.com/seeingred/crypto-claw/internal/vm"
	"github.com/seeingred/crypto-claw/internal/vm/evm"
	"github.com/seeingred/crypto-claw/tests/testutil"
)

// TestTokenTransfer_ERC20 tests ERC-20 CCLAW token transfers on Hardhat.
//
// Flow:
// 1. Start Hardhat node
// 2. Deploy CclawToken contract
// 3. Run DKG, derive EVM address
// 4. Mint CCLAW tokens to derived address
// 5. Build unsigned ERC-20 transfer tx (calldata for transfer(to, amount))
// 6. TSS sign the tx
// 7. Broadcast and verify token balances
func TestTokenTransfer_ERC20(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Skip("requires TSS protocol implementation, Hardhat, and deployed contracts")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cluster := testutil.NewTestCluster(t)
	_ = ctx

	// Step 1: Start Hardhat.
	// hardhat := testutil.StartHardhat(t, "contracts/evm")

	// Step 2: Deploy CclawToken.
	// tokenAddr := hardhat.DeployContract(t, "CclawToken")
	// t.Logf("CclawToken deployed at: %s", tokenAddr)

	// Step 3: DKG + derive address.
	adapter := evm.New()
	_ = adapter
	// var protocol tss.Protocol = tssimpl.New()
	// testutil.RunDKG(ctx, t, cluster, protocol, tss.CurveSecp256k1)
	// shareA, _ := cluster.PartyA.GetKeyShare(tss.CurveSecp256k1)
	// senderAddr, _ := adapter.DeriveAddress(shareA.PublicKey)

	// Step 4: Mint CCLAW tokens to the sender.
	// ERC-20 mint calldata: mint(address,uint256)
	// selector: 0x40c10f19
	// hardhat.FundAddress(t, senderAddr, "1") // need ETH for gas

	// Build mint calldata:
	// mintData := buildMintCalldata(senderAddr, "1000000000000000000000") // 1000 CCLAW
	// ... execute mint from owner account

	// Step 5: Build transfer calldata.
	// transfer(address,uint256)
	// selector: 0xa9059cbb
	// recipientAddr := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
	// transferData := buildTransferCalldata(recipientAddr, "100000000000000000000") // 100 CCLAW

	// Step 6-7: Build unsigned tx, sign, broadcast.
	// unsignedTx, err := adapter.BuildUnsignedTx(ctx, &vm.TxRequest{
	//     From:     senderAddr,
	//     To:       []string{tokenAddr},
	//     Data:     transferData,
	//     ChainID:  "31337",
	//     GasLimit: 100000,
	// })
	// ... TSS sign and broadcast

	// Step 8: Verify token balances.
	// ... query balanceOf for sender and recipient

	_ = cluster
}

// TestTokenTransfer_SPL tests SPL token transfers on local Solana validator.
func TestTokenTransfer_SPL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Skip("requires TSS protocol implementation and Solana CLI")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cluster := testutil.NewTestCluster(t)
	_ = ctx

	// Step 1: Start Solana validator.
	// validator := testutil.StartSolanaValidator(t)

	// Step 2: Create SPL CCLAW token.
	// keypairPath, _ := testutil.GenerateSolanaKeypair(t)
	// validator.Airdrop(t, pubkey, 10)
	// tokenMint := validator.CreateSPLToken(t, keypairPath, 9)
	// tokenAccount := validator.CreateTokenAccount(t, tokenMint, keypairPath)
	// validator.MintTokens(t, tokenMint, 1000, keypairPath)

	// Step 3: DKG for EdDSA.
	// var protocol tss.Protocol = tssimpl.New()
	// testutil.RunDKG(ctx, t, cluster, protocol, tss.CurveEd25519)
	// shareA, _ := cluster.PartyA.GetKeyShare(tss.CurveEd25519)

	// Step 4-7: Create token accounts, build SPL transfer instruction,
	// TSS sign, broadcast, verify balances.

	_ = cluster
}

// TestDecodeTx_ERC20Transfer verifies decoding an ERC-20 transfer transaction.
func TestDecodeTx_ERC20Transfer(t *testing.T) {
	adapter := evm.New()

	// Build a transaction with ERC-20 transfer calldata.
	// transfer(address,uint256) selector: 0xa9059cbb
	transferData := make([]byte, 68)
	// Function selector.
	transferData[0] = 0xa9
	transferData[1] = 0x05
	transferData[2] = 0x9c
	transferData[3] = 0xbb
	// Address param (padded to 32 bytes) - recipient.
	copy(transferData[16:36], []byte{0x70, 0x99, 0x79, 0x70, 0xC5, 0x18, 0x12, 0xdc,
		0x3A, 0x01, 0x0C, 0x7d, 0x01, 0xb5, 0x0e, 0x0d, 0x17, 0xdc, 0x79, 0xC8})
	// Amount param (100 tokens = 100e18).
	transferData[67] = 0x64

	unsignedTx, err := adapter.BuildUnsignedTx(context.Background(), &vm.TxRequest{
		From:     "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		To:       []string{"0x5FbDB2315678afecb367f032d93F642f64180aa3"}, // token contract
		Data:     transferData,
		ChainID:  "31337",
		GasLimit: 100000,
	})
	if err != nil {
		t.Fatal("build unsigned tx:", err)
	}

	decoded, err := adapter.DecodeTx(unsignedTx.RawBytes)
	if err != nil {
		t.Fatal("decode tx:", err)
	}

	if decoded.Method != "0xa9059cbb" {
		t.Fatalf("expected method 0xa9059cbb, got %s", decoded.Method)
	}
	if decoded.GasLimit != 100000 {
		t.Fatalf("expected gas limit 100000, got %d", decoded.GasLimit)
	}
	t.Logf("Decoded tx: to=%v method=%s gasLimit=%d", decoded.To, decoded.Method, decoded.GasLimit)
}

// Ensure imports compile.
var (
	_ = evm.New
	_ = (*vm.TxRequest)(nil)
)

// buildTransferCalldata helper (for reference - used in full integration).
// func buildTransferCalldata(to string, amount string) []byte { ... }
// func buildMintCalldata(to string, amount string) []byte { ... }
