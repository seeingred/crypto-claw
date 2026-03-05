package tests

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/seeingred/crypto-claw/internal/tss"
	"github.com/seeingred/crypto-claw/internal/vm"
	"github.com/seeingred/crypto-claw/internal/vm/evm"
	"github.com/seeingred/crypto-claw/tests/testutil"
)

// TestNativeTransfer_ETH tests sending ETH on a local Hardhat network.
//
// Flow:
// 1. Start Hardhat node
// 2. Run DKG to get shared ECDSA key
// 3. Derive EVM address from shared public key
// 4. Fund the derived address
// 5. Build unsigned ETH transfer
// 6. Sign via TSS (both parties)
// 7. Broadcast signed tx
// 8. Verify recipient balance increased
func TestNativeTransfer_ETH(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Skip("requires TSS protocol implementation and Hardhat")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cluster := testutil.NewTestCluster(t)
	_ = ctx

	// Step 1: Start Hardhat.
	// hardhat := testutil.StartHardhat(t, "contracts/evm")

	// Step 2: DKG.
	// var protocol tss.Protocol = tssimpl.New()
	// testutil.RunDKG(ctx, t, cluster, protocol, tss.CurveSecp256k1)

	// Step 3: Derive EVM address.
	adapter := evm.New()
	_ = adapter
	// shareA, _ := cluster.PartyA.GetKeyShare(tss.CurveSecp256k1)
	// senderAddr, err := adapter.DeriveAddress(shareA.PublicKey)

	// Step 4: Fund the sender.
	// hardhat.FundAddress(t, senderAddr, "10")

	// Step 5: Build unsigned tx.
	recipientAddr := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" // Hardhat account #1
	_ = recipientAddr
	// unsignedTx, err := adapter.BuildUnsignedTx(ctx, &vm.TxRequest{
	//     From:    senderAddr,
	//     To:      []string{recipientAddr},
	//     Value:   "1000000000000000000", // 1 ETH in wei
	//     ChainID: "31337",
	//     Nonce:   0,
	// })

	// Step 6: TSS sign.
	// signable, err := adapter.ExtractSignableBytes(unsignedTx.RawBytes)
	// signReq := tss.SignRequest{
	//     DerivationPath: "m/44'/60'/0'/0/0",
	//     Message:        signable,
	//     Curve:          tss.CurveSecp256k1,
	// }
	// sig := runTSSSign(ctx, t, cluster, protocol, signReq)

	// Step 7: Assemble and broadcast.
	// signedTx, err := adapter.AssembleSignedTx(unsignedTx.RawBytes, sig)
	// txHash := hardhat.SendRawTx(t, "0x"+hex.EncodeToString(signedTx))

	// Step 8: Verify.
	// hardhat.MineBlock(t)
	// balance := hardhat.GetBalance(t, recipientAddr)
	// ... assert balance increased

	_ = cluster
}

// TestNativeTransfer_SOL tests sending SOL on a local Solana validator.
func TestNativeTransfer_SOL(t *testing.T) {
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

	// Step 2: DKG for EdDSA.
	// var protocol tss.Protocol = tssimpl.New()
	// testutil.RunDKG(ctx, t, cluster, protocol, tss.CurveEd25519)

	// Step 3: Derive Solana address from ed25519 public key.
	// shareA, _ := cluster.PartyA.GetKeyShare(tss.CurveEd25519)
	// solAddr := base58.Encode(shareA.PublicKey)

	// Step 4: Fund sender.
	// validator.Airdrop(t, solAddr, 10)

	// Step 5-8: Build, sign, broadcast, verify SOL transfer.
	// (Similar pattern to ETH but using Solana transaction format)

	_ = cluster
}

// TestBuildUnsignedTx_EVM verifies building an unsigned EVM transaction.
func TestBuildUnsignedTx_EVM(t *testing.T) {
	adapter := evm.New()

	unsignedTx, err := adapter.BuildUnsignedTx(context.Background(), &vm.TxRequest{
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		To:      []string{"0x70997970C51812dc3A010C7d01b50e0d17dc79C8"},
		Value:   "1000000000000000000", // 1 ETH
		ChainID: "31337",
		Nonce:   0,
	})
	if err != nil {
		t.Fatal("build unsigned tx:", err)
	}

	if len(unsignedTx.RawBytes) == 0 {
		t.Fatal("unsigned tx raw bytes empty")
	}
	if len(unsignedTx.Hash) != 32 {
		t.Fatalf("expected 32-byte hash, got %d", len(unsignedTx.Hash))
	}
	if len(unsignedTx.To) != 1 || unsignedTx.To[0] != "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" {
		t.Fatal("unexpected To field")
	}
	t.Logf("Unsigned TX hash: %x", unsignedTx.Hash)
}

// TestExtractSignableBytes_EVM verifies extracting signable bytes from an unsigned tx.
func TestExtractSignableBytes_EVM(t *testing.T) {
	adapter := evm.New()

	unsignedTx, err := adapter.BuildUnsignedTx(context.Background(), &vm.TxRequest{
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		To:      []string{"0x70997970C51812dc3A010C7d01b50e0d17dc79C8"},
		Value:   "1000000000000000000",
		ChainID: "31337",
	})
	if err != nil {
		t.Fatal(err)
	}

	signable, err := adapter.ExtractSignableBytes(unsignedTx.RawBytes)
	if err != nil {
		t.Fatal("extract signable bytes:", err)
	}
	if len(signable) != 32 {
		t.Fatalf("expected 32-byte hash, got %d", len(signable))
	}
}

// Ensure imports are used.
var (
	_ = tss.CurveEd25519
	_ = vm.NewRegistry
	_ = (*big.Int)(nil)
)
