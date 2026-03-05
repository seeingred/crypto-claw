package tests

import (
	"context"
	"encoding/hex"
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
// 3. Derive child key at m/44'/60'/0'/0/0
// 4. Derive EVM address from derived public key
// 5. Fund the derived address with 10 ETH
// 6. Build unsigned ETH transfer (1 ETH to Hardhat account #1)
// 7. Extract signable bytes
// 8. Sign via TSS (both parties)
// 9. Assemble signed tx
// 10. Broadcast signed tx
// 11. Mine block
// 12. Verify recipient balance increased
func TestNativeTransfer_ETH(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	testutil.RequireHardhat(t)

	// Step 1: Start Hardhat node.
	hardhat := testutil.StartHardhat(t, "contracts/evm")

	// Step 2: Generate pre-params and run ECDSA DKG.
	cluster := testutil.NewTestCluster(t)
	preParams := testutil.GenerateTestPreParams(t)
	protocol := testutil.NewTestProtocolWithPreParams(preParams)

	// Create context after pre-params generation (which can take minutes).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	testutil.RunDKG(ctx, t, cluster, protocol, tss.CurveSecp256k1)

	// Step 3: Derive child key at the standard EVM path.
	derivationPath := "m/44'/60'/0'/0/0"
	pubKeyA, _ := testutil.RunDerive(ctx, t, cluster, protocol, tss.CurveSecp256k1, derivationPath)

	// Step 4: Derive EVM address from the derived public key.
	adapter := evm.New()
	senderAddr, err := adapter.DeriveAddress(pubKeyA)
	if err != nil {
		t.Fatalf("derive EVM address: %v", err)
	}
	t.Logf("Derived sender address: %s", senderAddr)

	// Step 5: Fund the derived address with 10 ETH.
	hardhat.FundAddress(t, senderAddr, "10")
	hardhat.MineBlock(t)

	senderBalance := hardhat.GetBalance(t, senderAddr)
	t.Logf("Sender balance after funding: %s wei", senderBalance.String())
	if senderBalance.Cmp(big.NewInt(0)) <= 0 {
		t.Fatal("sender balance is zero after funding")
	}

	// Step 6: Build unsigned ETH transfer tx (1 ETH to Hardhat account #1).
	recipientAddr := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
	recipientBalanceBefore := hardhat.GetBalance(t, recipientAddr)
	t.Logf("Recipient balance before: %s wei", recipientBalanceBefore.String())

	unsignedTx, err := adapter.BuildUnsignedTx(ctx, &vm.TxRequest{
		From:     senderAddr,
		To:       []string{recipientAddr},
		Value:    "1000000000000000000", // 1 ETH in wei
		ChainID:  "31337",
		GasPrice: "20000000000", // 20 gwei — must exceed Hardhat baseFee
		Nonce:    0,
	})
	if err != nil {
		t.Fatalf("build unsigned tx: %v", err)
	}
	t.Logf("Unsigned TX hash: %x", unsignedTx.Hash)

	// Step 7: Extract signable bytes (32-byte hash).
	signable, err := adapter.ExtractSignableBytes(unsignedTx.RawBytes)
	if err != nil {
		t.Fatalf("extract signable bytes: %v", err)
	}
	if len(signable) != 32 {
		t.Fatalf("expected 32-byte signable hash, got %d bytes", len(signable))
	}

	// Step 8: Run TSS signing with derived key shares.
	sig := testutil.RunSign(ctx, t, cluster, protocol, tss.CurveSecp256k1, signable, derivationPath)
	t.Logf("TSS signature: R=%x S=%x V=%d", sig.R.Bytes(), sig.S.Bytes(), sig.V)

	// Step 9: Assemble signed tx.
	signedTx, err := adapter.AssembleSignedTx(unsignedTx.RawBytes, sig)
	if err != nil {
		t.Fatalf("assemble signed tx: %v", err)
	}

	// Step 10: Broadcast the signed tx.
	rawTxHex := "0x" + hex.EncodeToString(signedTx)
	txHash := hardhat.SendRawTx(t, rawTxHex)
	t.Logf("Broadcast tx hash: %s", txHash)

	// Step 11: Mine a block to confirm the transaction.
	hardhat.MineBlock(t)

	// Step 12: Verify recipient balance increased.
	recipientBalanceAfter := hardhat.GetBalance(t, recipientAddr)
	t.Logf("Recipient balance after: %s wei", recipientBalanceAfter.String())

	oneETH := new(big.Int).SetUint64(1000000000000000000)
	expectedMin := new(big.Int).Add(recipientBalanceBefore, oneETH)
	if recipientBalanceAfter.Cmp(expectedMin) < 0 {
		t.Fatalf("recipient balance did not increase by 1 ETH: before=%s after=%s expected_min=%s",
			recipientBalanceBefore.String(), recipientBalanceAfter.String(), expectedMin.String())
	}
	t.Logf("Native ETH transfer verified: recipient received 1 ETH")
}

// TestNativeTransfer_SOL tests sending SOL on a local Solana validator.
func TestNativeTransfer_SOL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	testutil.RequireSolana(t)
	t.Skip("Solana native transfer requires EdDSA TSS signing integration")
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
