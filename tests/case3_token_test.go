package tests

import (
	"context"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/seeingred/crypto-claw/internal/tss"
	"github.com/seeingred/crypto-claw/internal/vm"
	"github.com/seeingred/crypto-claw/internal/vm/evm"
	"github.com/seeingred/crypto-claw/tests/testutil"
)

// abiEncodeAddress pads an Ethereum address to 32 bytes.
func abiEncodeAddress(addr string) []byte {
	addr = strings.TrimPrefix(addr, "0x")
	b, _ := hex.DecodeString(addr)
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

// abiEncodeUint256 encodes a big.Int as a 32-byte ABI parameter.
func abiEncodeUint256(n *big.Int) []byte {
	padded := make([]byte, 32)
	b := n.Bytes()
	copy(padded[32-len(b):], b)
	return padded
}

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

	testutil.RequireHardhat(t)

	// Step 1: Start Hardhat.
	hardhat := testutil.StartHardhat(t, "contracts/evm")

	// Step 2: Deploy CclawToken.
	tokenAddr := hardhat.DeployContract(t, "CclawToken")
	t.Logf("CclawToken deployed at: %s", tokenAddr)

	// Step 3: DKG + derive address.
	cluster := testutil.NewTestCluster(t)
	preParams := testutil.GenerateTestPreParams(t)
	protocol := testutil.NewTestProtocolWithPreParams(preParams)

	// Create context after pre-params generation (which can take minutes).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	testutil.RunDKG(ctx, t, cluster, protocol, tss.CurveSecp256k1)

	derivationPath := "m/44'/60'/0'/0/0"
	pubKeyA, _ := testutil.RunDerive(ctx, t, cluster, protocol, tss.CurveSecp256k1, derivationPath)

	adapter := evm.New()
	senderAddr, err := adapter.DeriveAddress(pubKeyA)
	if err != nil {
		t.Fatalf("derive EVM address: %v", err)
	}
	t.Logf("Derived sender address: %s", senderAddr)

	// Step 4: Fund derived address with ETH for gas.
	hardhat.FundAddress(t, senderAddr, "10")
	hardhat.MineBlock(t)

	// Mint 1000 CCLAW (1000e18) to derived address using owner account.
	// mint(address,uint256) selector: 0x40c10f19
	mintSelector, _ := hex.DecodeString("40c10f19")
	mintAmount := new(big.Int).Mul(big.NewInt(1000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	mintCalldata := append(mintSelector, abiEncodeAddress(senderAddr)...)
	mintCalldata = append(mintCalldata, abiEncodeUint256(mintAmount)...)

	ownerAddr := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	mintTxHash := hardhat.SendTx(t, ownerAddr, tokenAddr, "0x"+hex.EncodeToString(mintCalldata))
	t.Logf("Mint tx hash: %s", mintTxHash)
	hardhat.MineBlock(t)

	// Step 5: Verify token balance using balanceOf(address).
	// balanceOf selector: 0x70a08231
	balanceOfSelector, _ := hex.DecodeString("70a08231")
	balanceOfCalldata := append(balanceOfSelector, abiEncodeAddress(senderAddr)...)
	balanceResult := hardhat.EthCall(t, tokenAddr, "0x"+hex.EncodeToString(balanceOfCalldata))
	senderBalance := new(big.Int)
	senderBalance.SetString(strings.TrimPrefix(balanceResult, "0x"), 16)
	if senderBalance.Cmp(mintAmount) != 0 {
		t.Fatalf("expected sender balance %s, got %s", mintAmount.String(), senderBalance.String())
	}
	t.Logf("Sender token balance after mint: %s", senderBalance.String())

	// Step 6: Build unsigned tx for transfer(to, amount).
	// Transfer 100 CCLAW (100e18) to Hardhat account #1.
	recipientAddr := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
	transferAmount := new(big.Int).Mul(big.NewInt(100), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))

	transferSelector, _ := hex.DecodeString("a9059cbb")
	transferCalldata := append(transferSelector, abiEncodeAddress(recipientAddr)...)
	transferCalldata = append(transferCalldata, abiEncodeUint256(transferAmount)...)

	unsignedTx, err := adapter.BuildUnsignedTx(ctx, &vm.TxRequest{
		From:     senderAddr,
		To:       []string{tokenAddr},
		Data:     transferCalldata,
		ChainID:  "31337",
		GasPrice: "20000000000", // 20 gwei — must exceed Hardhat baseFee
		GasLimit: 100000,
	})
	if err != nil {
		t.Fatalf("build unsigned tx: %v", err)
	}

	// Step 7: Extract signable bytes.
	signable, err := adapter.ExtractSignableBytes(unsignedTx.RawBytes)
	if err != nil {
		t.Fatalf("extract signable bytes: %v", err)
	}
	if len(signable) != 32 {
		t.Fatalf("expected 32-byte signable hash, got %d", len(signable))
	}

	// Step 8: TSS sign with derived keys.
	sig := testutil.RunSign(ctx, t, cluster, protocol, tss.CurveSecp256k1, signable, derivationPath)
	t.Logf("TSS signature: R=%s S=%s V=%d", sig.R.String(), sig.S.String(), sig.V)

	// Step 9: Assemble signed tx.
	signedTxBytes, err := adapter.AssembleSignedTx(unsignedTx.RawBytes, sig)
	if err != nil {
		t.Fatalf("assemble signed tx: %v", err)
	}

	// Step 10: Broadcast and mine.
	txHash := hardhat.SendRawTx(t, "0x"+hex.EncodeToString(signedTxBytes))
	t.Logf("Transfer tx hash: %s", txHash)
	hardhat.MineBlock(t)

	// Step 11: Verify balances.
	// Sender should have 900 CCLAW.
	expectedSenderBalance := new(big.Int).Mul(big.NewInt(900), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	balanceOfSenderCalldata := append(balanceOfSelector, abiEncodeAddress(senderAddr)...)
	senderResult := hardhat.EthCall(t, tokenAddr, "0x"+hex.EncodeToString(balanceOfSenderCalldata))
	finalSenderBalance := new(big.Int)
	finalSenderBalance.SetString(strings.TrimPrefix(senderResult, "0x"), 16)
	if finalSenderBalance.Cmp(expectedSenderBalance) != 0 {
		t.Fatalf("expected sender balance %s, got %s", expectedSenderBalance.String(), finalSenderBalance.String())
	}
	t.Logf("Final sender balance: %s CCLAW", finalSenderBalance.String())

	// Recipient should have 100 CCLAW.
	balanceOfRecipientCalldata := append(balanceOfSelector, abiEncodeAddress(recipientAddr)...)
	recipientResult := hardhat.EthCall(t, tokenAddr, "0x"+hex.EncodeToString(balanceOfRecipientCalldata))
	finalRecipientBalance := new(big.Int)
	finalRecipientBalance.SetString(strings.TrimPrefix(recipientResult, "0x"), 16)
	if finalRecipientBalance.Cmp(transferAmount) != 0 {
		t.Fatalf("expected recipient balance %s, got %s", transferAmount.String(), finalRecipientBalance.String())
	}
	t.Logf("Final recipient balance: %s CCLAW", finalRecipientBalance.String())
}

// TestTokenTransfer_SPL tests SPL token transfers on local Solana validator.
func TestTokenTransfer_SPL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	testutil.RequireSolana(t)
	t.Skip("SPL token transfer requires EdDSA TSS signing integration")
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
