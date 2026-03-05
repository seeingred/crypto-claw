package tests

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/seeingred/crypto-claw/internal/tss"
	"github.com/seeingred/crypto-claw/internal/vm"
	"github.com/seeingred/crypto-claw/internal/vm/evm"
	"github.com/seeingred/crypto-claw/tests/testutil"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// abiEncodeAddress and abiEncodeUint256 are defined in case3_token_test.go
// (same package), so we reuse them here.

func parseUint256(hexResult string) *big.Int {
	hexResult = strings.TrimPrefix(hexResult, "0x")
	n := new(big.Int)
	n.SetString(hexResult, 16)
	return n
}

// ---------------------------------------------------------------------------
// signAndBroadcast signs an unsigned tx via TSS and broadcasts it
// ---------------------------------------------------------------------------

func signAndBroadcast(
	ctx context.Context,
	t *testing.T,
	cluster *testutil.TestCluster,
	protocol tss.Protocol,
	hardhat *testutil.HardhatNode,
	adapter *evm.Adapter,
	unsignedTx *vm.UnsignedTx,
	derivationPath string,
) {
	t.Helper()

	signable, err := adapter.ExtractSignableBytes(unsignedTx.RawBytes)
	if err != nil {
		t.Fatal("extract signable:", err)
	}

	sig := testutil.RunSign(ctx, t, cluster, protocol, tss.CurveSecp256k1, signable, derivationPath)

	signedTx, err := adapter.AssembleSignedTx(unsignedTx.RawBytes, sig)
	if err != nil {
		t.Fatal("assemble signed tx:", err)
	}

	hardhat.SendRawTx(t, "0x"+hex.EncodeToString(signedTx))
	hardhat.MineBlock(t)
}

// ---------------------------------------------------------------------------
// Selector helpers
// ---------------------------------------------------------------------------

var (
	// ERC-20 / CclawToken selectors
	selectorMint     = []byte{0x40, 0xc1, 0x0f, 0x19} // mint(address,uint256)
	selectorTransfer = []byte{0xa9, 0x05, 0x9c, 0xbb} // transfer(address,uint256)
	selectorApprove  = []byte{0x09, 0x5e, 0xa7, 0xb3} // approve(address,uint256)
	selectorBalanceOf = []byte{0x70, 0xa0, 0x82, 0x31} // balanceOf(address)

	// CclawStaking selectors
	selectorDeposit  = []byte{0xb6, 0xb5, 0x5f, 0x25} // deposit(uint256)
	selectorClaim    = []byte{0x4e, 0x71, 0xd9, 0x2d} // claim()
	selectorBalances = []byte{0x27, 0xe2, 0x35, 0xe3} // balances(address)

	// claimAmount(uint256) — computed via keccak256
	selectorClaimAmount = crypto.Keccak256([]byte("claimAmount(uint256)"))[:4]

	// Hardhat default owner (account #0)
	hardhatOwner = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
)

// ---------------------------------------------------------------------------
// queryTokenBalance returns the CclawToken.balanceOf(addr) result.
// ---------------------------------------------------------------------------

func queryTokenBalance(t *testing.T, hardhat *testutil.HardhatNode, tokenAddr, addr string) *big.Int {
	t.Helper()
	calldata := append(selectorBalanceOf, abiEncodeAddress(addr)...)
	result := hardhat.EthCall(t, tokenAddr, "0x"+hex.EncodeToString(calldata))
	return parseUint256(result)
}

// ---------------------------------------------------------------------------
// queryStakingBalance returns the CclawStaking.balances(addr) result.
// ---------------------------------------------------------------------------

func queryStakingBalance(t *testing.T, hardhat *testutil.HardhatNode, stakingAddr, addr string) *big.Int {
	t.Helper()
	calldata := append(selectorBalances, abiEncodeAddress(addr)...)
	result := hardhat.EthCall(t, stakingAddr, "0x"+hex.EncodeToString(calldata))
	return parseUint256(result)
}

// ---------------------------------------------------------------------------
// TestStaking_DepositClaim_FullCycle
//
// Comprehensive staking integration test covering:
//   - Deploy CclawToken + CclawStaking on Hardhat
//   - TSS DKG + HD derivation at m/44'/60'/0'/0/0
//   - Derive EVM address, fund with ETH
//   - Mint 1000 CCLAW, verify balance
//   - Approve staking contract for 1000 CCLAW
//   - Deposit 500 CCLAW, verify staking=500, token=500
//   - ClaimAmount 200 CCLAW, verify staking=300, token=700
//   - Claim all remaining, verify staking=0, token=1000
// ---------------------------------------------------------------------------

func TestStaking_DepositClaim_FullCycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	testutil.RequireHardhat(t)

	// ---------------------------------------------------------------
	// 1. Start Hardhat, deploy CclawToken and CclawStaking
	// ---------------------------------------------------------------
	hardhat := testutil.StartHardhat(t, "contracts/evm")

	tokenAddr := hardhat.DeployContract(t, "CclawToken")
	t.Logf("CclawToken deployed at: %s", tokenAddr)

	stakingAddr := hardhat.DeployContract(t, "CclawStaking", fmt.Sprintf(`"%s"`, tokenAddr))
	t.Logf("CclawStaking deployed at: %s", stakingAddr)

	// ---------------------------------------------------------------
	// 2. TSS DKG + derive
	// ---------------------------------------------------------------
	cluster := testutil.NewTestCluster(t)
	preParams := testutil.GenerateTestPreParams(t)
	protocol := testutil.NewTestProtocolWithPreParams(preParams)

	// Create context after pre-params generation (which can take minutes).
	// Use 20 minutes because this test performs DKG + 4 signing rounds.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	testutil.RunDKG(ctx, t, cluster, protocol, tss.CurveSecp256k1)

	derivationPath := "m/44'/60'/0'/0/0"
	pubKeyA, _ := testutil.RunDerive(ctx, t, cluster, protocol, tss.CurveSecp256k1, derivationPath)

	// ---------------------------------------------------------------
	// 3. Derive EVM address, fund with ETH for gas
	// ---------------------------------------------------------------
	adapter := evm.New()
	senderAddr, err := adapter.DeriveAddress(pubKeyA)
	if err != nil {
		t.Fatalf("derive EVM address: %v", err)
	}
	t.Logf("Derived sender address: %s", senderAddr)

	hardhat.FundAddress(t, senderAddr, "10")
	hardhat.MineBlock(t)

	// ---------------------------------------------------------------
	// 4. Mint 1000 CCLAW to the derived address (owner SendTx)
	// ---------------------------------------------------------------
	amount1000 := new(big.Int).Mul(big.NewInt(1000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	mintData := append(selectorMint, abiEncodeAddress(senderAddr)...)
	mintData = append(mintData, abiEncodeUint256(amount1000)...)

	hardhat.SendTx(t, hardhatOwner, tokenAddr, "0x"+hex.EncodeToString(mintData))
	hardhat.MineBlock(t)

	// ---------------------------------------------------------------
	// 5. Verify token balance = 1000e18
	// ---------------------------------------------------------------
	tokenBal := queryTokenBalance(t, hardhat, tokenAddr, senderAddr)
	if tokenBal.Cmp(amount1000) != 0 {
		t.Fatalf("expected token balance %s, got %s", amount1000, tokenBal)
	}
	t.Logf("Token balance after mint: %s", tokenBal)

	// Track nonce for TSS-signed transactions.
	var nonce uint64

	// ---------------------------------------------------------------
	// 6. Approve staking contract to spend 1000 CCLAW
	// ---------------------------------------------------------------
	approveData := append(selectorApprove, abiEncodeAddress(stakingAddr)...)
	approveData = append(approveData, abiEncodeUint256(amount1000)...)

	approveTx, err := adapter.BuildUnsignedTx(ctx, &vm.TxRequest{
		From:     senderAddr,
		To:       []string{tokenAddr},
		Data:     approveData,
		ChainID:  "31337",
		GasPrice: "20000000000", // 20 gwei
		GasLimit: 200000,
		Nonce:    nonce,
	})
	if err != nil {
		t.Fatal("build approve tx:", err)
	}
	signAndBroadcast(ctx, t, cluster, protocol, hardhat, adapter, approveTx, derivationPath)
	nonce++
	t.Log("Approve tx confirmed")

	// ---------------------------------------------------------------
	// 7. Deposit 500 CCLAW into staking
	// ---------------------------------------------------------------
	amount500 := new(big.Int).Mul(big.NewInt(500), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	depositData := append(selectorDeposit, abiEncodeUint256(amount500)...)

	depositTx, err := adapter.BuildUnsignedTx(ctx, &vm.TxRequest{
		From:     senderAddr,
		To:       []string{stakingAddr},
		Data:     depositData,
		ChainID:  "31337",
		GasPrice: "20000000000", // 20 gwei
		GasLimit: 200000,
		Nonce:    nonce,
	})
	if err != nil {
		t.Fatal("build deposit tx:", err)
	}
	signAndBroadcast(ctx, t, cluster, protocol, hardhat, adapter, depositTx, derivationPath)
	nonce++
	t.Log("Deposit tx confirmed")

	// ---------------------------------------------------------------
	// 8. Verify: staking balance = 500e18, token balance = 500e18
	// ---------------------------------------------------------------
	stakeBal := queryStakingBalance(t, hardhat, stakingAddr, senderAddr)
	tokenBal = queryTokenBalance(t, hardhat, tokenAddr, senderAddr)

	if stakeBal.Cmp(amount500) != 0 {
		t.Fatalf("expected staking balance %s, got %s", amount500, stakeBal)
	}
	if tokenBal.Cmp(amount500) != 0 {
		t.Fatalf("expected token balance %s, got %s", amount500, tokenBal)
	}
	t.Logf("After deposit: staking=%s, token=%s", stakeBal, tokenBal)

	// ---------------------------------------------------------------
	// 9. ClaimAmount 200 CCLAW
	// ---------------------------------------------------------------
	amount200 := new(big.Int).Mul(big.NewInt(200), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	claimAmountData := append(selectorClaimAmount, abiEncodeUint256(amount200)...)

	claimAmountTx, err := adapter.BuildUnsignedTx(ctx, &vm.TxRequest{
		From:     senderAddr,
		To:       []string{stakingAddr},
		Data:     claimAmountData,
		ChainID:  "31337",
		GasPrice: "20000000000", // 20 gwei
		GasLimit: 200000,
		Nonce:    nonce,
	})
	if err != nil {
		t.Fatal("build claimAmount tx:", err)
	}
	signAndBroadcast(ctx, t, cluster, protocol, hardhat, adapter, claimAmountTx, derivationPath)
	nonce++
	t.Log("ClaimAmount tx confirmed")

	// ---------------------------------------------------------------
	// 10. Verify: staking balance = 300e18, token balance = 700e18
	// ---------------------------------------------------------------
	amount300 := new(big.Int).Mul(big.NewInt(300), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	amount700 := new(big.Int).Mul(big.NewInt(700), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))

	stakeBal = queryStakingBalance(t, hardhat, stakingAddr, senderAddr)
	tokenBal = queryTokenBalance(t, hardhat, tokenAddr, senderAddr)

	if stakeBal.Cmp(amount300) != 0 {
		t.Fatalf("expected staking balance %s, got %s", amount300, stakeBal)
	}
	if tokenBal.Cmp(amount700) != 0 {
		t.Fatalf("expected token balance %s, got %s", amount700, tokenBal)
	}
	t.Logf("After claimAmount: staking=%s, token=%s", stakeBal, tokenBal)

	// ---------------------------------------------------------------
	// 11. Claim all remaining
	// ---------------------------------------------------------------
	// claim() takes no arguments, just the 4-byte selector
	claimData := make([]byte, 4)
	copy(claimData, selectorClaim)

	claimTx, err := adapter.BuildUnsignedTx(ctx, &vm.TxRequest{
		From:     senderAddr,
		To:       []string{stakingAddr},
		Data:     claimData,
		ChainID:  "31337",
		GasPrice: "20000000000", // 20 gwei
		GasLimit: 200000,
		Nonce:    nonce,
	})
	if err != nil {
		t.Fatal("build claim tx:", err)
	}
	signAndBroadcast(ctx, t, cluster, protocol, hardhat, adapter, claimTx, derivationPath)
	nonce++
	t.Log("Claim tx confirmed")

	// ---------------------------------------------------------------
	// 12. Verify: staking balance = 0, token balance = 1000e18
	// ---------------------------------------------------------------
	stakeBal = queryStakingBalance(t, hardhat, stakingAddr, senderAddr)
	tokenBal = queryTokenBalance(t, hardhat, tokenAddr, senderAddr)

	if stakeBal.Sign() != 0 {
		t.Fatalf("expected staking balance 0, got %s", stakeBal)
	}
	if tokenBal.Cmp(amount1000) != 0 {
		t.Fatalf("expected token balance %s, got %s", amount1000, tokenBal)
	}
	t.Logf("After claim all: staking=%s, token=%s", stakeBal, tokenBal)
	t.Log("Full staking cycle completed successfully")

	// Keep nonce variable referenced to suppress lint warning.
	_ = nonce
}

// ---------------------------------------------------------------------------
// Individual test functions — delegate to the full cycle test
// ---------------------------------------------------------------------------

// TestStaking_Deposit_EVM tests depositing CCLAW tokens into the staking contract.
func TestStaking_Deposit_EVM(t *testing.T) {
	t.Skip("covered by TestStaking_DepositClaim_FullCycle")
}

// TestStaking_Claim_EVM tests claiming tokens back from the staking contract.
func TestStaking_Claim_EVM(t *testing.T) {
	t.Skip("covered by TestStaking_DepositClaim_FullCycle")
}

// TestStaking_ClaimAmount_EVM tests partial claim from staking.
func TestStaking_ClaimAmount_EVM(t *testing.T) {
	t.Skip("covered by TestStaking_DepositClaim_FullCycle")
}
