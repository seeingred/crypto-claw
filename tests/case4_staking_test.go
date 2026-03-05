package tests

import (
	"context"
	"testing"
	"time"

	"github.com/seeingred/crypto-claw/internal/vm/evm"
	"github.com/seeingred/crypto-claw/tests/testutil"
)

// TestStaking_Deposit_EVM tests depositing CCLAW tokens into the staking contract.
//
// Flow:
// 1. Start Hardhat, deploy CclawToken + CclawStaking
// 2. Run DKG, derive EVM address
// 3. Mint CCLAW tokens to derived address
// 4. Approve staking contract to spend tokens
// 5. Call deposit(amount) on staking contract
// 6. Verify staking balance increased, token balance decreased
func TestStaking_Deposit_EVM(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Skip("requires TSS protocol implementation, Hardhat, and deployed contracts")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cluster := testutil.NewTestCluster(t)
	_ = ctx

	// Step 1: Start Hardhat, deploy contracts.
	// hardhat := testutil.StartHardhat(t, "contracts/evm")
	// tokenAddr := hardhat.DeployContract(t, "CclawToken")
	// stakingAddr := hardhat.DeployContract(t, "CclawStaking", fmt.Sprintf(`"%s"`, tokenAddr))

	// Step 2: DKG + derive.
	adapter := evm.New()
	_ = adapter
	// var protocol tss.Protocol = tssimpl.New()
	// testutil.RunDKG(ctx, t, cluster, protocol, tss.CurveSecp256k1)
	// shareA, _ := cluster.PartyA.GetKeyShare(tss.CurveSecp256k1)
	// senderAddr, _ := adapter.DeriveAddress(shareA.PublicKey)
	// hardhat.FundAddress(t, senderAddr, "1") // for gas

	// Step 3: Mint CCLAW.
	// ... mint 1000 CCLAW to senderAddr

	// Step 4: Approve staking contract.
	// approve(address,uint256) selector: 0x095ea7b3
	// approveData := buildApproveCalldata(stakingAddr, "1000000000000000000000")
	// ... build, sign, broadcast approve tx

	// Step 5: Deposit.
	// deposit(uint256) selector: 0xb6b55f25
	// depositData := buildDepositCalldata("500000000000000000000") // 500 CCLAW
	// ... build, sign, broadcast deposit tx

	// Step 6: Verify.
	// Query balances(senderAddr) on staking contract should return 500e18
	// Query balanceOf(senderAddr) on token contract should return 500e18

	_ = cluster
}

// TestStaking_Claim_EVM tests claiming tokens back from the staking contract.
//
// Flow:
// 1. Setup (same as deposit test)
// 2. Deposit tokens
// 3. Call claim() on staking contract
// 4. Verify staking balance is 0, token balance restored
func TestStaking_Claim_EVM(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Skip("requires TSS protocol implementation, Hardhat, and deployed contracts")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cluster := testutil.NewTestCluster(t)
	_ = ctx

	// After depositing 500 CCLAW...

	// Step 3: Claim all.
	// claim() selector: 0x4e71d92d
	// claimData := []byte{0x4e, 0x71, 0xd9, 0x2d}
	// ... build, sign, broadcast claim tx

	// Step 4: Verify.
	// balances(senderAddr) == 0
	// balanceOf(senderAddr) == 1000e18 (original amount restored)

	_ = cluster
}

// TestStaking_ClaimAmount_EVM tests partial claim from staking.
func TestStaking_ClaimAmount_EVM(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Skip("requires TSS protocol implementation, Hardhat, and deployed contracts")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cluster := testutil.NewTestCluster(t)
	_ = ctx

	// After depositing 500 CCLAW...

	// Claim 200 CCLAW.
	// claimAmount(uint256) selector: 0x...
	// ... build, sign, broadcast claimAmount(200e18) tx

	// Verify:
	// staking balances(senderAddr) == 300e18
	// token balanceOf(senderAddr) == 700e18

	_ = cluster
}

// TestStaking_DepositClaim_FullCycle runs the complete deposit-claim cycle.
func TestStaking_DepositClaim_FullCycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Skip("requires TSS protocol implementation, Hardhat, and deployed contracts")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cluster := testutil.NewTestCluster(t)
	_ = ctx
	_ = cluster

	// Full cycle test:
	// 1. Deploy token + staking
	// 2. DKG -> derive address
	// 3. Mint 1000 CCLAW
	// 4. Approve staking for 1000 CCLAW
	// 5. Deposit 500 CCLAW -> verify staking=500, token=500
	// 6. Deposit 300 more -> verify staking=800, token=200
	// 7. ClaimAmount 400 -> verify staking=400, token=600
	// 8. Claim all -> verify staking=0, token=1000
}

// Ensure imports compile.
var _ = evm.New
