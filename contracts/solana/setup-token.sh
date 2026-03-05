#!/usr/bin/env bash
# setup-token.sh - Create SPL CCLAW token on local solana-test-validator.
# Usage: ./setup-token.sh [keypair_path]
#
# Prerequisites: solana-cli, spl-token CLI installed.

set -euo pipefail

KEYPAIR="${1:-$HOME/.config/solana/id.json}"
RPC="http://127.0.0.1:8899"

echo "==> Using keypair: $KEYPAIR"
echo "==> RPC: $RPC"

# Airdrop SOL to the keypair for fees.
solana airdrop 10 --keypair "$KEYPAIR" --url "$RPC" 2>/dev/null || true

# Create the CCLAW SPL token (fungible, 9 decimals).
TOKEN_MINT=$(spl-token create-token \
  --decimals 9 \
  --keypair "$KEYPAIR" \
  --url "$RPC" \
  2>&1 | grep "Creating token" | awk '{print $3}')

echo "==> CCLAW Token Mint: $TOKEN_MINT"

# Create an associated token account for the deployer.
ACCOUNT=$(spl-token create-account "$TOKEN_MINT" \
  --keypair "$KEYPAIR" \
  --url "$RPC" \
  2>&1 | grep "Creating account" | awk '{print $3}')

echo "==> Deployer Token Account: $ACCOUNT"

# Mint 1,000,000 CCLAW tokens to the deployer.
spl-token mint "$TOKEN_MINT" 1000000 \
  --keypair "$KEYPAIR" \
  --url "$RPC"

echo "==> Minted 1,000,000 CCLAW tokens"
echo ""
echo "TOKEN_MINT=$TOKEN_MINT"
echo "TOKEN_ACCOUNT=$ACCOUNT"
