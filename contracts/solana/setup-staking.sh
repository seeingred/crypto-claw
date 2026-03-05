#!/usr/bin/env bash
# setup-staking.sh - Simple staking via SPL token delegation on local validator.
# For integration tests, staking is simulated by transferring tokens to a
# designated "staking vault" account and tracking balances off-chain.
#
# Usage: ./setup-staking.sh <token_mint> [keypair_path]

set -euo pipefail

TOKEN_MINT="${1:?Usage: setup-staking.sh <token_mint> [keypair_path]}"
KEYPAIR="${2:-$HOME/.config/solana/id.json}"
RPC="http://127.0.0.1:8899"

echo "==> Setting up staking vault for token: $TOKEN_MINT"

# Generate a new keypair for the staking vault.
VAULT_KEYPAIR=$(mktemp /tmp/vault-XXXXXX.json)
solana-keygen new --no-bip39-passphrase --outfile "$VAULT_KEYPAIR" --force --silent

VAULT_PUBKEY=$(solana-keygen pubkey "$VAULT_KEYPAIR")
echo "==> Staking Vault Pubkey: $VAULT_PUBKEY"

# Fund the vault with SOL for rent.
solana airdrop 1 "$VAULT_PUBKEY" --url "$RPC" 2>/dev/null || true

# Create token account for the vault.
VAULT_TOKEN_ACCOUNT=$(spl-token create-account "$TOKEN_MINT" \
  --owner "$VAULT_PUBKEY" \
  --keypair "$VAULT_KEYPAIR" \
  --url "$RPC" \
  2>&1 | grep "Creating account" | awk '{print $3}')

echo "==> Vault Token Account: $VAULT_TOKEN_ACCOUNT"
echo ""
echo "VAULT_PUBKEY=$VAULT_PUBKEY"
echo "VAULT_KEYPAIR=$VAULT_KEYPAIR"
echo "VAULT_TOKEN_ACCOUNT=$VAULT_TOKEN_ACCOUNT"
