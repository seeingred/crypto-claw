package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seeingred/crypto-claw/internal/tss"
	"golang.org/x/crypto/pbkdf2"
)

// PostgresStore implements Store using PostgreSQL with AES-256-GCM encryption for key shares.
type PostgresStore struct {
	pool      *pgxpool.Pool
	encKey    []byte // 32-byte AES-256 key derived from passphrase
}

// NewPostgresStore creates a new PostgreSQL store and auto-migrates the schema.
func NewPostgresStore(ctx context.Context, dsn string, passphrase string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	encKey := deriveKey(passphrase)

	s := &PostgresStore{
		pool:   pool,
		encKey: encKey,
	}

	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate schema: %w", err)
	}

	return s, nil
}

func deriveKey(passphrase string) []byte {
	salt := []byte("crypto-claw-v1") // Static salt; passphrase should be strong.
	return pbkdf2.Key([]byte(passphrase), salt, 600000, 32, sha256.New)
}

func (s *PostgresStore) migrate(ctx context.Context) error {
	schema := `
		CREATE TABLE IF NOT EXISTS master_shares (
			curve       TEXT PRIMARY KEY,
			party_id    TEXT NOT NULL,
			party_index INTEGER NOT NULL,
			share       BYTEA NOT NULL,
			public_key  BYTEA NOT NULL,
			chain_code  BYTEA NOT NULL,
			created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);

		CREATE TABLE IF NOT EXISTS derived_keys (
			derivation_path TEXT PRIMARY KEY,
			curve           TEXT NOT NULL,
			public_key      BYTEA NOT NULL,
			address         TEXT NOT NULL DEFAULT '',
			label           TEXT NOT NULL DEFAULT '',
			share           BYTEA NOT NULL,
			created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);

		CREATE TABLE IF NOT EXISTS transactions (
			id              TEXT PRIMARY KEY,
			derivation_path TEXT NOT NULL,
			to_addrs        TEXT[] NOT NULL DEFAULT '{}',
			value           TEXT NOT NULL DEFAULT '',
			data            TEXT NOT NULL DEFAULT '',
			unsigned_tx     BYTEA,
			signed_tx       BYTEA,
			status          TEXT NOT NULL DEFAULT 'pending_review',
			reason          TEXT NOT NULL DEFAULT '',
			created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);

		CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);
		CREATE INDEX IF NOT EXISTS idx_transactions_derivation_path ON transactions(derivation_path);
	`
	_, err := s.pool.Exec(ctx, schema)
	return err
}

// encrypt encrypts data using AES-256-GCM.
func (s *PostgresStore) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.encKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decrypt decrypts AES-256-GCM encrypted data.
func (s *PostgresStore) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.encKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// SaveMasterShare stores a master key share (encrypted).
func (s *PostgresStore) SaveMasterShare(ctx context.Context, share *tss.KeyShare) error {
	encrypted, err := s.encrypt(share.Share)
	if err != nil {
		return fmt.Errorf("encrypt share: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO master_shares (curve, party_id, party_index, share, public_key, chain_code)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (curve) DO UPDATE SET
			party_id = EXCLUDED.party_id,
			party_index = EXCLUDED.party_index,
			share = EXCLUDED.share,
			public_key = EXCLUDED.public_key,
			chain_code = EXCLUDED.chain_code
	`, string(share.Curve), share.PartyID.ID, share.PartyID.Index, encrypted, share.PublicKey, share.ChainCode)

	return err
}

// GetMasterShare retrieves a master key share by curve.
func (s *PostgresStore) GetMasterShare(ctx context.Context, curve tss.Curve) (*tss.KeyShare, error) {
	var (
		partyIDStr string
		partyIndex int
		encrypted  []byte
		publicKey  []byte
		chainCode  []byte
	)

	err := s.pool.QueryRow(ctx, `
		SELECT party_id, party_index, share, public_key, chain_code
		FROM master_shares WHERE curve = $1
	`, string(curve)).Scan(&partyIDStr, &partyIndex, &encrypted, &publicKey, &chainCode)
	if err != nil {
		return nil, fmt.Errorf("get master share: %w", err)
	}

	shareData, err := s.decrypt(encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt share: %w", err)
	}

	return &tss.KeyShare{
		Curve:     curve,
		PartyID:   tss.PartyID{ID: partyIDStr, Index: partyIndex},
		Share:     shareData,
		PublicKey: publicKey,
		ChainCode: chainCode,
	}, nil
}

// SaveDerivedKey stores a derived child key.
func (s *PostgresStore) SaveDerivedKey(ctx context.Context, key *DerivedKeyRecord) error {
	encrypted, err := s.encrypt(key.Share)
	if err != nil {
		return fmt.Errorf("encrypt derived key share: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO derived_keys (derivation_path, curve, public_key, address, label, share, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (derivation_path) DO UPDATE SET
			public_key = EXCLUDED.public_key,
			address = EXCLUDED.address,
			label = EXCLUDED.label,
			share = EXCLUDED.share
	`, key.DerivationPath, string(key.Curve), key.PublicKey, key.Address, key.Label, encrypted, key.CreatedAt)

	return err
}

// GetDerivedKey retrieves a derived key by path.
func (s *PostgresStore) GetDerivedKey(ctx context.Context, derivationPath string) (*DerivedKeyRecord, error) {
	var (
		curve     string
		publicKey []byte
		address   string
		label     string
		encrypted []byte
		createdAt time.Time
	)

	err := s.pool.QueryRow(ctx, `
		SELECT curve, public_key, address, label, share, created_at
		FROM derived_keys WHERE derivation_path = $1
	`, derivationPath).Scan(&curve, &publicKey, &address, &label, &encrypted, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("get derived key: %w", err)
	}

	shareData, err := s.decrypt(encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt derived key share: %w", err)
	}

	return &DerivedKeyRecord{
		DerivationPath: derivationPath,
		Curve:          tss.Curve(curve),
		PublicKey:      publicKey,
		Address:        address,
		Label:          label,
		Share:          shareData,
		CreatedAt:      createdAt,
	}, nil
}

// ListDerivedKeys returns all derived keys.
func (s *PostgresStore) ListDerivedKeys(ctx context.Context) ([]*DerivedKeyRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT derivation_path, curve, public_key, address, label, share, created_at
		FROM derived_keys ORDER BY created_at
	`)
	if err != nil {
		return nil, fmt.Errorf("list derived keys: %w", err)
	}
	defer rows.Close()

	var keys []*DerivedKeyRecord
	for rows.Next() {
		var (
			path      string
			curve     string
			publicKey []byte
			address   string
			label     string
			encrypted []byte
			createdAt time.Time
		)
		if err := rows.Scan(&path, &curve, &publicKey, &address, &label, &encrypted, &createdAt); err != nil {
			return nil, err
		}
		shareData, err := s.decrypt(encrypted)
		if err != nil {
			return nil, fmt.Errorf("decrypt derived key: %w", err)
		}
		keys = append(keys, &DerivedKeyRecord{
			DerivationPath: path,
			Curve:          tss.Curve(curve),
			PublicKey:      publicKey,
			Address:        address,
			Label:          label,
			Share:          shareData,
			CreatedAt:      createdAt,
		})
	}
	return keys, rows.Err()
}

// UpdateLabel updates the label for a derived key.
func (s *PostgresStore) UpdateLabel(ctx context.Context, derivationPath string, label string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE derived_keys SET label = $1 WHERE derivation_path = $2
	`, label, derivationPath)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("derived key not found: %s", derivationPath)
	}
	return nil
}

// SaveTx stores a transaction record.
func (s *PostgresStore) SaveTx(ctx context.Context, tx *TxRecord) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO transactions (id, derivation_path, to_addrs, value, data, unsigned_tx, signed_tx, status, reason, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO UPDATE SET
			status = EXCLUDED.status,
			signed_tx = EXCLUDED.signed_tx,
			reason = EXCLUDED.reason,
			updated_at = EXCLUDED.updated_at
	`, tx.ID, tx.DerivationPath, tx.To, tx.Value, tx.Data, tx.UnsignedTx, tx.SignedTx,
		string(tx.Status), tx.Reason, tx.CreatedAt, tx.UpdatedAt)
	return err
}

// GetTx retrieves a transaction by ID.
func (s *PostgresStore) GetTx(ctx context.Context, txID string) (*TxRecord, error) {
	var tx TxRecord
	var status string
	err := s.pool.QueryRow(ctx, `
		SELECT id, derivation_path, to_addrs, value, data, unsigned_tx, signed_tx, status, reason, created_at, updated_at
		FROM transactions WHERE id = $1
	`, txID).Scan(&tx.ID, &tx.DerivationPath, &tx.To, &tx.Value, &tx.Data,
		&tx.UnsignedTx, &tx.SignedTx, &status, &tx.Reason, &tx.CreatedAt, &tx.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get transaction: %w", err)
	}
	tx.Status = TxStatus(status)
	return &tx, nil
}

// UpdateTxStatus updates a transaction's status and optionally its signed data.
func (s *PostgresStore) UpdateTxStatus(ctx context.Context, txID string, status TxStatus, signedTx []byte) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE transactions SET status = $1, signed_tx = $2, updated_at = NOW()
		WHERE id = $3
	`, string(status), signedTx, txID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("transaction not found: %s", txID)
	}
	return nil
}

// ListTxs returns transactions with optional filtering.
func (s *PostgresStore) ListTxs(ctx context.Context, filter TxFilter) ([]*TxRecord, error) {
	query := `SELECT id, derivation_path, to_addrs, value, data, unsigned_tx, signed_tx, status, reason, created_at, updated_at FROM transactions WHERE 1=1`
	args := []any{}
	argN := 1

	if filter.Status != nil {
		query += fmt.Sprintf(" AND status = $%d", argN)
		args = append(args, string(*filter.Status))
		argN++
	}
	if filter.DerivationPath != nil {
		query += fmt.Sprintf(" AND derivation_path = $%d", argN)
		args = append(args, *filter.DerivationPath)
		argN++
	}

	query += " ORDER BY created_at DESC"

	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argN)
		args = append(args, filter.Limit)
		argN++
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argN)
		args = append(args, filter.Offset)
		argN++
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list transactions: %w", err)
	}
	defer rows.Close()

	var txs []*TxRecord
	for rows.Next() {
		var tx TxRecord
		var status string
		if err := rows.Scan(&tx.ID, &tx.DerivationPath, &tx.To, &tx.Value, &tx.Data,
			&tx.UnsignedTx, &tx.SignedTx, &status, &tx.Reason, &tx.CreatedAt, &tx.UpdatedAt); err != nil {
			return nil, err
		}
		tx.Status = TxStatus(status)
		txs = append(txs, &tx)
	}
	return txs, rows.Err()
}

// DeleteTx removes a transaction record.
func (s *PostgresStore) DeleteTx(ctx context.Context, txID string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM transactions WHERE id = $1`, txID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("transaction not found: %s", txID)
	}
	return nil
}

// ClearDerivedKeys removes all derived keys.
func (s *PostgresStore) ClearDerivedKeys(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM derived_keys`)
	return err
}

// Close closes the database connection pool.
func (s *PostgresStore) Close() error {
	s.pool.Close()
	return nil
}

// Verify interface compliance.
var _ Store = (*PostgresStore)(nil)
