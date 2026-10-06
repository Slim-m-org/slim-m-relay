// SPDX-License-Identifier: Apache-2.0

// Package keys stores the registration keys the relay hands out, and the device-token
// bindings that keep one self-hosted server from harassing another server's devices. Only
// a SHA-256 hash of each key is kept, so a leak of the database never yields a usable key.
// SQLite (pure-Go modernc driver) keeps the relay a single container with no extra
// database to run.
package keys

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// keyPrefix makes an issued key recognisable in logs and configs without revealing it.
const keyPrefix = "smr_"

// ErrNotFound is returned for an unknown, or revoked, key.
var ErrNotFound = errors.New("key not found")

// ErrRegistrationCeiling is returned by Issue when minting another key would exceed the
// configured maximum number of keys the relay will ever issue.
var ErrRegistrationCeiling = errors.New("registration ceiling reached")

// Key is one issued registration key. It never carries the plaintext or the hash. Label is
// the public URL the registrant claimed, kept unverified purely to help an admin tell keys
// apart.
type Key struct {
	ID         int64      `json:"id"`
	Label      string     `json:"label"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
}

// Store is the SQLite-backed key store.
type Store struct {
	db *sql.DB

	// pruneMu guards lastPrune, the lazy-sweep gate for stale token bindings, the same way
	// ratelimit.Limiter gates its own idle-bucket sweep: a background loop would be one more
	// thing to start and stop cleanly, so pruning instead piggybacks on BindToken calls, at
	// most once per pruneInterval.
	pruneMu   sync.Mutex
	lastPrune time.Time
}

// pruneInterval bounds how often BindToken's lazy sweep actually runs the DELETE, so a busy
// relay isn't scanning the tokens table on every single call.
const pruneInterval = time.Hour

// Open opens (creating if needed) the key store at path and applies its schema.
func Open(path string) (*Store, error) {
	// busy_timeout lets a writer wait rather than fail under contention; WAL keeps reads
	// from blocking the occasional write; temp_store=MEMORY avoids needing a writable temp
	// dir, which the distroless runtime image does not provide.
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=temp_store(MEMORY)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// modernc/sqlite serialises writes on one connection cleanly; a small pool avoids
	// "database is locked" without extra coordination, and lets BindToken's read-then-write
	// stay race-free without needing SQLite-level locking of its own.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, lastPrune: time.Now()}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the underlying database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS keys (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	key_hash     TEXT NOT NULL UNIQUE,
	label        TEXT NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL,
	last_used_at INTEGER,
	revoked_at   INTEGER
);
CREATE TABLE IF NOT EXISTS tokens (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	platform     TEXT NOT NULL,
	token        TEXT NOT NULL,
	key_id       INTEGER NOT NULL REFERENCES keys(id),
	created_at   INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL DEFAULT 0,
	UNIQUE(platform, token)
);
CREATE INDEX IF NOT EXISTS tokens_key_id ON tokens(key_id);`)
	if err != nil {
		return err
	}
	// A store created before last_seen_at existed has the tokens table but not the column;
	// add it defensively so opening an already-deployed database does not fail. SQLite has no
	// "ADD COLUMN IF NOT EXISTS" - a duplicate-column error here just means a fresh store's
	// CREATE TABLE above already included it.
	_, alterErr := s.db.Exec(`ALTER TABLE tokens ADD COLUMN last_seen_at INTEGER NOT NULL DEFAULT 0`)
	switch {
	case alterErr == nil:
		// The column was just added, so every existing row backfilled to 0 and would look
		// older than any retention window. Pruning would then delete the whole table on the
		// first sweep, destroying the token-to-key bindings that stop one key from pushing
		// to another key's device. Treat rows that predate the column as seen now, which
		// gives them a full retention window to be re-bound by real traffic.
		if _, err := s.db.Exec(
			`UPDATE tokens SET last_seen_at = ? WHERE last_seen_at = 0`, time.Now().Unix(),
		); err != nil {
			return err
		}
	case !strings.Contains(alterErr.Error(), "duplicate column name"):
		return alterErr
	}
	return nil
}

// Issue mints a new key, stores only its hash, and returns the plaintext once. The
// plaintext is unrecoverable afterward. label is an unverified admin hint (the claimed
// public URL). max bounds the total number of keys this store will ever issue - including
// revoked ones, since revoking a key does not reopen the slot it used - so /v1/register
// cannot grow the key table without bound; zero or negative disables the ceiling. Returns
// ErrRegistrationCeiling once max is reached.
//
// The count-then-insert runs in one transaction, race-free for the same reason BindToken is
// (see Open): the whole relay shares one connection, so a second Issue call blocks until
// this one commits rather than reading a stale count.
func (s *Store) Issue(ctx context.Context, label string, max int64) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	plain := keyPrefix + base64.RawURLEncoding.EncodeToString(raw)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()

	if max > 0 {
		var count int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM keys`).Scan(&count); err != nil {
			return "", err
		}
		if count >= max {
			return "", ErrRegistrationCeiling
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO keys (key_hash, label, created_at) VALUES (?, ?, ?)`,
		hashKey(plain), label, time.Now().Unix()); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return plain, nil
}

// Verify returns the key for a plaintext secret if it exists and is not revoked, stamping
// its last-used time. Returns ErrNotFound for an unknown or revoked key.
func (s *Store) Verify(ctx context.Context, plain string) (*Key, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, label, created_at, last_used_at, revoked_at FROM keys WHERE key_hash = ?`,
		hashKey(plain))
	k, err := scanKey(row)
	if err != nil {
		return nil, err
	}
	if k.RevokedAt != nil {
		return nil, ErrNotFound
	}
	// The stamp doubles as the revocation gate: guarding on revoked_at closes the window
	// where a revoke lands between the scan above and this write, so a just-revoked key
	// cannot slip one more send through, and a write failure refuses rather than trusting
	// the possibly stale scan.
	used := time.Now()
	res, err := s.db.ExecContext(ctx,
		`UPDATE keys SET last_used_at = ? WHERE id = ? AND revoked_at IS NULL`,
		used.Unix(), k.ID)
	if err != nil {
		return nil, err
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return nil, ErrNotFound
	}
	t := time.Unix(used.Unix(), 0)
	k.LastUsedAt = &t
	return k, nil
}

// Ping answers whether the store can actually serve a query right now, for the health
// endpoint: a relay whose database has become unreadable or unwritable used to stay
// green on /healthz while every register and verify failed.
func (s *Store) Ping(ctx context.Context) error {
	var one int
	return s.db.QueryRowContext(ctx, `SELECT 1`).Scan(&one)
}

// List returns every issued key, newest first, for the admin view.
func (s *Store) List(ctx context.Context) ([]Key, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, label, created_at, last_used_at, revoked_at FROM keys ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Key
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

// Revoke marks a key unusable. Returns ErrNotFound if no such (unrevoked) key exists.
func (s *Store) Revoke(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ErrTokenLimit is returned by BindToken when a key already holds its maximum of bound tokens.
var ErrTokenLimit = errors.New("keys: token limit reached")

// BindToken enforces harassment-hardening: a device push token is bound, per platform, to
// whichever key first sends to it, and every later send for that token must come from the
// same key. It returns the id of the key that owns the token - keyID itself on a fresh
// binding, or the original owner if the token was already claimed by someone else - so the
// caller can compare the two and reject a mismatch without a second round trip.
//
// maxPerKey caps how many bindings keyID may hold; a new token past it gets ErrTokenLimit
// and a token the key already owns still succeeds. Zero or negative disables the cap.
//
// retention bounds how long a binding may go untouched by its owning key before it becomes
// eligible for pruning (see maybePruneStaleTokens); zero or negative disables pruning. A
// legitimate send from the owning key always refreshes the token's clock, so an actively
// used token is never at risk regardless of how old the binding is.
//
// The read-then-write here is race-free because Open sets SetMaxOpenConns(1): the whole
// relay shares one connection, so this transaction can never interleave with another.
func (s *Store) BindToken(ctx context.Context, keyID int64, platform, token string, retention time.Duration, maxPerKey int) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().Unix()
	var owner int64
	err = tx.QueryRowContext(ctx,
		`SELECT key_id FROM tokens WHERE platform = ? AND token = ?`, platform, token).Scan(&owner)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if maxPerKey > 0 {
			var bound int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM tokens WHERE key_id = ?`, keyID).Scan(&bound); err != nil {
				return 0, err
			}
			if bound >= maxPerKey {
				return 0, ErrTokenLimit
			}
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO tokens (platform, token, key_id, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?)`,
			platform, token, keyID, now, now); err != nil {
			return 0, err
		}
		owner = keyID
	case err != nil:
		return 0, err
	default:
		if owner == keyID {
			// Only the owning key's own sends push the token's clock forward, so a different
			// key merely naming a token it does not own - and being refused for it - can't keep
			// an otherwise-abandoned binding alive forever.
			if _, err := tx.ExecContext(ctx,
				`UPDATE tokens SET last_seen_at = ? WHERE platform = ? AND token = ?`, now, platform, token); err != nil {
				return 0, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	s.maybePruneStaleTokens(ctx, retention)
	return owner, nil
}

// maybePruneStaleTokens opportunistically deletes token bindings nobody has sent to within
// retention, at most once per pruneInterval so a busy relay isn't scanning the tokens table
// on every call. Unlike the keys table, which MaxRegistrations bounds directly, tokens grow
// at a rate the caller controls with every send, and nothing on the happy path ever deletes
// a row - so without this the table grows without bound. A dead device token is worthless
// once the provider reports it unregistered and the caller stops sending to it, which is
// exactly what lets it go quiet long enough to be pruned safely.
func (s *Store) maybePruneStaleTokens(ctx context.Context, retention time.Duration) {
	if retention <= 0 {
		return
	}
	s.pruneMu.Lock()
	due := time.Since(s.lastPrune) >= pruneInterval
	if due {
		s.lastPrune = time.Now()
	}
	s.pruneMu.Unlock()
	if !due {
		return
	}
	cutoff := time.Now().Add(-retention).Unix()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM tokens WHERE last_seen_at < ?`, cutoff); err != nil {
		log.Printf("relay: prune stale tokens: %v", err)
	}
}

func hashKey(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanKey(r rowScanner) (*Key, error) {
	var (
		k        Key
		created  int64
		lastUsed sql.NullInt64
		revoked  sql.NullInt64
	)
	if err := r.Scan(&k.ID, &k.Label, &created, &lastUsed, &revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	k.CreatedAt = time.Unix(created, 0)
	if lastUsed.Valid {
		t := time.Unix(lastUsed.Int64, 0)
		k.LastUsedAt = &t
	}
	if revoked.Valid {
		t := time.Unix(revoked.Int64, 0)
		k.RevokedAt = &t
	}
	return &k, nil
}
