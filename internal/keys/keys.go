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
	UNIQUE(platform, token, key_id)
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
	if err := s.addLastBoundAt(); err != nil {
		return err
	}
	return s.widenTokenUniqueness()
}

// addLastBoundAt adds the stamp PurgeUnused reads; a duplicate-column error means it exists.
func (s *Store) addLastBoundAt() error {
	_, err := s.db.Exec(`ALTER TABLE keys ADD COLUMN last_bound_at INTEGER`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return err
	}
	return nil
}

// widenTokenUniqueness rebuilds a tokens table created with UNIQUE(platform, token), which
// let only one key hold a token, into one unique per (platform, token, key_id) so several
// servers can share a device. Existing single-key bindings carry over unchanged.
func (s *Store) widenTokenUniqueness() error {
	var ddl string
	if err := s.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'tokens'`).Scan(&ddl); err != nil {
		return err
	}
	if !strings.Contains(ddl, "UNIQUE(platform, token)") {
		return nil
	}
	_, err := s.db.Exec(`
BEGIN;
CREATE TABLE tokens_wide (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	platform     TEXT NOT NULL,
	token        TEXT NOT NULL,
	key_id       INTEGER NOT NULL REFERENCES keys(id),
	created_at   INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL DEFAULT 0,
	UNIQUE(platform, token, key_id)
);
INSERT INTO tokens_wide (id, platform, token, key_id, created_at, last_seen_at)
	SELECT id, platform, token, key_id, created_at, last_seen_at FROM tokens;
DROP TABLE tokens;
ALTER TABLE tokens_wide RENAME TO tokens;
CREATE INDEX IF NOT EXISTS tokens_key_id ON tokens(key_id);
COMMIT;`)
	return err
}

// Issue mints a new key, stores only its hash, and returns the plaintext once. The
// plaintext is unrecoverable afterward. label is an unverified admin hint (the claimed
// public URL). max bounds the number of live keys, so revoking a key reopens its slot and
// /v1/register cannot grow the live key set without bound; zero or negative disables the
// ceiling. Returns ErrRegistrationCeiling once max is reached. The store logs when the count
// crosses 80% of max and again when it reaches max.
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

	var count int64
	if max > 0 {
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM keys WHERE revoked_at IS NULL`).Scan(&count); err != nil {
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
	if max > 0 {
		logCeilingProgress(count+1, max)
	}
	return plain, nil
}

// ceilingWarnPercent is how full the registration ceiling gets before the operator is told.
const ceilingWarnPercent = 80

func logCeilingProgress(issued, max int64) {
	switch issued {
	case max:
		log.Printf("relay: registration ceiling reached (%d keys); new servers are refused until keys are purged or RELAY_MAX_REGISTRATIONS is raised", max)
	case max * ceilingWarnPercent / 100:
		log.Printf("relay: %d of %d registrations used; purge unused keys (POST /admin/keys/purge-unused) or raise RELAY_MAX_REGISTRATIONS", issued, max)
	}
}

// stampInterval is how stale a last_used_at or last_seen_at stamp may get before it is
// written again. Each write is its own fsync'd commit on the relay's single connection, so
// refreshing a stamp on every request and every message made the hot path pay for
// bookkeeping nobody reads at sub-minute resolution.
const stampInterval = time.Minute

// Verify returns the key for a plaintext secret if it exists and is not revoked, stamping
// its last-used time at most once per stampInterval. Returns ErrNotFound for an unknown or
// revoked key.
//
// A stamp write doubles as a revocation gate: guarding it on revoked_at closes the window
// where a revoke lands between the scan and the write. A request that skips the write
// relies on BindTokens, which re-checks the key inside its own transaction before anything
// is dispatched.
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
	used := time.Now()
	if k.LastUsedAt != nil && used.Sub(*k.LastUsedAt) < stampInterval {
		return k, nil
	}
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

// Revoke marks a key unusable and releases its device-token bindings, so the devices it
// owned can be claimed by another key. Returns ErrNotFound if no such (unrevoked) key exists.
func (s *Store) Revoke(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`UPDATE keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM tokens WHERE key_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// PurgeUnused deletes keys that hold no bound token, were issued more than olderThan ago and
// have not bound one within that window, revoked or not, and returns how many it removed. A
// key that only ever authenticated or sent empty batches counts as unused, so squatted keys
// cannot hold the ceiling by touching last_used_at, while a key that really sent survives
// having all its tokens pruned. Key ids are never reused, so a purged key cannot come back
// as someone else's.
func (s *Store) PurgeUnused(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan).Unix()
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM keys WHERE created_at < ? AND (last_bound_at IS NULL OR last_bound_at < ?)
		 AND NOT EXISTS (SELECT 1 FROM tokens WHERE tokens.key_id = keys.id)`, cutoff, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ErrTokenLimit is returned by BindTokens when a key already holds its maximum of bound tokens.
var ErrTokenLimit = errors.New("keys: token limit reached")

// ErrRelayTokenLimit is returned by BindTokens when the relay as a whole holds its maximum
// of bound tokens, whichever keys hold them.
var ErrRelayTokenLimit = errors.New("keys: relay token limit reached")

// ErrTokenKeyLimit is returned by BindTokens when a token already has its maximum number of
// distinct keys bound and none of them is idle enough to make room.
var ErrTokenKeyLimit = errors.New("keys: token key limit reached")

// BindLimits are the bounds BindTokens applies. A zero or negative field disables that bound.
type BindLimits struct {
	// Retention is how long a binding may go untouched by its key before pruning may drop it.
	Retention time.Duration
	// MaxPerKey caps how many bindings one key may hold.
	MaxPerKey int
	// MaxTotal caps how many bindings the whole relay may hold.
	MaxTotal int
	// MaxKeysPerToken caps how many distinct keys may share one (platform, token).
	MaxKeysPerToken int
	// BindingIdle is how long a binding must be unused before a new key may take its slot
	// on a token that is at MaxKeysPerToken.
	BindingIdle time.Duration
}

// TokenRef names one device token a key wants to deliver to.
type TokenRef struct {
	Platform string
	Token    string
}

// BindToken binds one token; see BindTokens.
func (s *Store) BindToken(ctx context.Context, keyID int64, platform, token string, lim BindLimits) error {
	errs, err := s.BindTokens(ctx, keyID, []TokenRef{{Platform: platform, Token: token}}, lim)
	if err != nil {
		return err
	}
	return errs[0]
}

// Unbind removes keyID's bindings for refs, for tokens the provider reported dead, so fake
// tokens cannot pile up toward the relay-wide cap. Other keys' bindings are never touched.
func (s *Store) Unbind(ctx context.Context, keyID int64, refs []TokenRef) error {
	if len(refs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, ref := range refs {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM tokens WHERE platform = ? AND token = ? AND key_id = ?`, ref.Platform, ref.Token, keyID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// BindTokens enforces harassment-hardening for a whole batch in one transaction: a device
// push token is bound, per platform, to the keys that have sent to it, and a key may
// deliver to a token only through its own binding. Several keys may share a token, because
// one phone signed in to several servers hands the same token to each of them; a key never
// gains or loses anything by another key's binding, so a hostile server cannot hijack the
// token from a real one. The number of keys per token is capped, and a full token admits a
// new key only by replacing a binding that has been idle for lim.BindingIdle, so a hostile
// server cannot fill the slots and keep real servers out unless it keeps every one of its
// keys actively sending.
//
// It returns one error per ref, in order: nil when keyID may deliver to that token,
// ErrTokenKeyLimit when the token is full, ErrTokenLimit when keyID holds too many tokens.
// The returned error is ErrNotFound when keyID was revoked, in which case nothing was bound.
//
// A new binding is only ever written for a live key. Revoke deletes the key's bindings once,
// so a send that was already in flight would otherwise re-create them for a revoked key.
//
// A legitimate send from a key refreshes its own binding's clock, at most once per
// stampInterval, so an actively used token is never at risk of pruning.
//
// The read-then-write here is race-free because Open sets SetMaxOpenConns(1): the whole
// relay shares one connection, so this transaction can never interleave with another.
func (s *Store) BindTokens(ctx context.Context, keyID int64, refs []TokenRef, lim BindLimits) ([]error, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var live int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM keys WHERE id = ? AND revoked_at IS NULL`, keyID).Scan(&live)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	if len(refs) > 0 {
		_, err = tx.ExecContext(ctx,
			`UPDATE keys SET last_bound_at = ? WHERE id = ? AND (last_bound_at IS NULL OR last_bound_at < ?)`,
			now, keyID, now-int64(stampInterval.Seconds()))
		if err != nil {
			return nil, err
		}
	}
	outcomes := make([]error, len(refs))
	counts := &bindCounts{}
	for i, ref := range refs {
		outcomes[i], err = bindOne(ctx, tx, keyID, ref, now, lim, counts)
		if err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.maybePruneStaleTokens(ctx, lim.Retention)
	return outcomes, nil
}

// bindOne refreshes or creates one binding. The first return is the refusal for this token
// alone, the second a failure that must abandon the whole transaction.
func bindOne(ctx context.Context, tx *sql.Tx, keyID int64, ref TokenRef, now int64, lim BindLimits, counts *bindCounts) (refusal, fatal error) {
	var seen int64
	err := tx.QueryRowContext(ctx,
		`SELECT last_seen_at FROM tokens WHERE platform = ? AND token = ? AND key_id = ?`,
		ref.Platform, ref.Token, keyID).Scan(&seen)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		err = insertBinding(ctx, tx, keyID, ref, now, lim, counts)
		if errors.Is(err, ErrTokenLimit) || errors.Is(err, ErrRelayTokenLimit) || errors.Is(err, ErrTokenKeyLimit) {
			return err, nil
		}
		return nil, err
	case err != nil:
		return nil, err
	case now-seen < int64(stampInterval.Seconds()):
		return nil, nil
	}
	_, err = tx.ExecContext(ctx,
		`UPDATE tokens SET last_seen_at = ? WHERE platform = ? AND token = ? AND key_id = ?`,
		now, ref.Platform, ref.Token, keyID)
	return nil, err
}

// bindCounts caches, for one BindTokens transaction, how many bindings the key and the whole
// relay hold, so a batch of new tokens runs one COUNT each instead of one per token. The
// single connection means nothing else writes between the read and the batch's own inserts.
type bindCounts struct {
	loaded     bool
	key, total int
}

func (c *bindCounts) load(ctx context.Context, tx *sql.Tx, keyID int64, lim BindLimits) error {
	if c.loaded {
		return nil
	}
	if lim.MaxPerKey > 0 {
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM tokens WHERE key_id = ?`, keyID).Scan(&c.key); err != nil {
			return err
		}
	}
	if lim.MaxTotal > 0 {
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM tokens`).Scan(&c.total); err != nil {
			return err
		}
	}
	c.loaded = true
	return nil
}

func insertBinding(ctx context.Context, tx *sql.Tx, keyID int64, ref TokenRef, now int64, lim BindLimits, counts *bindCounts) error {
	platform, token := ref.Platform, ref.Token
	if err := counts.load(ctx, tx, keyID, lim); err != nil {
		return err
	}
	if lim.MaxPerKey > 0 && counts.key >= lim.MaxPerKey {
		return ErrTokenLimit
	}
	if lim.MaxTotal > 0 && counts.total >= lim.MaxTotal {
		return ErrRelayTokenLimit
	}
	if lim.MaxKeysPerToken > 0 {
		var holders int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM tokens WHERE platform = ? AND token = ?`, platform, token).Scan(&holders); err != nil {
			return err
		}
		if holders >= lim.MaxKeysPerToken {
			if lim.BindingIdle <= 0 {
				return ErrTokenKeyLimit
			}
			cutoff := now - int64(lim.BindingIdle.Seconds())
			res, err := tx.ExecContext(ctx,
				`DELETE FROM tokens WHERE id = (SELECT id FROM tokens WHERE platform = ? AND token = ? AND last_seen_at < ?
				 ORDER BY last_seen_at LIMIT 1)`, platform, token, cutoff)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return ErrTokenKeyLimit
			}
			counts.total--
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO tokens (platform, token, key_id, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?)`,
		platform, token, keyID, now, now); err != nil {
		return err
	}
	counts.key++
	counts.total++
	return nil
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
