package auth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dian/securedb/internal/security"
)

const SessionCookie = "sdb_session"

type Session struct {
	ID        string
	UserID    string
	CSRFToken string
	ExpiresAt time.Time
}

// TTLFunc resolves the current session lifetimes (absolute, idle). Wired to
// the app_settings table so admins can tune timeouts without a restart.
type TTLFunc func(ctx context.Context) (ttl, idleTTL time.Duration)

// Store keeps sessions server-side in the app database. The browser only
// holds an opaque random token; the DB stores its SHA-256 hash.
type Store struct {
	pool *pgxpool.Pool
	ttls TTLFunc
}

func NewStore(pool *pgxpool.Pool, ttls TTLFunc) *Store {
	return &Store{pool: pool, ttls: ttls}
}

// Create starts a new session and returns the raw token for the cookie.
func (s *Store) Create(ctx context.Context, userID, ip, userAgent string) (string, *Session, error) {
	token, err := security.RandomToken(32)
	if err != nil {
		return "", nil, err
	}
	csrf, err := security.RandomToken(32)
	if err != nil {
		return "", nil, err
	}
	ttl, _ := s.ttls(ctx)
	sess := &Session{UserID: userID, CSRFToken: csrf, ExpiresAt: time.Now().Add(ttl)}
	err = s.pool.QueryRow(ctx,
		`INSERT INTO sessions (token_hash, user_id, csrf_token, ip_address, user_agent, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		security.HashToken(token), userID, csrf, ip, userAgent, sess.ExpiresAt).Scan(&sess.ID)
	if err != nil {
		return "", nil, err
	}
	return token, sess, nil
}

// Get validates a token against absolute and idle timeouts and refreshes last_seen_at.
func (s *Store) Get(ctx context.Context, token string) (*Session, error) {
	var sess Session
	var lastSeen time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT id, user_id, csrf_token, expires_at, last_seen_at FROM sessions WHERE token_hash=$1`,
		security.HashToken(token)).Scan(&sess.ID, &sess.UserID, &sess.CSRFToken, &sess.ExpiresAt, &lastSeen)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	_, idleTTL := s.ttls(ctx)
	if now.After(sess.ExpiresAt) || now.Sub(lastSeen) > idleTTL {
		_ = s.Delete(ctx, token)
		return nil, context.DeadlineExceeded
	}
	_, _ = s.pool.Exec(ctx, `UPDATE sessions SET last_seen_at=now() WHERE id=$1`, sess.ID)
	return &sess, nil
}

func (s *Store) Delete(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash=$1`, security.HashToken(token))
	return err
}

// Cleanup removes expired sessions; call periodically.
func (s *Store) Cleanup(ctx context.Context) {
	_, _ = s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now()`)
}

// CountActive returns the number of live sessions (dashboard widget).
func (s *Store) CountActive(ctx context.Context) (int, error) {
	var n int
	_, idleTTL := s.ttls(ctx)
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM sessions WHERE expires_at > now() AND last_seen_at > now() - $1::interval`,
		idleTTL.String()).Scan(&n)
	return n, err
}
