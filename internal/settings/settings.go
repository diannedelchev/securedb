// Package settings persists runtime-tunable configuration in the app_settings
// table of the application database. Values seeded from config.yaml on first
// boot; edits from the Settings page take effect for new sessions immediately.
package settings

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	KeySessionTTL     = "session_ttl"
	KeySessionIdleTTL = "session_idle_ttl"
)

var descriptions = map[string]string{
	KeySessionTTL:     "Absolute session lifetime (Go duration, e.g. 8h)",
	KeySessionIdleTTL: "Idle timeout before a session is revoked (e.g. 45m)",
}

type Setting struct {
	Key         string
	Value       string
	Description string
	UpdatedAt   time.Time
}

type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

// EnsureDefaults inserts missing keys with the values from config.yaml/env.
// Existing database values win — the database is the source of truth.
func (s *Service) EnsureDefaults(ctx context.Context, defaults map[string]string) error {
	for key, value := range defaults {
		_, err := s.pool.Exec(ctx,
			`INSERT INTO app_settings (key, value, description) VALUES ($1,$2,$3)
			 ON CONFLICT (key) DO NOTHING`,
			key, value, descriptions[key])
		if err != nil {
			return fmt.Errorf("seed setting %s: %w", key, err)
		}
	}
	return nil
}

func (s *Service) List(ctx context.Context) ([]Setting, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT key, value, description, updated_at FROM app_settings ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Setting
	for rows.Next() {
		var st Setting
		if err := rows.Scan(&st.Key, &st.Value, &st.Description, &st.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// Duration reads a duration setting, falling back when missing or invalid.
func (s *Service) Duration(ctx context.Context, key string, fallback time.Duration) time.Duration {
	var raw string
	if err := s.pool.QueryRow(ctx,
		`SELECT value FROM app_settings WHERE key=$1`, key).Scan(&raw); err != nil {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

// Set validates and updates a known setting.
func (s *Service) Set(ctx context.Context, key, value string) error {
	if _, known := descriptions[key]; !known {
		return fmt.Errorf("unknown setting %q", key)
	}
	switch key {
	case KeySessionTTL, KeySessionIdleTTL:
		d, err := time.ParseDuration(value)
		if err != nil || d < time.Minute || d > 30*24*time.Hour {
			return fmt.Errorf("%s must be a duration between 1m and 720h (got %q)", key, value)
		}
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE app_settings SET value=$2, updated_at=now() WHERE key=$1`, key, value)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("setting %q not found", key)
	}
	return nil
}
