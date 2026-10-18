// Package pam implements Privileged Access Management: just-in-time,
// time-bound access windows. A pending grant is reviewed by an Admin/DBA
// (four-eyes); once active, its holder can run production writes on the
// granted connection without per-query approvals until it expires or is
// revoked. All queries remain audited and subject to the hard guardrails
// (blocked keywords, WHERE requirements, read-only connections).
package pam

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	MinDuration   = 15 * time.Minute
	MaxDuration   = 8 * time.Hour
	RequestExpiry = 24 * time.Hour // pending requests expire unanswered
)

type Grant struct {
	ID             string
	UserID         string
	UserEmail      string
	UserName       string
	ConnectionID   string
	ConnectionName string
	Environment    string
	Level          string
	Reason         string
	Duration       int    // minutes
	Status         string // pending | active | rejected | expired | revoked
	ApproverEmail  string
	Comments       string
	StartsAt       *time.Time
	ExpiresAt      *time.Time
	RevokedByEmail string
	RevokedAt      *time.Time
	CreatedAt      time.Time
}

func (g *Grant) IsPending() bool { return g.Status == "pending" }
func (g *Grant) IsActive() bool {
	return g.Status == "active" && g.ExpiresAt != nil && time.Now().Before(*g.ExpiresAt)
}

// Remaining is the human-readable time left on an active window.
func (g *Grant) Remaining() string {
	if !g.IsActive() {
		return ""
	}
	d := time.Until(*g.ExpiresAt).Round(time.Minute)
	if d < time.Minute {
		return "<1m"
	}
	return d.String()
}

func (g *Grant) DurationLabel() string {
	return (time.Duration(g.Duration) * time.Minute).String()
}

type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

// Request opens a pending access-window request. One open request or active
// window per user+connection at a time.
func (s *Service) Request(ctx context.Context, userID, connectionID string, duration time.Duration, reason string) (*Grant, error) {
	if duration < MinDuration || duration > MaxDuration {
		return nil, fmt.Errorf("access window must be between %s and %s", MinDuration, MaxDuration)
	}
	s.expireStale(ctx)
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM access_grants
		 WHERE user_id=$1 AND connection_id=$2 AND status IN ('pending','active'))`,
		userID, connectionID).Scan(&exists)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("you already have a pending request or an active window for this connection")
	}
	var id string
	err = s.pool.QueryRow(ctx,
		`INSERT INTO access_grants (user_id, connection_id, reason, duration_minutes, request_expires_at)
		 VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		userID, connectionID, reason, int(duration.Minutes()), time.Now().Add(RequestExpiry)).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

const grantCols = `g.id, g.user_id, u.email, u.display_name, g.connection_id, COALESCE(c.name,''),
	COALESCE(c.environment,''), g.level, g.reason, g.duration_minutes, g.status,
	COALESCE(a.email,''), g.comments, g.starts_at, g.expires_at, COALESCE(rv.email,''), g.revoked_at, g.created_at`

const grantFrom = ` FROM access_grants g
	JOIN users u ON u.id = g.user_id
	LEFT JOIN database_connections c ON c.id = g.connection_id
	LEFT JOIN users a ON a.id = g.approver_id
	LEFT JOIN users rv ON rv.id = g.revoked_by`

func scanGrant(row interface{ Scan(...any) error }) (*Grant, error) {
	var g Grant
	err := row.Scan(&g.ID, &g.UserID, &g.UserEmail, &g.UserName, &g.ConnectionID, &g.ConnectionName,
		&g.Environment, &g.Level, &g.Reason, &g.Duration, &g.Status,
		&g.ApproverEmail, &g.Comments, &g.StartsAt, &g.ExpiresAt, &g.RevokedByEmail, &g.RevokedAt, &g.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

func (s *Service) Get(ctx context.Context, id string) (*Grant, error) {
	s.expireStale(ctx)
	return scanGrant(s.pool.QueryRow(ctx, `SELECT `+grantCols+grantFrom+` WHERE g.id=$1`, id))
}

// List returns grants, optionally filtered by status and requesting user.
func (s *Service) List(ctx context.Context, status, userID string) ([]*Grant, error) {
	s.expireStale(ctx)
	q := `SELECT ` + grantCols + grantFrom + ` WHERE 1=1`
	args := []any{}
	if status != "" {
		args = append(args, status)
		q += fmt.Sprintf(" AND g.status = $%d", len(args))
	}
	if userID != "" {
		args = append(args, userID)
		q += fmt.Sprintf(" AND g.user_id = $%d", len(args))
	}
	q += ` ORDER BY g.created_at DESC LIMIT 100`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Grant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// Decide approves (activates the window from now) or rejects a pending grant.
// Four-eyes: approvers cannot decide their own requests.
func (s *Service) Decide(ctx context.Context, id, approverID, decision, comments string) (*Grant, error) {
	g, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !g.IsPending() {
		return nil, fmt.Errorf("request is %s, not pending", g.Status)
	}
	if g.UserID == approverID {
		return nil, fmt.Errorf("you cannot approve your own access request")
	}
	switch decision {
	case "approved":
		now := time.Now()
		expires := now.Add(time.Duration(g.Duration) * time.Minute)
		_, err = s.pool.Exec(ctx,
			`UPDATE access_grants SET status='active', approver_id=$2, comments=$3,
			 starts_at=$4, expires_at=$5, updated_at=now()
			 WHERE id=$1 AND status='pending'`,
			id, approverID, comments, now, expires)
	case "rejected":
		_, err = s.pool.Exec(ctx,
			`UPDATE access_grants SET status='rejected', approver_id=$2, comments=$3, updated_at=now()
			 WHERE id=$1 AND status='pending'`,
			id, approverID, comments)
	default:
		return nil, fmt.Errorf("invalid decision %q", decision)
	}
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

// Revoke ends an active window early.
func (s *Service) Revoke(ctx context.Context, id, byID string) (*Grant, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE access_grants SET status='revoked', revoked_by=$2, revoked_at=now(), updated_at=now()
		 WHERE id=$1 AND status='active'`, id, byID)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, fmt.Errorf("grant is not active")
	}
	return s.Get(ctx, id)
}

// HasActive reports whether the user holds a live access window for the
// connection — the check the query pipeline consults before demanding
// per-query approval.
func (s *Service) HasActive(ctx context.Context, userID, connectionID string) bool {
	var ok bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM access_grants
		 WHERE user_id=$1 AND connection_id=$2 AND status='active' AND expires_at > now())`,
		userID, connectionID).Scan(&ok)
	return err == nil && ok
}

func (s *Service) CountPending(ctx context.Context) (int, error) {
	s.expireStale(ctx)
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM access_grants WHERE status='pending'`).Scan(&n)
	return n, err
}

func (s *Service) expireStale(ctx context.Context) {
	_, _ = s.pool.Exec(ctx,
		`UPDATE access_grants SET status='expired', updated_at=now()
		 WHERE (status='pending' AND request_expires_at < now())
		    OR (status='active' AND expires_at < now())`)
}
