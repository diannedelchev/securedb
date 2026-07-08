package approvals

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const DefaultExpiry = 24 * time.Hour

type Request struct {
	ID             string
	UserID         string
	UserEmail      string
	ConnectionID   string
	ConnectionName string
	DatabaseName   string // database on the server the query targets
	Environment    string
	QueryText      string
	Reason         string
	RiskScore      int
	Status         string // pending | approved | rejected | expired
	ApproverID     string
	ApproverEmail  string
	Comments       string
	ExecutedAt     *time.Time
	ExpiresAt      time.Time
	CreatedAt      time.Time
}

func (r *Request) IsPending() bool { return r.Status == "pending" }

// ExecutedAtFmt renders the nullable execution time for templates.
func (r *Request) ExecutedAtFmt() string {
	if r.ExecutedAt == nil {
		return ""
	}
	return r.ExecutedAt.Local().Format("Jan 02 15:04")
}
func (r *Request) CanExecute() bool {
	return r.Status == "approved" && r.ExecutedAt == nil && time.Now().Before(r.ExpiresAt)
}

type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

func (s *Service) Create(ctx context.Context, userID, connectionID, database, environment, sql, reason string, riskScore int) (*Request, error) {
	var id string
	err := s.pool.QueryRow(ctx,
		`INSERT INTO approval_requests (user_id, connection_id, database_name, environment, query_text, reason, risk_score, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		userID, connectionID, database, environment, sql, reason, riskScore, time.Now().Add(DefaultExpiry)).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

const reqCols = `r.id, r.user_id, u.email, r.connection_id, COALESCE(c.name,''), r.database_name, r.environment,
	r.query_text, r.reason, r.risk_score, r.status, COALESCE(r.approver_id::text,''), COALESCE(a.email,''),
	r.comments, r.executed_at, r.expires_at, r.created_at`

const reqFrom = ` FROM approval_requests r
	JOIN users u ON u.id = r.user_id
	LEFT JOIN database_connections c ON c.id = r.connection_id
	LEFT JOIN users a ON a.id = r.approver_id`

func scanReq(row interface{ Scan(...any) error }) (*Request, error) {
	var r Request
	err := row.Scan(&r.ID, &r.UserID, &r.UserEmail, &r.ConnectionID, &r.ConnectionName, &r.DatabaseName,
		&r.Environment, &r.QueryText, &r.Reason, &r.RiskScore, &r.Status, &r.ApproverID, &r.ApproverEmail,
		&r.Comments, &r.ExecutedAt, &r.ExpiresAt, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Service) Get(ctx context.Context, id string) (*Request, error) {
	s.expireStale(ctx)
	return scanReq(s.pool.QueryRow(ctx, `SELECT `+reqCols+reqFrom+` WHERE r.id=$1`, id))
}

// List returns requests, optionally filtered by status; auditors and approvers
// see all, requesters see their own (filtering by userID).
func (s *Service) List(ctx context.Context, status, userID string) ([]*Request, error) {
	s.expireStale(ctx)
	q := `SELECT ` + reqCols + reqFrom + ` WHERE 1=1`
	args := []any{}
	if status != "" {
		args = append(args, status)
		q += fmt.Sprintf(" AND r.status = $%d", len(args))
	}
	if userID != "" {
		args = append(args, userID)
		q += fmt.Sprintf(" AND r.user_id = $%d", len(args))
	}
	q += ` ORDER BY r.created_at DESC LIMIT 200`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Request
	for rows.Next() {
		r, err := scanReq(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Service) CountPending(ctx context.Context) (int, error) {
	s.expireStale(ctx)
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM approval_requests WHERE status='pending'`).Scan(&n)
	return n, err
}

// Decide approves or rejects a pending request. Approvers cannot decide their
// own requests (four-eyes principle).
func (s *Service) Decide(ctx context.Context, id, approverID, decision, comments string) (*Request, error) {
	if decision != "approved" && decision != "rejected" {
		return nil, fmt.Errorf("invalid decision %q", decision)
	}
	req, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !req.IsPending() {
		return nil, fmt.Errorf("request is %s, not pending", req.Status)
	}
	if req.UserID == approverID {
		return nil, fmt.Errorf("you cannot approve your own request")
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE approval_requests SET status=$2, approver_id=$3, comments=$4, updated_at=now()
		 WHERE id=$1 AND status='pending'`,
		id, decision, approverID, comments)
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

// MarkExecuted stamps an approved request after its one-time execution.
func (s *Service) MarkExecuted(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE approval_requests SET executed_at=now(), updated_at=now()
		 WHERE id=$1 AND status='approved' AND executed_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("request is not executable")
	}
	return nil
}

func (s *Service) expireStale(ctx context.Context) {
	_, _ = s.pool.Exec(ctx,
		`UPDATE approval_requests SET status='expired', updated_at=now()
		 WHERE status='pending' AND expires_at < now()`)
}
