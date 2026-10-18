package audit

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Actions recorded in the audit trail.
const (
	ActionLogin             = "login"
	ActionLogout            = "logout"
	ActionPasswordChanged   = "password_changed"
	ActionLoginFailed       = "login_failed"
	ActionConnectionCreated = "connection_created"
	ActionConnectionUpdated = "connection_updated"
	ActionConnectionDeleted = "connection_deleted"
	ActionConnectionTested  = "connection_tested"
	ActionQueryExecuted     = "query_executed"
	ActionQueryBlocked      = "query_blocked"
	ActionQueryCancelled    = "query_cancelled"
	ActionExportRequested   = "export_requested"
	ActionApprovalRequested = "approval_requested"
	ActionApprovalApproved  = "approval_approved"
	ActionApprovalRejected  = "approval_rejected"
	ActionUserCreated       = "user_created"
	ActionUserRoleChanged   = "user_role_changed"
	ActionUserStatusChanged = "user_status_changed"
	ActionPolicyUpdated     = "policy_updated"
	ActionSettingUpdated    = "setting_updated"
	ActionGrantRequested    = "grant_requested"
	ActionGrantApproved     = "grant_approved"
	ActionGrantRejected     = "grant_rejected"
	ActionGrantRevoked      = "grant_revoked"
)

type Entry struct {
	UserID       string
	Action       string
	EntityType   string
	EntityID     string
	ConnectionID string
	IP           string
	UserAgent    string
	QueryText    string
	Status       string // success | failure | blocked
	ErrorMessage string
}

type Record struct {
	ID           string
	UserEmail    string
	Action       string
	EntityType   string
	EntityID     string
	Connection   string
	IP           string
	UserAgent    string
	QueryText    string
	Status       string
	ErrorMessage string
	CreatedAt    time.Time
}

type Logger struct {
	pool *pgxpool.Pool
}

func NewLogger(pool *pgxpool.Pool) *Logger { return &Logger{pool: pool} }

// Log writes an audit entry and returns failures to callers that require durable auditing.
func (l *Logger) Log(ctx context.Context, e Entry) error {
	if e.Status == "" {
		e.Status = "success"
	}
	var userID, connID any
	if e.UserID != "" {
		userID = e.UserID
	}
	if e.ConnectionID != "" {
		connID = e.ConnectionID
	}
	_, err := l.pool.Exec(ctx,
		`INSERT INTO audit_logs (user_id, action, entity_type, entity_id, connection_id, ip_address, user_agent, query_text, status, error_message)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		userID, e.Action, e.EntityType, e.EntityID, connID, e.IP, e.UserAgent, e.QueryText, e.Status, e.ErrorMessage)
	if err != nil {
		slog.Error("audit log write failed", "action", e.Action, "error", err)
	}
	return err
}

// Severity classifies an event for display.
func (r *Record) Severity() string {
	switch {
	case r.Action == ActionQueryBlocked, r.Action == ActionLoginFailed:
		return "CRITICAL"
	case r.Status == "running", r.Status == "failure", r.Action == ActionUserRoleChanged, r.Action == ActionUserStatusChanged,
		r.Action == ActionPasswordChanged,
		r.Action == ActionPolicyUpdated, r.Action == ActionConnectionDeleted,
		r.Action == ActionGrantApproved, r.Action == ActionGrantRevoked:
		return "WARN"
	case r.Action == ActionApprovalApproved, r.Action == ActionLogin:
		return "OK"
	default:
		return "INFO"
	}
}

// Title is the human headline for an event row.
func (r *Record) Title() string {
	if r.Action == ActionQueryExecuted && r.Status == "running" {
		return "Query started — outcome unconfirmed"
	}
	titles := map[string]string{
		ActionLogin:             "Sign-in",
		ActionLogout:            "Session ended",
		ActionPasswordChanged:   "Password changed",
		ActionLoginFailed:       "Failed sign-in",
		ActionConnectionCreated: "Connection created",
		ActionConnectionUpdated: "Connection updated",
		ActionConnectionDeleted: "Connection deleted",
		ActionConnectionTested:  "Connection tested",
		ActionQueryExecuted:     "Query executed",
		ActionQueryBlocked:      "Query denied",
		ActionQueryCancelled:    "Query cancelled",
		ActionExportRequested:   "Result export",
		ActionApprovalRequested: "Approval requested",
		ActionApprovalApproved:  "Approval granted",
		ActionApprovalRejected:  "Approval rejected",
		ActionUserCreated:       "User created",
		ActionUserRoleChanged:   "Role changed",
		ActionUserStatusChanged: "User status changed",
		ActionPolicyUpdated:     "Policy updated",
		ActionSettingUpdated:    "Setting updated",
		ActionGrantRequested:    "Access window requested",
		ActionGrantApproved:     "Access window granted",
		ActionGrantRejected:     "Access window rejected",
		ActionGrantRevoked:      "Access window revoked",
	}
	if t, ok := titles[r.Action]; ok {
		return t
	}
	return r.Action
}

// Categories for the filter pills, mapped to action sets.
var Categories = map[string][]string{
	"auth":    {ActionLogin, ActionLogout, ActionLoginFailed, ActionPasswordChanged},
	"queries": {ActionQueryExecuted, ActionQueryCancelled},
	"denied":  {ActionQueryBlocked},
	"exports": {ActionExportRequested},
	"approvals": {ActionApprovalRequested, ActionApprovalApproved, ActionApprovalRejected,
		ActionGrantRequested, ActionGrantApproved, ActionGrantRejected, ActionGrantRevoked},
	"roles": {ActionUserCreated, ActionUserRoleChanged, ActionUserStatusChanged},
	"conns": {ActionConnectionCreated, ActionConnectionUpdated, ActionConnectionDeleted, ActionConnectionTested},
}

type Filter struct {
	Category string
	Action   string
	Status   string
	Search   string
	Limit    int
}

func (l *Logger) List(ctx context.Context, f Filter) ([]Record, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	q := `SELECT a.id, COALESCE(u.email,'system'), a.action, a.entity_type, a.entity_id,
	             COALESCE(c.name,''), a.ip_address, a.user_agent, a.query_text, a.status, a.error_message, a.created_at
	      FROM audit_logs a
	      LEFT JOIN users u ON u.id = a.user_id
	      LEFT JOIN database_connections c ON c.id = a.connection_id
	      WHERE 1=1`
	args := []any{}
	if f.Action != "" {
		args = append(args, f.Action)
		q += ` AND a.action = $` + itoa(len(args))
	}
	if actions, ok := Categories[f.Category]; ok {
		args = append(args, actions)
		q += ` AND a.action = ANY($` + itoa(len(args)) + `)`
	}
	if f.Status != "" {
		args = append(args, f.Status)
		q += ` AND a.status = $` + itoa(len(args))
	}
	if f.Search != "" {
		args = append(args, "%"+strings.ToLower(f.Search)+"%")
		n := itoa(len(args))
		q += ` AND (lower(COALESCE(u.email,'')) LIKE $` + n + ` OR lower(a.query_text) LIKE $` + n + ` OR lower(a.entity_type) LIKE $` + n + `)`
	}
	args = append(args, f.Limit)
	q += ` ORDER BY a.created_at DESC LIMIT $` + itoa(len(args))

	rows, err := l.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.ID, &r.UserEmail, &r.Action, &r.EntityType, &r.EntityID, &r.Connection,
			&r.IP, &r.UserAgent, &r.QueryText, &r.Status, &r.ErrorMessage, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Get loads a single audit record for the detail panel.
func (l *Logger) Get(ctx context.Context, id string) (*Record, error) {
	row := l.pool.QueryRow(ctx,
		`SELECT a.id, COALESCE(u.email,'system'), a.action, a.entity_type, a.entity_id,
		        COALESCE(c.name,''), a.ip_address, a.user_agent, a.query_text, a.status, a.error_message, a.created_at
		 FROM audit_logs a
		 LEFT JOIN users u ON u.id = a.user_id
		 LEFT JOIN database_connections c ON c.id = a.connection_id
		 WHERE a.id = $1`, id)
	var r Record
	err := row.Scan(&r.ID, &r.UserEmail, &r.Action, &r.EntityType, &r.EntityID, &r.Connection,
		&r.IP, &r.UserAgent, &r.QueryText, &r.Status, &r.ErrorMessage, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func itoa(n int) string { return strconv.Itoa(n) }
