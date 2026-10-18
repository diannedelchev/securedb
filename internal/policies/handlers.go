package policies

import (
	"context"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/diannedelchev/securedb/internal/audit"
	"github.com/diannedelchev/securedb/internal/auth"
	"github.com/diannedelchev/securedb/internal/web/view"
)

type Handlers struct {
	Svc   *Service
	Audit *audit.Logger
	Pool  *pgxpool.Pool
}

// SecurityStats feeds the Security Center overview widgets.
type SecurityStats struct {
	Score            int
	BlockedWeek      int
	BlockedToday     int
	FailedLogins24h  int
	MaskingRules     int
	UnboundedDeletes int
	NoSSLConns       int
	InactiveUsers    int
	BlockedByDay     []DayBar
}

type DayBar struct {
	Label     string
	HeightPct int
	Hot       bool
}

type ThreatEvent struct {
	Time     time.Time
	Title    string
	Tag      string // CRITICAL | MEDIUM | LOW
	Body     string
	LinkText string
	LinkHref string
}

func (h *Handlers) List(c fiber.Ctx) error {
	ctx := c.Context()
	pols, err := h.Svc.List(ctx)
	if err != nil {
		return err
	}
	rules, err := h.Svc.MaskingRules(ctx)
	if err != nil {
		return err
	}
	return view.Render(c, "policies", fiber.Map{
		"Title":    "Security Center",
		"Policies": pols,
		"Rules":    rules,
		"Stats":    h.securityStats(ctx, pols, rules),
		"Threats":  h.threats(ctx),
		"CanEdit":  auth.CurrentUser(c).IsAdmin(),
	})
}

func (h *Handlers) securityStats(ctx context.Context, pols []Policy, rules []MaskingRule) SecurityStats {
	var s SecurityStats
	_ = h.Pool.QueryRow(ctx,
		`SELECT count(*) FROM query_history WHERE status='blocked' AND created_at > now() - interval '7 days'`).Scan(&s.BlockedWeek)
	_ = h.Pool.QueryRow(ctx,
		`SELECT count(*) FROM query_history WHERE status='blocked' AND created_at::date = now()::date`).Scan(&s.BlockedToday)
	_ = h.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_logs WHERE action='login_failed' AND created_at > now() - interval '24 hours'`).Scan(&s.FailedLogins24h)
	_ = h.Pool.QueryRow(ctx,
		`SELECT count(*) FROM query_history WHERE status='blocked' AND error_message LIKE '%WHERE%' AND created_at > now() - interval '7 days'`).Scan(&s.UnboundedDeletes)
	_ = h.Pool.QueryRow(ctx,
		`SELECT count(*) FROM database_connections WHERE NOT ssl_enabled AND is_active`).Scan(&s.NoSSLConns)
	_ = h.Pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE NOT is_active`).Scan(&s.InactiveUsers)
	for _, r := range rules {
		if r.IsActive {
			s.MaskingRules++
		}
	}

	// Posture score from the effective configuration.
	score := 30 // encrypted credentials + parameterised control plane (always on)
	for _, p := range pols {
		if p.Environment == "production" {
			if p.RequireApprovalWrites {
				score += 25
			}
			if p.MaskSensitiveColumns {
				score += 10
			}
			if !p.AllowExport {
				score += 5
			}
			if len(p.BlockedKeywordList()) >= 4 {
				score += 10
			}
		}
	}
	if s.MaskingRules >= len(DefaultMaskingRules()) {
		score += 10
	}
	if s.NoSSLConns == 0 {
		score += 10
	}
	if score > 100 {
		score = 100
	}
	s.Score = score

	// Blocked-query histogram, last 7 days.
	counts := make([]int, 7)
	rows, err := h.Pool.Query(ctx,
		`SELECT (now()::date - created_at::date)::int AS days_ago, count(*)
		 FROM query_history
		 WHERE status='blocked' AND created_at > now() - interval '7 days'
		 GROUP BY 1`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var daysAgo, n int
			if rows.Scan(&daysAgo, &n) == nil && daysAgo >= 0 && daysAgo < 7 {
				counts[6-daysAgo] = n
			}
		}
	}
	maxN := 1
	for _, n := range counts {
		if n > maxN {
			maxN = n
		}
	}
	now := time.Now()
	for i, n := range counts {
		pct := n * 100 / maxN
		if pct < 5 {
			pct = 5
		}
		s.BlockedByDay = append(s.BlockedByDay, DayBar{
			Label:     now.AddDate(0, 0, i-6).Format("Mon"),
			HeightPct: pct,
			Hot:       n > 0 && n == maxN,
		})
	}
	return s
}

func (h *Handlers) threats(ctx context.Context) []ThreatEvent {
	rows, err := h.Pool.Query(ctx,
		`SELECT a.action, COALESCE(u.email,'system'), COALESCE(c.name,''), a.query_text, a.error_message, a.created_at
		 FROM audit_logs a
		 LEFT JOIN users u ON u.id = a.user_id
		 LEFT JOIN database_connections c ON c.id = a.connection_id
		 WHERE a.action IN ('query_blocked','login_failed','user_role_changed','policy_updated','approval_requested','user_status_changed')
		 ORDER BY a.created_at DESC LIMIT 5`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []ThreatEvent
	for rows.Next() {
		var action, email, conn, sql, errMsg string
		var at time.Time
		if rows.Scan(&action, &email, &conn, &sql, &errMsg, &at) != nil {
			continue
		}
		ev := ThreatEvent{Time: at, LinkText: "View audit trail", LinkHref: "/audit"}
		switch action {
		case "query_blocked":
			ev.Title = "Query blocked on " + conn
			ev.Tag = "CRITICAL"
			ev.Body = email + " attempted a statement that policy rejected pre-execution: " + errMsg + "."
			ev.LinkHref = "/audit?cat=denied"
		case "login_failed":
			ev.Title = "Failed sign-in attempt"
			ev.Tag = "MEDIUM"
			ev.Body = "Authentication rejected for " + email + ". Repeated failures may indicate credential stuffing."
			ev.LinkHref = "/audit?cat=auth"
		case "user_role_changed":
			ev.Title = "Role assignment changed"
			ev.Tag = "MEDIUM"
			ev.Body = "Roles for a user account were modified by " + email + ". Verify the change was expected."
			ev.LinkHref = "/audit?cat=roles"
		case "user_status_changed":
			ev.Title = "User account status changed"
			ev.Tag = "MEDIUM"
			ev.Body = email + " enabled or disabled a user account."
			ev.LinkHref = "/audit?cat=roles"
		case "policy_updated":
			ev.Title = "Security policy modified"
			ev.Tag = "LOW"
			ev.Body = email + " changed guardrail settings. Review the diff in the audit trail."
		case "approval_requested":
			ev.Title = "Production write requested"
			ev.Tag = "LOW"
			ev.Body = email + " requested approval for a production write on " + conn + "."
			ev.LinkText = "Review request"
			ev.LinkHref = "/approvals?status=pending"
		}
		out = append(out, ev)
	}
	return out
}

func (h *Handlers) Update(c fiber.Ctx) error {
	user := auth.CurrentUser(c)
	maxRows, _ := strconv.Atoi(c.FormValue("max_rows"))
	timeout, _ := strconv.Atoi(c.FormValue("timeout_seconds"))
	p := Policy{
		Environment:           c.Params("env"),
		MaxRows:               maxRows,
		TimeoutSeconds:        timeout,
		AllowExport:           c.FormValue("allow_export") == "on",
		RequireApprovalWrites: c.FormValue("require_approval_writes") == "on",
		AllowWriteQueries:     c.FormValue("allow_write_queries") == "on",
		MaskSensitiveColumns:  c.FormValue("mask_sensitive_columns") == "on",
		AllowedSchemas:        c.FormValue("allowed_schemas"),
		BlockedKeywords:       c.FormValue("blocked_keywords"),
	}
	entry := audit.Entry{
		UserID: user.ID, Action: audit.ActionPolicyUpdated, EntityType: "security_policy",
		EntityID: p.Environment, IP: c.IP(), UserAgent: c.Get("User-Agent"),
	}
	if err := h.Svc.Update(c.Context(), p); err != nil {
		entry.Status = "failure"
		entry.ErrorMessage = err.Error()
		h.Audit.Log(c.Context(), entry)
		return view.Toast(c, "error", err.Error())
	}
	h.Audit.Log(c.Context(), entry)
	return view.Toast(c, "success", "Policy for "+p.Environment+" updated")
}
