package dashboard

import (
	"context"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dian/securedb/internal/auth"
	"github.com/dian/securedb/internal/web/view"
)

type Stats struct {
	TotalConnections  int
	ActiveSessions    int
	QueriesToday      int
	BlockedToday      int
	PendingApprovals  int
	FailedConnections int
}

// VolumeBar is one bucket of query volume for the histogram widget.
type VolumeBar struct {
	HeightPct int
	Level     string // cold | warm | hot (bar color tiers from the design)
	Count     int
	Label     string // tooltip: bucket + count
}

// VolumeData feeds the query-volume chart for one time range.
type VolumeData struct {
	Range string // 24h | 7d | 30d
	Bars  []VolumeBar
	Axis  []string
	Total int
}

type SlowQuery struct {
	QueryText  string
	Connection string
	DurationMS int
	UserEmail  string
}

type RecentConn struct {
	ID          string
	Name        string
	DBType      string
	Environment string
	LastUsed    *time.Time
	IsActive    bool
}

type EnvStatus struct {
	Environment string
	Total       int
	Active      int
}

type PendingCard struct {
	ID        string
	UserEmail string
	UserName  string
	ConnName  string
	Reason    string
	RiskScore int
	CreatedAt time.Time
}

type ActivityEvent struct {
	Kind      string // danger | success | info | warn
	Headline  string
	Detail    string
	UserEmail string
	CreatedAt time.Time
}

type Handlers struct {
	Pool     *pgxpool.Pool
	Sessions *auth.Store
}

func (h *Handlers) Dashboard(c fiber.Ctx) error {
	ctx := c.Context()
	var s Stats
	_ = h.Pool.QueryRow(ctx, `SELECT count(*) FROM database_connections`).Scan(&s.TotalConnections)
	_ = h.Pool.QueryRow(ctx, `SELECT count(*) FROM query_history WHERE created_at::date = now()::date`).Scan(&s.QueriesToday)
	_ = h.Pool.QueryRow(ctx, `SELECT count(*) FROM query_history WHERE status='blocked' AND created_at::date = now()::date`).Scan(&s.BlockedToday)
	_ = h.Pool.QueryRow(ctx, `SELECT count(*) FROM approval_requests WHERE status='pending'`).Scan(&s.PendingApprovals)
	_ = h.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_logs WHERE action='connection_tested' AND status='failure' AND created_at > now() - interval '24 hours'`).
		Scan(&s.FailedConnections)
	s.ActiveSessions, _ = h.Sessions.CountActive(ctx)

	return view.Render(c, "dashboard", fiber.Map{
		"Title":       "Dashboard",
		"Stats":       s,
		"Volume":      h.queryVolume(ctx, "24h"),
		"SlowQueries": h.slowQueries(ctx),
		"RecentConns": h.recentConnections(ctx),
		"EnvStatus":   h.envStatus(ctx),
		"Pending":     h.pendingCards(ctx),
		"Activity":    h.activity(ctx),
	})
}

// Volume serves the query-volume chart fragment for a time range
// (the 24h / 7d / 30d switcher on the dashboard).
func (h *Handlers) Volume(c fiber.Ctx) error {
	return view.Partial(c, "partials/dash_volume", fiber.Map{
		"V": h.queryVolume(c.Context(), c.Query("range")),
	})
}

// queryVolume returns histogram buckets for a range: hourly for 24h,
// daily for 7d and 30d, scaled to the design's three-tier color ramp.
func (h *Handlers) queryVolume(ctx context.Context, rng string) VolumeData {
	var (
		buckets int
		q       string
		axis    []string
	)
	now := time.Now().Local()
	switch rng {
	case "7d":
		buckets = 7
		q = `SELECT (now()::date - created_at::date)::int, count(*)
		     FROM query_history WHERE created_at > now() - interval '7 days' GROUP BY 1`
		for i := 0; i < buckets; i++ {
			axis = append(axis, now.AddDate(0, 0, i-buckets+1).Format("Mon"))
		}
	case "30d":
		buckets = 30
		q = `SELECT (now()::date - created_at::date)::int, count(*)
		     FROM query_history WHERE created_at > now() - interval '30 days' GROUP BY 1`
		for _, off := range []int{-29, -21, -14, -7, 0} {
			axis = append(axis, now.AddDate(0, 0, off).Format("Jan 2"))
		}
	default:
		rng = "24h"
		buckets = 24
		q = `SELECT extract(hour FROM age(now(), created_at))::int, count(*)
		     FROM query_history WHERE created_at > now() - interval '24 hours' GROUP BY 1`
		axis = []string{"-24h", "-18h", "-12h", "-6h", "now"}
	}

	counts := make([]int, buckets)
	rows, err := h.Pool.Query(ctx, q)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ago, n int
			if rows.Scan(&ago, &n) == nil && ago >= 0 && ago < buckets {
				counts[buckets-1-ago] = n
			}
		}
	}

	data := VolumeData{Range: rng, Axis: axis}
	maxN := 1
	for _, n := range counts {
		data.Total += n
		if n > maxN {
			maxN = n
		}
	}
	for i, n := range counts {
		pct := n * 100 / maxN
		if pct < 4 {
			pct = 4 // keep an empty-bucket baseline visible, like the design
		}
		level := "cold"
		switch {
		case pct >= 85:
			level = "hot"
		case pct >= 35:
			level = "warm"
		}
		label := ""
		if rng == "24h" {
			label = now.Add(time.Duration(i-buckets+1) * time.Hour).Format("15:00")
		} else {
			label = now.AddDate(0, 0, i-buckets+1).Format("Jan 2")
		}
		data.Bars = append(data.Bars, VolumeBar{
			HeightPct: pct, Level: level, Count: n,
			Label: fmt.Sprintf("%s · %d queries", label, n),
		})
	}
	return data
}

func (h *Handlers) slowQueries(ctx context.Context) []SlowQuery {
	rows, err := h.Pool.Query(ctx,
		`SELECT h.query_text, COALESCE(c.name,''), h.duration_ms, u.email
		 FROM query_history h
		 JOIN users u ON u.id = h.user_id
		 LEFT JOIN database_connections c ON c.id = h.connection_id
		 WHERE h.status = 'success' AND h.created_at > now() - interval '7 days'
		 ORDER BY h.duration_ms DESC LIMIT 4`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []SlowQuery
	for rows.Next() {
		var q SlowQuery
		if rows.Scan(&q.QueryText, &q.Connection, &q.DurationMS, &q.UserEmail) == nil {
			out = append(out, q)
		}
	}
	return out
}

func (h *Handlers) recentConnections(ctx context.Context) []RecentConn {
	rows, err := h.Pool.Query(ctx,
		`SELECT c.id, c.name, c.db_type, c.environment, c.is_active, max(h.created_at)
		 FROM database_connections c
		 LEFT JOIN query_history h ON h.connection_id = c.id
		 GROUP BY c.id
		 ORDER BY max(h.created_at) DESC NULLS LAST, c.updated_at DESC
		 LIMIT 3`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []RecentConn
	for rows.Next() {
		var r RecentConn
		if rows.Scan(&r.ID, &r.Name, &r.DBType, &r.Environment, &r.IsActive, &r.LastUsed) == nil {
			out = append(out, r)
		}
	}
	return out
}

func (h *Handlers) envStatus(ctx context.Context) []EnvStatus {
	out := []EnvStatus{{Environment: "production"}, {Environment: "staging"}, {Environment: "development"}}
	rows, err := h.Pool.Query(ctx,
		`SELECT environment, count(*), count(*) FILTER (WHERE is_active) FROM database_connections GROUP BY environment`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var env string
		var total, active int
		if rows.Scan(&env, &total, &active) == nil {
			for i := range out {
				if out[i].Environment == env {
					out[i].Total, out[i].Active = total, active
				}
			}
		}
	}
	return out
}

func (h *Handlers) pendingCards(ctx context.Context) []PendingCard {
	rows, err := h.Pool.Query(ctx,
		`SELECT r.id, u.email, u.display_name, COALESCE(c.name,''), r.reason, r.risk_score, r.created_at
		 FROM approval_requests r
		 JOIN users u ON u.id = r.user_id
		 LEFT JOIN database_connections c ON c.id = r.connection_id
		 WHERE r.status = 'pending'
		 ORDER BY r.created_at DESC LIMIT 3`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []PendingCard
	for rows.Next() {
		var p PendingCard
		if rows.Scan(&p.ID, &p.UserEmail, &p.UserName, &p.ConnName, &p.Reason, &p.RiskScore, &p.CreatedAt) == nil {
			out = append(out, p)
		}
	}
	return out
}

func (h *Handlers) activity(ctx context.Context) []ActivityEvent {
	rows, err := h.Pool.Query(ctx,
		`SELECT a.action, a.status, COALESCE(u.email,'system'), COALESCE(c.name,''), a.error_message, a.created_at
		 FROM audit_logs a
		 LEFT JOIN users u ON u.id = a.user_id
		 LEFT JOIN database_connections c ON c.id = a.connection_id
		 ORDER BY a.created_at DESC LIMIT 5`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []ActivityEvent
	for rows.Next() {
		var action, status, email, conn, errMsg string
		var at time.Time
		if rows.Scan(&action, &status, &email, &conn, &errMsg, &at) != nil {
			continue
		}
		ev := ActivityEvent{UserEmail: email, CreatedAt: at, Kind: "info"}
		switch action {
		case "query_blocked":
			ev.Kind = "danger"
			ev.Headline = "Query blocked"
			ev.Detail = errMsg
		case "login_failed":
			ev.Kind = "danger"
			ev.Headline = "Failed login"
			ev.Detail = "authentication rejected"
		case "approval_approved":
			ev.Kind = "success"
			ev.Headline = "Approval granted"
			ev.Detail = "on " + conn
		case "approval_rejected":
			ev.Kind = "warn"
			ev.Headline = "Approval rejected"
			ev.Detail = "on " + conn
		case "approval_requested":
			ev.Kind = "warn"
			ev.Headline = "Approval requested"
			ev.Detail = "production write on " + conn
		case "query_executed":
			ev.Headline = "Query executed"
			ev.Detail = "on " + conn
			if status == "failure" {
				ev.Kind = "warn"
				ev.Headline = "Query failed"
			}
		case "connection_tested":
			ev.Headline = "Connection tested"
			ev.Detail = conn
			if status == "failure" {
				ev.Kind = "danger"
				ev.Headline = "Connection test failed"
			}
		case "login":
			ev.Kind = "success"
			ev.Headline = "Signed in"
		case "logout":
			ev.Headline = "Signed out"
		default:
			ev.Headline = action
			ev.Detail = conn
		}
		out = append(out, ev)
	}
	return out
}
