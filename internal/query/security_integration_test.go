package query

import (
	"context"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/diannedelchev/securedb/internal/approvals"
	"github.com/diannedelchev/securedb/internal/audit"
	"github.com/diannedelchev/securedb/internal/auth"
	"github.com/diannedelchev/securedb/internal/connections"
	"github.com/diannedelchev/securedb/internal/db"
	"github.com/diannedelchev/securedb/internal/pam"
	"github.com/diannedelchev/securedb/internal/policies"
	"github.com/diannedelchev/securedb/internal/security"
	"github.com/diannedelchev/securedb/internal/seed"
	"github.com/diannedelchev/securedb/internal/users"
	"github.com/diannedelchev/securedb/migrations"
)

type fixture struct {
	s                                  *Service
	pool                               *pgxpool.Pool
	schema                             string
	conn, other                        *connections.Connection
	admin, developer, analyst, auditor *users.User
}

func setupSecurityTest(t *testing.T) *fixture {
	t.Helper()
	dsn := os.Getenv("SECUREDB_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set SECUREDB_TEST_DATABASE_URL to run PostgreSQL integration tests")
	}
	ctx := context.Background()
	root, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "security_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = root.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		root.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = root.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`); root.Close() })
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err = db.Migrate(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	if err = seed.Run(ctx, pool, seed.Options{AdminEmail: "admin@test.local", AdminPassword: "test-password"}); err != nil {
		t.Fatal(err)
	}
	u := users.NewService(pool)
	admin, err := u.Authenticate(ctx, "admin@test.local", "test-password")
	if err != nil {
		t.Fatal(err)
	}
	createUser := func(role string) *users.User {
		user, err := u.Create(ctx, role+"@test.local", role, "test-password", []string{role})
		if err != nil {
			t.Fatal(err)
		}
		return user
	}
	enc, err := security.NewEncryptor(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	conns := connections.NewService(pool, enc)
	makeConn := func(name string) *connections.Connection {
		c, err := conns.Create(ctx, admin.ID, connections.Input{Name: name, Environment: "production", DBType: "postgres", Host: cfg.ConnConfig.Host, Port: int(cfg.ConnConfig.Port), DatabaseName: cfg.ConnConfig.Database, Username: cfg.ConnConfig.User, Password: cfg.ConnConfig.Password, IsActive: true})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	aud := audit.NewLogger(pool)
	pol := policies.NewService(pool)
	appr := approvals.NewService(pool)
	grants := pam.NewService(pool)
	f := &fixture{pool: pool, schema: schema, conn: makeConn("primary"), other: makeConn("other"), admin: admin, developer: createUser(users.RoleDeveloper), analyst: createUser(users.RoleAnalyst), auditor: createUser(users.RoleAuditor)}
	f.s = NewService(pool, conns, pol, appr, grants, aud)
	f.exec(t, `CREATE TABLE target (id integer PRIMARY KEY, value integer, card_number text); INSERT INTO target VALUES (1,0,'4111111111111111')`)
	return f
}

func (f *fixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}
func (f *fixture) value(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT value FROM target WHERE id=1`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
func (f *fixture) request(user *users.User, sql string) ExecRequest {
	return ExecRequest{User: user, ConnectionID: f.conn.ID, SQL: sql, RowLimit: 100}
}
func (f *fixture) update() string {
	return "UPDATE " + f.schema + ".target SET value=value+1 WHERE id=1"
}
func (f *fixture) approved(t *testing.T) ExecRequest {
	t.Helper()
	req := f.request(f.developer, f.update())
	out := f.s.Execute(context.Background(), req)
	if out.Status != "pending_approval" {
		t.Fatalf("expected approval request: %+v", out)
	}
	if _, err := f.s.approv.Decide(context.Background(), out.ApprovalRequest.ID, f.admin.ID, "approved", ""); err != nil {
		t.Fatal(err)
	}
	req.ApprovalID = out.ApprovalRequest.ID
	return req
}

func TestSecurityExecutionBoundaries(t *testing.T) {
	f := setupSecurityTest(t)
	ctx := context.Background()
	t.Run("role restrictions precede PAM", func(t *testing.T) {
		for _, u := range []*users.User{f.analyst, f.auditor} {
			g, err := f.s.grants.Request(ctx, u.ID, f.conn.ID, time.Hour, "regression")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.s.grants.Decide(ctx, g.ID, f.admin.ID, "approved", ""); err != nil {
				t.Fatal(err)
			}
			if out := f.s.Execute(ctx, f.request(u, f.update())); out.Status != "blocked" {
				t.Fatalf("role bypass via PAM: %+v", out)
			}
		}
		if f.value(t) != 0 {
			t.Fatal("role-restricted write executed")
		}
	})
	t.Run("parsed writes and WHERE", func(t *testing.T) {
		for _, sql := range []string{"WITH x AS ( SELECT 1 ) " + f.update(), "EXPLAIN ANALYZE " + f.update()} {
			if out := f.s.Execute(ctx, f.request(f.developer, sql)); out.Status != "pending_approval" {
				t.Fatalf("write not gated: %+v", out)
			}
		}
		sql := "DELETE FROM " + f.schema + ".target USING (SELECT id FROM " + f.schema + ".target WHERE id=1) s"
		if out := f.s.Execute(ctx, f.request(f.developer, sql)); out.Status != "blocked" {
			t.Fatalf("unbounded delete accepted: %+v", out)
		}
		if f.value(t) != 0 {
			t.Fatal("unapproved write executed")
		}
	})
	t.Run("read transaction blocks hidden writes", func(t *testing.T) {
		f.exec(t, `CREATE FUNCTION hidden_write() RETURNS int LANGUAGE plpgsql AS $$ BEGIN UPDATE `+f.schema+`.target SET value=99; RETURN 1; END $$`)
		out := f.s.Execute(ctx, f.request(f.analyst, "SELECT "+f.schema+".hidden_write()"))
		if out.Status != "error" || f.value(t) != 0 {
			t.Fatalf("hidden write executed: %+v", out)
		}
	})
	t.Run("aliases cannot remove masking", func(t *testing.T) {
		out := f.s.Execute(ctx, f.request(f.analyst, "SELECT card_number AS token FROM "+f.schema+".target"))
		if out.Status != "success" || out.Result.Rows[0][0] == "4111111111111111" {
			t.Fatalf("masking bypass: %+v", out)
		}
		var status string
		if err := f.pool.QueryRow(ctx, `SELECT status FROM audit_logs WHERE entity_id=$1`, out.HistoryID).Scan(&status); err != nil || status != "success" {
			t.Fatalf("missing audit: %s %v", status, err)
		}
	})
}

func TestApprovalBindingAndConcurrency(t *testing.T) {
	f := setupSecurityTest(t)
	ctx := context.Background()
	req := f.approved(t)
	for _, change := range []func(*ExecRequest){
		func(r *ExecRequest) { r.ConnectionID = f.other.ID },
		func(r *ExecRequest) { r.Database = "otherdb" },
		func(r *ExecRequest) { r.SQL = strings.ReplaceAll(r.SQL, "value+1", "value+2") },
		func(r *ExecRequest) { r.User = f.admin },
	} {
		bad := req
		change(&bad)
		if out := f.s.Execute(ctx, bad); out.Status != "error" {
			t.Fatalf("tampered approval accepted: %+v", out)
		}
	}
	var wg sync.WaitGroup
	outcomes := make(chan Outcome, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); outcomes <- f.s.Execute(ctx, req) }()
	}
	wg.Wait()
	close(outcomes)
	success := 0
	for out := range outcomes {
		if out.Status == "success" {
			success++
		}
	}
	if success != 1 || f.value(t) != 1 {
		t.Fatalf("one approval executed %d times; value=%d", success, f.value(t))
	}
	expired := f.approved(t)
	f.exec(t, `UPDATE approval_requests SET expires_at=now()-interval '1 second' WHERE id=$1`, expired.ApprovalID)
	if out := f.s.Execute(ctx, expired); out.Status != "error" {
		t.Fatal("expired approval accepted")
	}
	changed := f.approved(t)
	f.exec(t, `UPDATE database_connections SET updated_at=now() WHERE id=$1`, f.conn.ID)
	if out := f.s.Execute(ctx, changed); out.Status != "error" {
		t.Fatal("approval survived connection edit")
	}
}

func TestPolicyAndAuditOutagesFailClosed(t *testing.T) {
	f := setupSecurityTest(t)
	ctx := context.Background()
	for _, table := range []string{"security_policies", "masking_rules", "audit_logs"} {
		t.Run(table, func(t *testing.T) {
			f.exec(t, `ALTER TABLE `+table+` RENAME TO unavailable`)
			out := f.s.Execute(ctx, f.request(f.admin, f.update()))
			f.exec(t, `ALTER TABLE unavailable RENAME TO `+table)
			if out.Status != "error" || f.value(t) != 0 {
				t.Fatalf("write executed during %s outage: %+v", table, out)
			}
		})
	}
	f.exec(t, `DELETE FROM security_policies WHERE environment='production'`)
	if out := f.s.Execute(ctx, f.request(f.admin, f.update())); out.Status != "error" {
		t.Fatal("missing policy fell back to defaults")
	}
	// Completion outages leave an explicit unknown outcome and can be retried
	// idempotently after storage recovers, without replaying target SQL.
	id, err := f.s.beginExecution(ctx, f.request(f.admin, f.update()), f.conn.ID, f.conn.DatabaseName)
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `ALTER TABLE audit_logs RENAME TO unavailable`)
	if err = f.s.finishExecution(id, "success", "", 1, 10); err == nil {
		t.Fatal("audit failure ignored")
	}
	f.exec(t, `ALTER TABLE unavailable RENAME TO audit_logs`)
	var status string
	if err = f.pool.QueryRow(ctx, `SELECT status FROM query_history WHERE id=$1`, id).Scan(&status); err != nil || status != "running" {
		t.Fatalf("intent lost: %s %v", status, err)
	}
	if err = f.s.finishExecution(id, "success", "", 1, 10); err != nil {
		t.Fatal(err)
	}
	if err = f.s.finishExecution(id, "success", "", 1, 10); err != nil {
		t.Fatal(err)
	}
}

func TestMetadataAndExportAuthorization(t *testing.T) {
	f := setupSecurityTest(t)
	ctx := context.Background()
	h := &Handlers{Svc: f.s, Conns: f.s.conns, Policies: f.s.policies, Audit: f.s.audit}
	app := fiber.New()
	actor := f.analyst
	app.Use(func(c fiber.Ctx) error { c.Locals(auth.LocalUser, actor); return c.Next() })
	app.Post("/export", h.Export)
	app.Get("/explorer/tables", h.Tables)
	app.Get("/explorer/columns", h.Columns)
	status := func(path string, form url.Values) int {
		t.Helper()
		method := "GET"
		if form != nil {
			method = "POST"
		}
		r := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := app.Test(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	out := f.s.Execute(ctx, f.request(f.analyst, "SELECT id FROM "+f.schema+".target"))
	if out.Status != "success" {
		t.Fatal(out.Message)
	}
	form := url.Values{"history_id": {out.HistoryID}, "format": {"csv"}, "connection_id": {f.other.ID}}
	if status("/export", form) != 403 {
		t.Fatal("disabled export accepted")
	}
	f.exec(t, `UPDATE security_policies SET allow_export=true WHERE environment='production'`)
	if status("/export", form) != 204 {
		t.Fatal("allowed export failed")
	}
	var exportedConn, exportedSQL string
	if err := f.pool.QueryRow(ctx, `SELECT connection_id,query_text FROM audit_logs WHERE action=$1 AND entity_id=$2`, audit.ActionExportRequested, out.HistoryID).Scan(&exportedConn, &exportedSQL); err != nil {
		t.Fatal(err)
	}
	if exportedConn != f.conn.ID || !strings.Contains(exportedSQL, "SELECT id FROM "+f.schema+".target") {
		t.Fatal("export trusted client attribution")
	}
	f.exec(t, `ALTER TABLE audit_logs RENAME TO unavailable`)
	if status("/export", form) != 503 {
		t.Fatal("export accepted without durable audit")
	}
	f.exec(t, `ALTER TABLE unavailable RENAME TO audit_logs`)
	f.exec(t, `ALTER TABLE security_policies RENAME TO unavailable`)
	if status("/export", form) != 503 {
		t.Fatal("export accepted without policy")
	}
	f.exec(t, `ALTER TABLE unavailable RENAME TO security_policies`)
	actor = f.developer
	if status("/export", form) != 403 {
		t.Fatal("another user's result exported")
	}
	actor = f.analyst
	f.exec(t, `UPDATE security_policies SET allowed_schemas=$1 WHERE environment='production'`, f.schema)
	for _, path := range []string{"/explorer/tables", "/explorer/columns"} {
		if status(path+"?connection="+f.conn.ID+"&schema=restricted&table=secret", nil) != 403 {
			t.Fatal("metadata schema restriction bypass")
		}
	}
	if out := f.s.Execute(ctx, f.request(f.admin, "SELECT * FROM public.secret")); out.Status != "blocked" {
		t.Fatal("SQL schema restriction bypass")
	}
	actor = f.auditor
	if status("/explorer/tables?connection="+f.conn.ID+"&schema="+f.schema, nil) != 403 {
		t.Fatal("auditor accessed target metadata")
	}
}
