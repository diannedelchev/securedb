package query

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"

	"github.com/dian/securedb/internal/audit"
	"github.com/dian/securedb/internal/auth"
	"github.com/dian/securedb/internal/connections"
	"github.com/dian/securedb/internal/connectors"
	"github.com/dian/securedb/internal/policies"
	"github.com/dian/securedb/internal/users"
	"github.com/dian/securedb/internal/web/view"
)

type Handlers struct {
	Svc      *Service
	Conns    *connections.Service
	Policies *policies.Service
	Audit    *audit.Logger
	Users    *users.Service
}

// EditorPage renders the SQL editor with connection selector, explorer,
// history and saved queries.
func (h *Handlers) EditorPage(c fiber.Ctx) error {
	user := auth.CurrentUser(c)
	conns, err := h.activeConnections(c)
	if err != nil {
		return err
	}
	history, _ := h.Svc.History(c.Context(), user.ID, false, 20)
	saved, _ := h.Svc.SavedQueries(c.Context(), user.ID)
	// Saved pane sizes from the user's profile; empty means defaults.
	layout, _ := h.Users.GetPreference(c.Context(), user.ID, users.PrefEditorLayout)
	return view.Render(c, "editor", fiber.Map{
		"Title":        "SQL Editor",
		"FullBleed":    true,
		"Connections":  conns,
		"History":      history,
		"Saved":        saved,
		"SelectedID":   c.Query("connection"),
		"InitialSQL":   c.Query("sql"),
		"InitialDB":    c.Query("db"),
		"ApprovalID":   c.Query("approval"),
		"EditorLayout": layout,
	})
}

// Execute runs a query and returns the result grid fragment.
func (h *Handlers) Execute(c fiber.Ctx) error {
	user := auth.CurrentUser(c)
	outcome := h.Svc.Execute(c.Context(), ExecRequest{
		User:         user,
		ConnectionID: c.FormValue("connection_id"),
		Database:     strings.TrimSpace(c.FormValue("database")),
		SQL:          strings.TrimSpace(c.FormValue("sql")),
		Reason:       strings.TrimSpace(c.FormValue("reason")),
		ApprovalID:   strings.TrimSpace(c.FormValue("approval_id")),
		RunID:        c.FormValue("run_id"),
		RowLimit:     parseRowLimit(c.FormValue("row_limit")),
		IP:           c.IP(),
		UserAgent:    c.Get("User-Agent"),
	})
	return view.Partial(c, "partials/query_result", fiber.Map{"Outcome": outcome})
}

// Cancel stops an in-flight query.
func (h *Handlers) Cancel(c fiber.Ctx) error {
	user := auth.CurrentUser(c)
	runID := c.FormValue("run_id")
	if h.Svc.Cancel(runID, user.ID, user.IsAdmin()) {
		h.Audit.Log(c.Context(), audit.Entry{
			UserID: user.ID, Action: audit.ActionQueryCancelled, EntityType: "query",
			EntityID: runID, IP: c.IP(), UserAgent: c.Get("User-Agent"),
		})
		return view.Toast(c, "info", "Cancellation requested")
	}
	return view.Toast(c, "warning", "No running query with that ID")
}

// Export records that result rows left the gateway. The file itself is built
// in the browser from the grid the user was already shown — that keeps the
// export byte-identical to the masked view and avoids re-running the query
// against the target database — so this endpoint exists purely to put the
// event in the audit trail.
func (h *Handlers) Export(c fiber.Ctx) error {
	user := auth.CurrentUser(c)

	format := strings.ToLower(strings.TrimSpace(c.FormValue("format")))
	if format != "csv" && format != "json" {
		format = "csv"
	}
	rows := clampCount(c.FormValue("rows"))
	cols := clampCount(c.FormValue("columns"))
	masked := clampCount(c.FormValue("masked"))

	summary := fmt.Sprintf("%s export · %d row%s × %d column%s",
		strings.ToUpper(format), rows, plural(rows), cols, plural(cols))
	if masked > 0 {
		summary += fmt.Sprintf(" · %d masked", masked)
	}
	// Recording the originating SQL is what makes the entry useful to an
	// auditor: it identifies exactly which data was taken.
	if sql := strings.TrimSpace(c.FormValue("sql")); sql != "" {
		summary += "\n" + truncateText(sql, 4000)
	}

	h.Audit.Log(c.Context(), audit.Entry{
		UserID:       user.ID,
		Action:       audit.ActionExportRequested,
		EntityType:   "query",
		ConnectionID: strings.TrimSpace(c.FormValue("connection_id")),
		QueryText:    summary,
		Status:       "success",
		IP:           c.IP(),
		UserAgent:    c.Get("User-Agent"),
	})
	return c.SendStatus(fiber.StatusNoContent)
}

// parseRowLimit reads the editor's LIMIT selector. 0 means unlimited; a
// missing or malformed value falls back to the environment policy default.
func parseRowLimit(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return RowLimitPolicyDefault
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 10_000_000 {
		return RowLimitPolicyDefault
	}
	return n
}

// clampCount parses a client-supplied count defensively — it is only ever used
// for the audit description, so anything out of range collapses to 0.
func clampCount(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 || n > 10_000_000 {
		return 0
	}
	return n
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func truncateText(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + " …(truncated)"
}

// HistoryPage lists past queries. Auditors and admins see everyone's history.
func (h *Handlers) HistoryPage(c fiber.Ctx) error {
	user := auth.CurrentUser(c)
	all := (user.IsAdmin() || user.HasRole(users.RoleAuditor)) && c.Query("scope") == "all"
	items, err := h.Svc.History(c.Context(), user.ID, all, 100)
	if err != nil {
		return err
	}
	search := strings.ToLower(strings.TrimSpace(c.Query("q")))
	status := c.Query("status")
	env := c.Query("env")
	filtered := items[:0]
	for _, it := range items {
		if search != "" && !strings.Contains(strings.ToLower(it.QueryText+" "+it.ConnectionName), search) {
			continue
		}
		if status != "" && it.Status != status {
			continue
		}
		if env != "" && it.Environment != env {
			continue
		}
		filtered = append(filtered, it)
	}
	data := fiber.Map{
		"Title":    "Query History",
		"Days":     GroupByDay(filtered),
		"Count":    len(filtered),
		"Search":   c.Query("q"),
		"Status":   status,
		"Env":      env,
		"ScopeAll": all,
		"CanAll":   user.IsAdmin() || user.HasRole(users.RoleAuditor),
	}
	if c.Get("HX-Request") == "true" {
		return view.Partial(c, "partials/history_timeline", data)
	}
	return view.Render(c, "history", data)
}

func (h *Handlers) SaveQuery(c fiber.Ctx) error {
	user := auth.CurrentUser(c)
	err := h.Svc.SaveQuery(c.Context(), user.ID,
		c.FormValue("connection_id"), strings.TrimSpace(c.FormValue("name")), c.FormValue("sql"))
	if err != nil {
		return view.Toast(c, "error", err.Error())
	}
	saved, _ := h.Svc.SavedQueries(c.Context(), user.ID)
	return view.Partial(c, "partials/saved_queries", fiber.Map{"Saved": saved, "ToastMessage": "Query saved"})
}

func (h *Handlers) DeleteSavedQuery(c fiber.Ctx) error {
	user := auth.CurrentUser(c)
	if err := h.Svc.DeleteSavedQuery(c.Context(), user.ID, c.Params("id")); err != nil {
		return view.Toast(c, "error", err.Error())
	}
	saved, _ := h.Svc.SavedQueries(c.Context(), user.ID)
	return view.Partial(c, "partials/saved_queries", fiber.Map{"Saved": saved})
}

// --- Database explorer ---

// ExplorerPage is the standalone explorer view.
func (h *Handlers) ExplorerPage(c fiber.Ctx) error {
	conns, err := h.activeConnections(c)
	if err != nil {
		return err
	}
	return view.Render(c, "explorer", fiber.Map{
		"Title":       "Database Explorer",
		"FullBleed":   true,
		"Connections": conns,
		"SelectedID":  c.Query("connection"),
	})
}

// Databases returns the list of databases on the connection's server as a
// <select> options fragment (multi-database support: one connection, every
// database its credentials can reach).
func (h *Handlers) Databases(c fiber.Ctx) error {
	if c.Query("connection") == "" {
		return c.SendString(``)
	}
	conn, cfg, connector, errResp := h.resolve(c)
	if errResp != nil {
		return errResp(c)
	}
	dbs, err := connector.ListDatabases(c.Context(), cfg)
	if err != nil {
		// Fall back to just the default database when listing is not
		// permitted (or the engine is a stub).
		dbs = []connectors.DatabaseInfo{{Name: conn.DatabaseName, IsDefault: true}}
	}
	selected := c.Query("database")
	if selected == "" {
		selected = conn.DatabaseName
	}
	return view.Partial(c, "partials/database_options", fiber.Map{
		"ConnID": conn.ID, "Databases": dbs, "Selected": selected, "Mode": c.Query("mode"),
	})
}

// Schemas returns the schema list fragment for a connection.
func (h *Handlers) Schemas(c fiber.Ctx) error {
	if c.Query("connection") == "" {
		return c.SendString(`<p class="hint">Select a connection to browse schemas.</p>`)
	}
	conn, cfg, connector, errResp := h.resolve(c)
	if errResp != nil {
		return errResp(c)
	}
	schemas, err := connector.ListSchemas(c.Context(), cfg)
	if err != nil {
		return view.Partial(c, "partials/explorer_error", fiber.Map{"Error": err.Error()})
	}
	// Honour the allowed_schemas policy when configured.
	policy, _ := h.Policies.ForEnvironment(c.Context(), conn.Environment)
	if allowed := policy.AllowedSchemaList(); len(allowed) > 0 {
		var filtered []connectors.SchemaInfo
		for _, s := range schemas {
			for _, a := range allowed {
				if strings.EqualFold(s.Name, a) {
					filtered = append(filtered, s)
					break
				}
			}
		}
		schemas = filtered
	}
	return view.Partial(c, "partials/explorer_schemas", fiber.Map{
		"ConnID": conn.ID, "Schemas": schemas, "Mode": c.Query("mode"),
		"Database": cfg.Database,
	})
}

func (h *Handlers) Tables(c fiber.Ctx) error {
	conn, cfg, connector, errResp := h.resolve(c)
	if errResp != nil {
		return errResp(c)
	}
	schema := c.Query("schema")
	tables, err := connector.ListTables(c.Context(), cfg, schema)
	if err != nil {
		return view.Partial(c, "partials/explorer_error", fiber.Map{"Error": err.Error()})
	}
	return view.Partial(c, "partials/explorer_tables", fiber.Map{
		"ConnID": conn.ID, "Schema": schema, "Tables": tables, "Mode": c.Query("mode"),
		"Database": cfg.Database,
	})
}

func (h *Handlers) Columns(c fiber.Ctx) error {
	conn, cfg, connector, errResp := h.resolve(c)
	if errResp != nil {
		return errResp(c)
	}
	schema, table := c.Query("schema"), c.Query("table")
	cols, err := connector.ListColumns(c.Context(), cfg, schema, table)
	if err != nil {
		return view.Partial(c, "partials/explorer_error", fiber.Map{"Error": err.Error()})
	}
	data := fiber.Map{
		"ConnID": conn.ID, "Schema": schema, "Table": table, "Columns": cols,
		"Database": cfg.Database,
	}
	// Indexes and constraints where the connector supports them (PostgreSQL).
	if detailer, ok := connector.(connectors.TableDetailer); ok {
		if idx, err := detailer.ListIndexes(c.Context(), cfg, schema, table); err == nil {
			data["Indexes"] = idx
		}
		if cons, err := detailer.ListConstraints(c.Context(), cfg, schema, table); err == nil {
			data["Constraints"] = cons
		}
	}
	if c.Query("mode") == "detail" {
		// Explorer page: full detail pane with tabs + inspector, including the
		// caller's effective permissions on this object.
		user := auth.CurrentUser(c)
		policy, _ := h.Policies.ForEnvironment(c.Context(), conn.Environment)
		writePerm := "GRANTED"
		switch {
		case conn.ReadOnly:
			writePerm = "DENIED"
		case !policy.AllowWriteQueries && !user.IsPrivileged():
			writePerm = "DENIED"
		case conn.Environment == "production" && policy.RequireApprovalWrites && !user.IsAdmin():
			writePerm = "APPROVAL"
		}
		ddlPerm := "DENIED"
		if user.IsAdmin() {
			ddlPerm = "GRANTED"
		}
		data["Conn"] = conn
		data["WritePerm"] = writePerm
		data["DDLPerm"] = ddlPerm
		return view.Partial(c, "partials/explorer_detail", data)
	}
	return view.Partial(c, "partials/explorer_columns", data)
}

func (h *Handlers) activeConnections(c fiber.Ctx) ([]*connections.Connection, error) {
	conns, err := h.Conns.List(c.Context())
	if err != nil {
		return nil, err
	}
	active := conns[:0]
	for _, cn := range conns {
		if cn.IsActive {
			active = append(active, cn)
		}
	}
	return active, nil
}

// resolve loads the connection, decrypts credentials and picks the connector.
func (h *Handlers) resolve(c fiber.Ctx) (*connections.Connection, connectors.ConnectionConfig, connectors.DBConnector, func(fiber.Ctx) error) {
	conn, err := h.Conns.Get(c.Context(), c.Query("connection"))
	if err != nil || !conn.IsActive {
		return nil, connectors.ConnectionConfig{}, nil, func(c fiber.Ctx) error {
			return view.Partial(c, "partials/explorer_error", fiber.Map{"Error": "connection not found or inactive"})
		}
	}
	cfg, err := h.Conns.Config(conn)
	if err != nil {
		msg := err.Error()
		return nil, connectors.ConnectionConfig{}, nil, func(c fiber.Ctx) error {
			return view.Partial(c, "partials/explorer_error", fiber.Map{"Error": msg})
		}
	}
	// Multi-database: browse any database on the connection's server.
	if db := c.Query("database"); db != "" {
		if !connectors.ValidDatabaseName(db) {
			return nil, connectors.ConnectionConfig{}, nil, func(c fiber.Ctx) error {
				return view.Partial(c, "partials/explorer_error", fiber.Map{"Error": "invalid database name"})
			}
		}
		cfg.Database = db
	}
	connector, err := connectors.ForType(conn.DBType)
	if err != nil {
		msg := err.Error()
		return nil, connectors.ConnectionConfig{}, nil, func(c fiber.Ctx) error {
			return view.Partial(c, "partials/explorer_error", fiber.Map{"Error": msg})
		}
	}
	return conn, cfg, connector, nil
}
