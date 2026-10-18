package query

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"

	"github.com/diannedelchev/securedb/internal/audit"
	"github.com/diannedelchev/securedb/internal/auth"
	"github.com/diannedelchev/securedb/internal/connections"
	"github.com/diannedelchev/securedb/internal/connectors"
	"github.com/diannedelchev/securedb/internal/policies"
	"github.com/diannedelchev/securedb/internal/users"
	"github.com/diannedelchev/securedb/internal/web/view"
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

// Export authorizes and records the supported download before the browser starts
// it. The originating query/connection come from durable history, not form data.
func (h *Handlers) Export(c fiber.Ctx) error {
	user := auth.CurrentUser(c)
	if !user.CanQuery() {
		return fiber.NewError(fiber.StatusForbidden, "your roles do not allow exports")
	}
	id := strings.TrimSpace(c.FormValue("history_id"))
	var connID, env, database, sql string
	var rows int
	err := h.Svc.pool.QueryRow(c.Context(), `SELECT c.id,c.environment,h.database_name,h.query_text,h.row_count
		FROM query_history h JOIN database_connections c ON c.id=h.connection_id
		WHERE h.id=$1 AND h.user_id=$2 AND h.status='success' AND c.is_active`, id, user.ID).Scan(&connID, &env, &database, &sql, &rows)
	if err != nil {
		return fiber.NewError(fiber.StatusForbidden, "result is not available for export")
	}
	policy, err := h.Policies.ForEnvironment(c.Context(), env)
	if err != nil {
		return fiber.NewError(fiber.StatusServiceUnavailable, "security policy unavailable")
	}
	if !policy.AllowExport {
		return fiber.NewError(fiber.StatusForbidden, "export is disabled by policy")
	}
	format := strings.ToLower(strings.TrimSpace(c.FormValue("format")))
	if format != "csv" && format != "json" {
		return fiber.NewError(fiber.StatusBadRequest, "invalid export format")
	}
	if err := h.Audit.Log(c.Context(), audit.Entry{
		UserID: user.ID, Action: audit.ActionExportRequested, EntityType: "query", EntityID: id,
		ConnectionID: connID, QueryText: fmt.Sprintf("%s export · %d rows · database %s\n%s", strings.ToUpper(format), rows, database, sql), Status: "success", IP: c.IP(), UserAgent: c.Get("User-Agent"),
	}); err != nil {
		return fiber.NewError(fiber.StatusServiceUnavailable, "export audit unavailable")
	}
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

// Search powers the topbar global search: the user's recent queries plus the
// visible connections, rendered as a dropdown fragment.
func (h *Handlers) Search(c fiber.Ctx) error {
	q := strings.TrimSpace(c.Query("q"))
	if len(q) < 2 {
		return view.Partial(c, "partials/search_results", fiber.Map{"Q": q})
	}
	user := auth.CurrentUser(c)
	conns, err := h.Conns.List(c.Context())
	if err != nil {
		return err
	}
	needle := strings.ToLower(q)
	var matched []*connections.Connection
	for _, cn := range conns {
		haystack := strings.ToLower(cn.Name + " " + cn.Host + " " + cn.Tags + " " + cn.DatabaseName + " " + cn.DBType + " " + cn.Environment)
		if strings.Contains(haystack, needle) {
			matched = append(matched, cn)
		}
		if len(matched) == 5 {
			break
		}
	}
	queries, err := h.Svc.SearchHistory(c.Context(), user.ID, q, 8)
	if err != nil {
		return err
	}
	return view.Partial(c, "partials/search_results", fiber.Map{
		"Q": q, "Connections": matched, "Queries": queries,
	})
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
	policy := c.Locals("effective_query_policy").(policies.Policy)
	filtered := schemas[:0]
	for _, schema := range schemas {
		if policy.AllowsSchema(schema.Name) {
			filtered = append(filtered, schema)
		}
	}
	schemas = filtered

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
		policy := c.Locals("effective_query_policy").(policies.Policy)
		writePerm := "GRANTED"
		switch {
		case conn.ReadOnly || !user.CanWrite(conn.Environment):
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
	if !auth.CurrentUser(c).CanQuery() {
		return nil, fiber.NewError(fiber.StatusForbidden, "your roles do not allow database queries")
	}
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
	deny := func(message string) (*connections.Connection, connectors.ConnectionConfig, connectors.DBConnector, func(fiber.Ctx) error) {
		return nil, connectors.ConnectionConfig{}, nil, func(c fiber.Ctx) error { return fiber.NewError(fiber.StatusForbidden, message) }
	}
	if !auth.CurrentUser(c).CanQuery() {
		return deny("your roles do not allow database queries")
	}

	conn, err := h.Conns.Get(c.Context(), c.Query("connection"))
	if err != nil || !conn.IsActive {
		return nil, connectors.ConnectionConfig{}, nil, func(c fiber.Ctx) error {
			return view.Partial(c, "partials/explorer_error", fiber.Map{"Error": "connection not found or inactive"})
		}
	}
	policy, err := h.Policies.ForEnvironment(c.Context(), conn.Environment)
	if err != nil {
		return deny("security policy unavailable")
	}
	if (c.Path() == "/explorer/tables" || c.Path() == "/explorer/columns") && !policy.AllowsSchema(c.Query("schema")) {
		return deny("schema is not allowed by policy")
	}
	c.Locals("effective_query_policy", policy)

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
