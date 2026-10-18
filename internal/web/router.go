package web

import (
	"embed"
	"io/fs"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/static"

	"github.com/diannedelchev/securedb/internal/approvals"
	"github.com/diannedelchev/securedb/internal/audit"
	"github.com/diannedelchev/securedb/internal/auth"
	"github.com/diannedelchev/securedb/internal/connections"
	"github.com/diannedelchev/securedb/internal/dashboard"
	"github.com/diannedelchev/securedb/internal/pam"
	"github.com/diannedelchev/securedb/internal/policies"
	"github.com/diannedelchev/securedb/internal/query"
	"github.com/diannedelchev/securedb/internal/settings"
	"github.com/diannedelchev/securedb/internal/users"
)

//go:embed static
var staticFS embed.FS

// Deps wires every module's handlers into the router.
type Deps struct {
	Auth        *auth.Handlers
	SessionSt   *auth.Store
	Users       *users.Service
	UserH       *users.Handlers
	Connections *connections.Handlers
	Query       *query.Handlers
	Approvals   *approvals.Handlers
	Grants      *pam.Handlers
	Audit       *audit.Handlers
	Policies    *policies.Handlers
	Dashboard   *dashboard.Handlers
	Settings    *settings.Handlers
}

func Register(app *fiber.App, d Deps) {
	// Security headers on everything.
	app.Use(func(c fiber.Ctx) error {
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "DENY")
		c.Set("Referrer-Policy", "same-origin")
		// unsafe-inline/eval are needed by the inline HTMX helpers; all
		// template output is auto-escaped by html/template. Fonts are
		// self-hosted under /static/fonts (no third-party origins).
		c.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"font-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
		return c.Next()
	})

	staticSub, _ := fs.Sub(staticFS, "static")
	app.Get("/static/*", static.New("", static.Config{FS: staticSub, MaxAge: 3600}))

	// Liveness probe for containers and load balancers (no auth).
	app.Get("/healthz", func(c fiber.Ctx) error { return c.SendString("ok") })

	// Anonymous visitors are sent to the sign-in page by the auth middleware
	// below; "/" is the authenticated dashboard.
	app.Get("/login", d.Auth.LoginPage)
	app.Post("/login", d.Auth.Login)

	// Everything below requires an authenticated session (auth middleware also
	// enforces CSRF on state-changing verbs).
	app.Use(auth.RequireAuth(d.SessionSt, d.Users))

	// Pending approvals + access-window requests feed the nav badge.
	app.Use(func(c fiber.Ctx) error {
		total := 0
		if n, err := d.Approvals.Svc.CountPending(c.Context()); err == nil {
			total += n
		}
		if n, err := d.Grants.Svc.CountPending(c.Context()); err == nil {
			total += n
		}
		if total > 0 {
			c.Locals("pending_approvals", total)
		}
		return c.Next()
	})

	app.Post("/logout", d.Auth.Logout)
	// Own profile only (any authenticated user): UI preferences and password.
	app.Post("/profile/editor-layout", d.UserH.SaveEditorLayout)
	app.Post("/profile/password", d.Auth.ChangePassword)
	app.Get("/", d.Dashboard.Dashboard)
	app.Get("/dashboard/volume", d.Dashboard.Volume)

	// Registering a connection makes this server open outbound TCP/SSH
	// sessions with shared credentials, so only admins and DBAs may do it.
	connAdmin := auth.RequireRole(users.RoleAdmin, users.RoleDBA)
	app.Get("/connections", d.Connections.List)
	app.Get("/connections/new", connAdmin, d.Connections.NewForm)
	app.Post("/connections", connAdmin, d.Connections.Create)
	app.Get("/connections/:id/edit", d.Connections.EditForm)
	app.Post("/connections/:id", d.Connections.Update)
	app.Delete("/connections/:id", d.Connections.Delete)
	app.Post("/connections/:id/test", d.Connections.Test)

	app.Get("/editor", d.Query.EditorPage)
	app.Get("/search", d.Query.Search)
	app.Post("/query/execute", d.Query.Execute)
	app.Post("/query/cancel", d.Query.Cancel)
	app.Post("/query/export", d.Query.Export)
	app.Post("/query/save", d.Query.SaveQuery)
	app.Delete("/query/saved/:id", d.Query.DeleteSavedQuery)
	app.Get("/history", d.Query.HistoryPage)

	app.Get("/explorer", d.Query.ExplorerPage)
	app.Get("/explorer/databases", d.Query.Databases)
	app.Get("/explorer/schemas", d.Query.Schemas)
	app.Get("/explorer/tables", d.Query.Tables)
	app.Get("/explorer/columns", d.Query.Columns)

	app.Get("/approvals", d.Approvals.List)
	app.Get("/approvals/:id", d.Approvals.Detail)
	app.Post("/approvals/:id/decide", d.Approvals.Decide)

	// PAM: just-in-time access windows.
	app.Post("/grants", d.Grants.Request)
	app.Get("/grants/:id", d.Grants.Detail)
	app.Post("/grants/:id/decide", d.Grants.Decide)
	app.Post("/grants/:id/revoke", d.Grants.Revoke)

	// Auditors, DBAs and admins can read audit logs.
	auditRole := auth.RequireRole(users.RoleAdmin, users.RoleDBA, users.RoleAuditor)
	app.Get("/audit", auditRole, d.Audit.List)
	app.Get("/audit/:id", auditRole, d.Audit.Detail)

	app.Get("/policies", d.Policies.List)
	app.Post("/policies/:env", auth.RequireRole(users.RoleAdmin), d.Policies.Update)

	adminOnly := auth.RequireRole(users.RoleAdmin)
	app.Get("/users", adminOnly, d.UserH.List)
	app.Post("/users", adminOnly, d.UserH.Create)
	app.Post("/users/:id/roles", adminOnly, d.UserH.SetRoles)
	app.Post("/users/:id/active", adminOnly, d.UserH.SetActive)

	app.Get("/settings", adminOnly, d.Settings.Page)
	app.Post("/settings/:key", adminOnly, d.Settings.Update)

	// 404 fallthrough.
	app.Use(func(c fiber.Ctx) error {
		return c.Status(fiber.StatusNotFound).Render("error", fiber.Map{
			"Title": "Not found", "Message": "The page you requested does not exist.",
			"User": c.Locals("current_user"), "Path": c.Path(),
		}, "layouts/main")
	})
}
