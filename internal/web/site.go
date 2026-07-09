package web

import (
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/dian/securedb/internal/auth"
)

// registerSite mounts the public marketing pages. It must run before the auth
// middleware: "/" falls through to the authenticated dashboard when a valid
// session is present, everything else renders for anonymous visitors.
func registerSite(app *fiber.App, d Deps) {
	app.Get("/", func(c fiber.Ctx) error {
		if token := c.Cookies(auth.SessionCookie); token != "" {
			if _, err := d.SessionSt.Get(c.Context(), token); err == nil {
				return c.Next() // signed in → continue to the dashboard route
			}
		}
		return renderSite(c, "site/home", "",
			"Query PostgreSQL, MySQL and SQL Server from the browser with policy guardrails, approvals, data masking and a full audit trail.")
	})
	app.Get("/features", func(c fiber.Ctx) error {
		return renderSite(c, "site/features", "Features",
			"SQL editor, database explorer, policy engine, data masking, approvals, just-in-time access and audit logs — everything SecureDB ships with.")
	})
	app.Get("/privacy", func(c fiber.Ctx) error {
		return renderSite(c, "site/privacy", "Privacy Policy",
			"What information SecureDB processes, how it is protected, and the choices you have.")
	})
	app.Get("/terms", func(c fiber.Ctx) error {
		return renderSite(c, "site/terms", "Terms of Service",
			"The terms that govern use of this SecureDB installation.")
	})
}

func renderSite(c fiber.Ctx, tpl, title, description string) error {
	return c.Render(tpl, fiber.Map{
		"Title":       title,
		"Description": description,
		"Path":        c.Path(),
		"Year":        time.Now().Year(),
	}, "layouts/site")
}
