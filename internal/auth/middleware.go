package auth

import (
	"crypto/subtle"

	"github.com/gofiber/fiber/v3"

	"github.com/diannedelchev/securedb/internal/users"
)

// Locals keys used across handlers.
const (
	LocalUser    = "current_user"
	LocalCSRF    = "csrf_token"
	LocalSession = "session_token"
)

// CurrentUser returns the authenticated user attached by RequireAuth.
func CurrentUser(c fiber.Ctx) *users.User {
	if u, ok := c.Locals(LocalUser).(*users.User); ok {
		return u
	}
	return nil
}

func CSRFToken(c fiber.Ctx) string {
	if t, ok := c.Locals(LocalCSRF).(string); ok {
		return t
	}
	return ""
}

// RequireAuth loads the session, attaches the user, and enforces CSRF on
// state-changing requests.
func RequireAuth(store *Store, userSvc *users.Service) fiber.Handler {
	return func(c fiber.Ctx) error {
		token := c.Cookies(SessionCookie)
		if token == "" {
			return redirectToLogin(c)
		}
		sess, err := store.Get(c.Context(), token)
		if err != nil {
			c.ClearCookie(SessionCookie)
			return redirectToLogin(c)
		}
		user, err := userSvc.GetByID(c.Context(), sess.UserID)
		if err != nil || !user.IsActive {
			_ = store.Delete(c.Context(), token)
			c.ClearCookie(SessionCookie)
			return redirectToLogin(c)
		}
		c.Locals(LocalUser, user)
		c.Locals(LocalCSRF, sess.CSRFToken)
		c.Locals(LocalSession, token)

		switch c.Method() {
		case fiber.MethodPost, fiber.MethodPut, fiber.MethodPatch, fiber.MethodDelete:
			sent := c.Get("X-CSRF-Token")
			if sent == "" {
				sent = c.FormValue("_csrf")
			}
			if subtle.ConstantTimeCompare([]byte(sent), []byte(sess.CSRFToken)) != 1 {
				return c.Status(fiber.StatusForbidden).SendString("invalid CSRF token")
			}
		}
		return c.Next()
	}
}

// RequireRole guards a route group to users holding at least one of the roles.
func RequireRole(roles ...string) fiber.Handler {
	return func(c fiber.Ctx) error {
		user := CurrentUser(c)
		if user == nil {
			return redirectToLogin(c)
		}
		for _, r := range roles {
			if user.HasRole(r) {
				return c.Next()
			}
		}
		return c.Status(fiber.StatusForbidden).Render("error", fiber.Map{
			"Title":   "Forbidden",
			"Message": "You do not have permission to access this page.",
			"User":    user,
		}, "layouts/main")
	}
}

func redirectToLogin(c fiber.Ctx) error {
	// HTMX requests get a client-side redirect header instead of a 302 into a fragment.
	if c.Get("HX-Request") == "true" {
		c.Set("HX-Redirect", "/login")
		return c.SendStatus(fiber.StatusUnauthorized)
	}
	return c.Redirect().To("/login")
}
