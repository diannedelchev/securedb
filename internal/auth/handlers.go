package auth

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/diannedelchev/securedb/internal/audit"
	"github.com/diannedelchev/securedb/internal/users"
)

// Handlers implements local email/password login. The Authenticate call is the
// single integration point to swap in Azure AD / Office365 SSO later: an OIDC
// callback would resolve the user and then reuse the same session issuing below.
type Handlers struct {
	Store        *Store
	Users        *users.Service
	Audit        *audit.Logger
	CookieSecure bool
}

func (h *Handlers) LoginPage(c fiber.Ctx) error {
	if c.Cookies(SessionCookie) != "" {
		if _, err := h.Store.Get(c.Context(), c.Cookies(SessionCookie)); err == nil {
			return c.Redirect().To("/")
		}
	}
	return c.Render("login", fiber.Map{"Title": "Sign in"})
}

func (h *Handlers) Login(c fiber.Ctx) error {
	email := strings.TrimSpace(c.FormValue("email"))
	password := c.FormValue("password")
	ip, ua := c.IP(), c.Get("User-Agent")

	user, err := h.Users.Authenticate(c.Context(), email, password)
	if err != nil {
		h.Audit.Log(c.Context(), audit.Entry{
			Action: audit.ActionLoginFailed, EntityType: "user", EntityID: email,
			IP: ip, UserAgent: ua, Status: "failure", ErrorMessage: err.Error(),
		})
		return c.Status(fiber.StatusUnauthorized).Render("login", fiber.Map{
			"Title": "Sign in",
			"Error": "Invalid email or password.",
			"Email": email,
		})
	}

	token, sess, err := h.Store.Create(c.Context(), user.ID, ip, ua)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not create session")
	}
	c.Cookie(&fiber.Cookie{
		Name:     SessionCookie,
		Value:    token,
		Expires:  sess.ExpiresAt,
		HTTPOnly: true,
		Secure:   h.CookieSecure,
		SameSite: "Lax",
		Path:     "/",
	})
	h.Audit.Log(c.Context(), audit.Entry{
		UserID: user.ID, Action: audit.ActionLogin, EntityType: "user", EntityID: user.ID,
		IP: ip, UserAgent: ua,
	})
	return c.Redirect().To("/")
}

func (h *Handlers) Logout(c fiber.Ctx) error {
	user := CurrentUser(c)
	if token, ok := c.Locals(LocalSession).(string); ok && token != "" {
		_ = h.Store.Delete(c.Context(), token)
	}
	c.Cookie(&fiber.Cookie{
		Name: SessionCookie, Value: "", Expires: time.Now().Add(-time.Hour),
		HTTPOnly: true, Secure: h.CookieSecure, SameSite: "Lax", Path: "/",
	})
	if user != nil {
		h.Audit.Log(c.Context(), audit.Entry{
			UserID: user.ID, Action: audit.ActionLogout, EntityType: "user", EntityID: user.ID,
			IP: c.IP(), UserAgent: c.Get("User-Agent"),
		})
	}
	return c.Redirect().To("/login")
}
