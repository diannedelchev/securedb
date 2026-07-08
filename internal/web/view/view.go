package view

import (
	"github.com/gofiber/fiber/v3"
)

// Locals keys — kept in sync with the auth middleware (which cannot be
// imported here without creating an import cycle through domain packages).
const (
	localUser = "current_user"
	localCSRF = "csrf_token"
)

// Render wraps c.Render with the data every layout page needs: the current
// user, CSRF token and active nav item.
func Render(c fiber.Ctx, name string, data fiber.Map) error {
	if data == nil {
		data = fiber.Map{}
	}
	data["User"] = c.Locals(localUser)
	data["CSRF"] = csrf(c)
	data["Path"] = c.Path()
	data["PendingApprovals"] = c.Locals("pending_approvals")
	return c.Render(name, data, "layouts/main")
}

// Partial renders a template without the layout (HTMX fragment responses).
func Partial(c fiber.Ctx, name string, data fiber.Map) error {
	if data == nil {
		data = fiber.Map{}
	}
	if _, ok := data["User"]; !ok {
		data["User"] = c.Locals(localUser)
	}
	data["CSRF"] = csrf(c)
	return c.Render(name, data)
}

// Toast renders the shared toast partial, used as an HTMX response.
func Toast(c fiber.Ctx, kind, message string) error {
	return c.Render("partials/toast", fiber.Map{"Kind": kind, "Message": message})
}

func csrf(c fiber.Ctx) string {
	if t, ok := c.Locals(localCSRF).(string); ok {
		return t
	}
	return ""
}
