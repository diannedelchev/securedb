package pam

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/diannedelchev/securedb/internal/audit"
	"github.com/diannedelchev/securedb/internal/auth"
	"github.com/diannedelchev/securedb/internal/users"
	"github.com/diannedelchev/securedb/internal/web/view"
)

type Handlers struct {
	Svc   *Service
	Audit *audit.Logger
}

// Request opens a new access-window request (any authenticated user).
func (h *Handlers) Request(c fiber.Ctx) error {
	user := auth.CurrentUser(c)
	duration, err := time.ParseDuration(c.FormValue("duration"))
	if err != nil {
		return view.Toast(c, "error", "invalid duration")
	}
	reason := strings.TrimSpace(c.FormValue("reason"))
	if reason == "" {
		return view.Toast(c, "error", "a reason is required for privileged access")
	}
	g, err := h.Svc.Request(c.Context(), user.ID, c.FormValue("connection_id"), duration, reason)
	entry := audit.Entry{
		UserID: user.ID, Action: audit.ActionGrantRequested, EntityType: "access_grant",
		IP: c.IP(), UserAgent: c.Get("User-Agent"),
	}
	if err != nil {
		entry.Status = "failure"
		entry.ErrorMessage = err.Error()
		h.Audit.Log(c.Context(), entry)
		return view.Toast(c, "error", err.Error())
	}
	entry.EntityID = g.ID
	entry.ConnectionID = g.ConnectionID
	h.Audit.Log(c.Context(), entry)
	c.Set("HX-Refresh", "true")
	return c.SendStatus(fiber.StatusOK)
}

// Detail renders the grant pane on the approvals screen.
func (h *Handlers) Detail(c fiber.Ctx) error {
	user := auth.CurrentUser(c)
	g, err := h.Svc.Get(c.Context(), c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "grant not found")
	}
	if !user.IsApprover() && !user.HasRole(users.RoleAuditor) && g.UserID != user.ID {
		return fiber.NewError(fiber.StatusForbidden, "not your request")
	}
	return view.Partial(c, "partials/grant_detail", fiber.Map{
		"G": g, "IsApprover": user.IsApprover(),
	})
}

func (h *Handlers) Decide(c fiber.Ctx) error {
	user := auth.CurrentUser(c)
	if !user.IsApprover() {
		return fiber.NewError(fiber.StatusForbidden, "only admins and DBAs can decide access requests")
	}
	decision := c.FormValue("decision")
	g, err := h.Svc.Decide(c.Context(), c.Params("id"), user.ID, decision, strings.TrimSpace(c.FormValue("comments")))
	action := audit.ActionGrantApproved
	if decision == "rejected" {
		action = audit.ActionGrantRejected
	}
	entry := audit.Entry{
		UserID: user.ID, Action: action, EntityType: "access_grant", EntityID: c.Params("id"),
		IP: c.IP(), UserAgent: c.Get("User-Agent"),
	}
	if err != nil {
		entry.Status = "failure"
		entry.ErrorMessage = err.Error()
		h.Audit.Log(c.Context(), entry)
		return view.Toast(c, "error", err.Error())
	}
	entry.ConnectionID = g.ConnectionID
	h.Audit.Log(c.Context(), entry)
	c.Set("HX-Refresh", "true")
	return c.SendStatus(fiber.StatusOK)
}

func (h *Handlers) Revoke(c fiber.Ctx) error {
	user := auth.CurrentUser(c)
	if !user.IsApprover() {
		return fiber.NewError(fiber.StatusForbidden, "only admins and DBAs can revoke access windows")
	}
	g, err := h.Svc.Revoke(c.Context(), c.Params("id"), user.ID)
	entry := audit.Entry{
		UserID: user.ID, Action: audit.ActionGrantRevoked, EntityType: "access_grant", EntityID: c.Params("id"),
		IP: c.IP(), UserAgent: c.Get("User-Agent"),
	}
	if err != nil {
		entry.Status = "failure"
		entry.ErrorMessage = err.Error()
		h.Audit.Log(c.Context(), entry)
		return view.Toast(c, "error", err.Error())
	}
	entry.ConnectionID = g.ConnectionID
	h.Audit.Log(c.Context(), entry)
	c.Set("HX-Refresh", "true")
	return c.SendStatus(fiber.StatusOK)
}
