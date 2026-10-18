package users

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"

	"github.com/diannedelchev/securedb/internal/audit"
	"github.com/diannedelchev/securedb/internal/web/view"
)

type Handlers struct {
	Svc   *Service
	Audit *audit.Logger
}

func currentUser(c fiber.Ctx) *User {
	// mirrors auth.CurrentUser without importing auth (avoids an import cycle)
	if u, ok := c.Locals("current_user").(*User); ok {
		return u
	}
	return nil
}

func (h *Handlers) List(c fiber.Ctx) error {
	list, err := h.Svc.List(c.Context())
	if err != nil {
		return err
	}
	search := strings.ToLower(strings.TrimSpace(c.Query("q")))
	role := c.Query("role")
	filtered := list[:0]
	for _, u := range list {
		if search != "" && !strings.Contains(strings.ToLower(u.DisplayName+" "+u.Email), search) {
			continue
		}
		if role != "" && !u.HasRole(role) {
			continue
		}
		filtered = append(filtered, u)
	}
	return view.Render(c, "users", fiber.Map{
		"Title":    "Users & Roles",
		"Users":    filtered,
		"AllRoles": AllRoles,
		"Search":   c.Query("q"),
		"Role":     role,
	})
}

func (h *Handlers) Create(c fiber.Ctx) error {
	actor := currentUser(c)
	roles := formRoles(c)
	u, err := h.Svc.Create(c.Context(),
		c.FormValue("email"), c.FormValue("display_name"), c.FormValue("password"), roles)
	entry := audit.Entry{
		UserID: actor.ID, Action: audit.ActionUserCreated, EntityType: "user",
		IP: c.IP(), UserAgent: c.Get("User-Agent"),
	}
	if err != nil {
		entry.Status = "failure"
		entry.ErrorMessage = err.Error()
		h.Audit.Log(c.Context(), entry)
		return view.Toast(c, "error", err.Error())
	}
	entry.EntityID = u.ID
	h.Audit.Log(c.Context(), entry)
	c.Set("HX-Redirect", "/users")
	return c.SendStatus(fiber.StatusOK)
}

func (h *Handlers) SetRoles(c fiber.Ctx) error {
	actor := currentUser(c)
	targetID := c.Params("id")
	roles := formRoles(c)
	if len(roles) == 0 {
		return view.Toast(c, "error", "select at least one role")
	}
	// An admin cannot strip their own admin role — avoids lockouts.
	if targetID == actor.ID && !contains(roles, RoleAdmin) {
		return view.Toast(c, "error", "you cannot remove your own admin role")
	}
	if err := h.Svc.SetRoles(c.Context(), targetID, roles); err != nil {
		return view.Toast(c, "error", err.Error())
	}
	h.Audit.Log(c.Context(), audit.Entry{
		UserID: actor.ID, Action: audit.ActionUserRoleChanged, EntityType: "user",
		EntityID: targetID, IP: c.IP(), UserAgent: c.Get("User-Agent"),
		ErrorMessage: "", Status: "success", QueryText: "roles: " + strings.Join(roles, ","),
	})
	c.Set("HX-Redirect", "/users")
	return c.SendStatus(fiber.StatusOK)
}

func (h *Handlers) SetActive(c fiber.Ctx) error {
	actor := currentUser(c)
	targetID := c.Params("id")
	active := c.FormValue("active") == "true"
	if targetID == actor.ID && !active {
		return view.Toast(c, "error", "you cannot deactivate your own account")
	}
	if err := h.Svc.SetActive(c.Context(), targetID, active); err != nil {
		return view.Toast(c, "error", err.Error())
	}
	h.Audit.Log(c.Context(), audit.Entry{
		UserID: actor.ID, Action: audit.ActionUserStatusChanged, EntityType: "user",
		EntityID: targetID, IP: c.IP(), UserAgent: c.Get("User-Agent"),
	})
	c.Set("HX-Redirect", "/users")
	return c.SendStatus(fiber.StatusOK)
}

// Pane-size bounds shared with the client-side resizers (app.js).
const (
	minTreeWidth, maxTreeWidth       = 160, 480
	minEditorHeight, maxEditorHeight = 100, 900
)

// SaveEditorLayout persists the SQL editor pane sizes on the caller's profile.
func (h *Handlers) SaveEditorLayout(c fiber.Ctx) error {
	user := currentUser(c)
	treeWidth, err1 := strconv.Atoi(c.FormValue("tree_width"))
	editorHeight, err2 := strconv.Atoi(c.FormValue("editor_height"))
	if err1 != nil || err2 != nil {
		return fiber.NewError(fiber.StatusBadRequest, "tree_width and editor_height must be integers")
	}
	raw, _ := json.Marshal(map[string]int{
		"tree_width":    clampInt(treeWidth, minTreeWidth, maxTreeWidth),
		"editor_height": clampInt(editorHeight, minEditorHeight, maxEditorHeight),
	})
	if err := h.Svc.SetPreference(c.Context(), user.ID, PrefEditorLayout, string(raw)); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func formRoles(c fiber.Ctx) []string {
	var roles []string
	for _, r := range AllRoles {
		if c.FormValue("role_"+r) == "on" {
			roles = append(roles, r)
		}
	}
	return roles
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
