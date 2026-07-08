package settings

import (
	"strings"

	"github.com/gofiber/fiber/v3"

	"github.com/dian/securedb/internal/audit"
	"github.com/dian/securedb/internal/auth"
	"github.com/dian/securedb/internal/web/view"
)

type Handlers struct {
	Svc   *Service
	Audit *audit.Logger
}

func (h *Handlers) Page(c fiber.Ctx) error {
	list, err := h.Svc.List(c.Context())
	if err != nil {
		return err
	}
	return view.Render(c, "settings", fiber.Map{
		"Title":    "Settings",
		"Settings": list,
	})
}

func (h *Handlers) Update(c fiber.Ctx) error {
	user := auth.CurrentUser(c)
	key := c.Params("key")
	value := strings.TrimSpace(c.FormValue("value"))
	entry := audit.Entry{
		UserID: user.ID, Action: audit.ActionSettingUpdated, EntityType: "app_setting",
		EntityID: key, IP: c.IP(), UserAgent: c.Get("User-Agent"),
	}
	if err := h.Svc.Set(c.Context(), key, value); err != nil {
		entry.Status = "failure"
		entry.ErrorMessage = err.Error()
		h.Audit.Log(c.Context(), entry)
		return view.Toast(c, "error", err.Error())
	}
	h.Audit.Log(c.Context(), entry)
	return view.Toast(c, "success", "Setting "+key+" updated")
}
