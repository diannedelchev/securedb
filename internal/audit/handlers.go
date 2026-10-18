package audit

import (
	"github.com/gofiber/fiber/v3"

	"github.com/diannedelchev/securedb/internal/web/view"
)

type Handlers struct {
	Logger *Logger
}

func (h *Handlers) List(c fiber.Ctx) error {
	f := Filter{
		Category: c.Query("cat"),
		Status:   c.Query("status"),
		Search:   c.Query("q"),
	}
	records, err := h.Logger.List(c.Context(), f)
	if err != nil {
		return err
	}
	data := fiber.Map{
		"Title":     "Audit Logs",
		"FullBleed": true,
		"Records":   records,
		"Cat":       f.Category,
		"Filter":    f,
	}
	if c.Get("HX-Request") == "true" {
		return view.Partial(c, "partials/audit_table", data)
	}
	return view.Render(c, "audit", data)
}

// Detail renders the right-hand inspector for one event.
func (h *Handlers) Detail(c fiber.Ctx) error {
	r, err := h.Logger.Get(c.Context(), c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "audit record not found")
	}
	return view.Partial(c, "partials/audit_detail", fiber.Map{"R": r})
}
