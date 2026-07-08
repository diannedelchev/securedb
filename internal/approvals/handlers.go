package approvals

import (
	"strings"

	"github.com/gofiber/fiber/v3"

	"github.com/dian/securedb/internal/audit"
	"github.com/dian/securedb/internal/auth"
	"github.com/dian/securedb/internal/connections"
	"github.com/dian/securedb/internal/pam"
	"github.com/dian/securedb/internal/policies"
	"github.com/dian/securedb/internal/users"
	"github.com/dian/securedb/internal/web/view"
)

type Handlers struct {
	Svc    *Service
	Grants *pam.Service
	Conns  *connections.Service
	Audit  *audit.Logger
}

// RiskCheck is one line of the automated risk analysis panel.
type RiskCheck struct {
	OK   bool
	Text string
}

func (h *Handlers) List(c fiber.Ctx) error {
	user := auth.CurrentUser(c)
	status := c.Query("status")
	filterUser := ""
	if !user.IsApprover() && !user.HasRole(users.RoleAuditor) {
		filterUser = user.ID
	}
	reqs, err := h.Svc.List(c.Context(), status, filterUser)
	if err != nil {
		return err
	}
	grantStatus := status
	if grantStatus == "approved" {
		grantStatus = "active" // grants use "active" where requests use "approved"
	}
	grants, err := h.Grants.List(c.Context(), grantStatus, filterUser)
	if err != nil {
		return err
	}
	pending, _ := h.Svc.CountPending(c.Context())
	pendingGrants, _ := h.Grants.CountPending(c.Context())
	// Connections for the "request access window" modal.
	conns, _ := h.Conns.List(c.Context())
	var activeConns []*connections.Connection
	for _, cn := range conns {
		if cn.IsActive {
			activeConns = append(activeConns, cn)
		}
	}
	return view.Render(c, "approvals", fiber.Map{
		"Title":        "Approval Requests",
		"FullBleed":    true,
		"Requests":     reqs,
		"Grants":       grants,
		"Connections":  activeConns,
		"Status":       status,
		"PendingCount": pending + pendingGrants,
		"IsApprover":   user.IsApprover(),
	})
}

// Detail renders the right-hand pane for one request.
func (h *Handlers) Detail(c fiber.Ctx) error {
	user := auth.CurrentUser(c)
	req, err := h.Svc.Get(c.Context(), c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "request not found")
	}
	if !user.IsApprover() && !user.HasRole(users.RoleAuditor) && req.UserID != user.ID {
		return fiber.NewError(fiber.StatusForbidden, "not your request")
	}
	return view.Partial(c, "partials/approval_detail", h.detailData(req, user))
}

func (h *Handlers) detailData(req *Request, user *users.User) fiber.Map {
	a := policies.Analyze(req.QueryText)
	checks := []RiskCheck{}
	if a.HasWhere {
		checks = append(checks, RiskCheck{OK: true, Text: "Statement has a bounding WHERE clause"})
	} else if a.Kind == policies.KindWrite {
		checks = append(checks, RiskCheck{OK: false, Text: "No WHERE clause — affects all rows in the target table"})
	}
	if a.MultiStatement {
		checks = append(checks, RiskCheck{OK: false, Text: "Multiple statements in one request"})
	} else {
		checks = append(checks, RiskCheck{OK: true, Text: "Single statement · " + strings.ToUpper(string(a.Kind))})
	}
	if a.Kind == policies.KindDDL {
		checks = append(checks, RiskCheck{OK: false, Text: "DDL — schema change, review rollback plan"})
	}
	if req.Environment == "production" {
		checks = append(checks, RiskCheck{OK: false, Text: "Targets a production environment — audited and one-time"})
	} else {
		checks = append(checks, RiskCheck{OK: true, Text: "Non-production target"})
	}
	return fiber.Map{
		"R":          req,
		"Checks":     checks,
		"IsApprover": user.IsApprover(),
		"IsOwner":    req.UserID == user.ID,
	}
}

func (h *Handlers) Decide(c fiber.Ctx) error {
	user := auth.CurrentUser(c)
	if !user.IsApprover() {
		return fiber.NewError(fiber.StatusForbidden, "only admins and DBAs can decide approvals")
	}
	id := c.Params("id")
	decision := c.FormValue("decision")
	comments := strings.TrimSpace(c.FormValue("comments"))

	req, err := h.Svc.Decide(c.Context(), id, user.ID, decision, comments)
	entry := audit.Entry{
		UserID: user.ID, EntityType: "approval_request", EntityID: id,
		IP: c.IP(), UserAgent: c.Get("User-Agent"),
	}
	if err != nil {
		entry.Action = audit.ActionApprovalApproved
		entry.Status = "failure"
		entry.ErrorMessage = err.Error()
		h.Audit.Log(c.Context(), entry)
		return view.Toast(c, "error", err.Error())
	}
	if decision == "approved" {
		entry.Action = audit.ActionApprovalApproved
	} else {
		entry.Action = audit.ActionApprovalRejected
	}
	entry.ConnectionID = req.ConnectionID
	entry.QueryText = req.QueryText
	h.Audit.Log(c.Context(), entry)
	// Refresh the whole page so the card list and nav badge update too.
	c.Set("HX-Refresh", "true")
	return c.SendStatus(fiber.StatusOK)
}
