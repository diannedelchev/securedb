package connections

import (
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"

	"github.com/dian/securedb/internal/audit"
	"github.com/dian/securedb/internal/auth"
	"github.com/dian/securedb/internal/users"
	"github.com/dian/securedb/internal/web/view"
)

type Handlers struct {
	Svc   *Service
	Audit *audit.Logger
}

// canManage: admins and DBAs manage all connections, owners manage their own.
func canManage(u *users.User, c *Connection) bool {
	return u.IsPrivileged() || (c != nil && c.OwnerID == u.ID)
}

func (h *Handlers) List(c fiber.Ctx) error {
	conns, err := h.Svc.List(c.Context())
	if err != nil {
		return err
	}
	search := strings.ToLower(strings.TrimSpace(c.Query("q")))
	env := c.Query("env")
	filtered := conns[:0]
	for _, cn := range conns {
		if env != "" && cn.Environment != env {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(cn.Name+" "+cn.Host+" "+cn.Tags+" "+cn.DatabaseName), search) {
			continue
		}
		filtered = append(filtered, cn)
	}
	data := fiber.Map{
		"Title":       "Connections",
		"Connections": filtered,
		"Search":      c.Query("q"),
		"Env":         env,
	}
	if c.Get("HX-Request") == "true" {
		return view.Partial(c, "partials/connections_table", data)
	}
	return view.Render(c, "connections", data)
}

func (h *Handlers) NewForm(c fiber.Ctx) error {
	return view.Render(c, "connection_form", fiber.Map{
		"Title": "New connection",
		"Conn":  &Connection{Port: 5432, Environment: "development", DBType: "postgres", IsActive: true, SSHPort: 22, SSHAuth: "password"},
		"IsNew": true,
	})
}

func (h *Handlers) EditForm(c fiber.Ctx) error {
	conn, err := h.Svc.Get(c.Context(), c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "connection not found")
	}
	if !canManage(auth.CurrentUser(c), conn) {
		return fiber.NewError(fiber.StatusForbidden, "you cannot edit this connection")
	}
	return view.Render(c, "connection_form", fiber.Map{
		"Title": "Edit connection",
		"Conn":  conn,
		"IsNew": false,
	})
}

func parseInput(c fiber.Ctx) Input {
	port, _ := strconv.Atoi(c.FormValue("port"))
	sshPort, _ := strconv.Atoi(c.FormValue("ssh_port"))
	return Input{
		SSHEnabled:  c.FormValue("ssh_enabled") == "on",
		SSHHost:     strings.TrimSpace(c.FormValue("ssh_host")),
		SSHPort:     sshPort,
		SSHUser:     strings.TrimSpace(c.FormValue("ssh_user")),
		SSHAuth:     c.FormValue("ssh_auth"),
		SSHPassword: c.FormValue("ssh_password"),
		SSHKey:      c.FormValue("ssh_key"),
		SSHHostKey:  strings.TrimSpace(c.FormValue("ssh_host_key")),

		Name:             strings.TrimSpace(c.FormValue("name")),
		Description:      strings.TrimSpace(c.FormValue("description")),
		Environment:      c.FormValue("environment"),
		DBType:           c.FormValue("db_type"),
		Host:             strings.TrimSpace(c.FormValue("host")),
		Port:             port,
		DatabaseName:     strings.TrimSpace(c.FormValue("database_name")),
		Username:         strings.TrimSpace(c.FormValue("username")),
		Password:         c.FormValue("password"),
		SecretsReference: strings.TrimSpace(c.FormValue("secrets_reference")),
		SSLEnabled:       c.FormValue("ssl_enabled") == "on",
		ReadOnly:         c.FormValue("read_only") == "on",
		Tags:             strings.TrimSpace(c.FormValue("tags")),
		IsActive:         c.FormValue("is_active") == "on",
	}
}

func (h *Handlers) Create(c fiber.Ctx) error {
	user := auth.CurrentUser(c)
	in := parseInput(c)
	conn, err := h.Svc.Create(c.Context(), user.ID, in)
	if err != nil {
		return view.Render(c, "connection_form", fiber.Map{
			"Title": "New connection", "Conn": inputAsConn(in), "IsNew": true, "Error": err.Error(),
		})
	}
	h.Audit.Log(c.Context(), audit.Entry{
		UserID: user.ID, Action: audit.ActionConnectionCreated, EntityType: "connection",
		EntityID: conn.ID, ConnectionID: conn.ID, IP: c.IP(), UserAgent: c.Get("User-Agent"),
	})
	return c.Redirect().To("/connections")
}

func (h *Handlers) Update(c fiber.Ctx) error {
	user := auth.CurrentUser(c)
	existing, err := h.Svc.Get(c.Context(), c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "connection not found")
	}
	if !canManage(user, existing) {
		return fiber.NewError(fiber.StatusForbidden, "you cannot edit this connection")
	}
	in := parseInput(c)
	conn, err := h.Svc.Update(c.Context(), existing.ID, in)
	if err != nil {
		return view.Render(c, "connection_form", fiber.Map{
			"Title": "Edit connection", "Conn": existing, "IsNew": false, "Error": err.Error(),
		})
	}
	h.Audit.Log(c.Context(), audit.Entry{
		UserID: user.ID, Action: audit.ActionConnectionUpdated, EntityType: "connection",
		EntityID: conn.ID, ConnectionID: conn.ID, IP: c.IP(), UserAgent: c.Get("User-Agent"),
	})
	return c.Redirect().To("/connections")
}

func (h *Handlers) Delete(c fiber.Ctx) error {
	user := auth.CurrentUser(c)
	conn, err := h.Svc.Get(c.Context(), c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "connection not found")
	}
	if !canManage(user, conn) {
		return fiber.NewError(fiber.StatusForbidden, "you cannot delete this connection")
	}
	if err := h.Svc.Delete(c.Context(), conn.ID); err != nil {
		return err
	}
	h.Audit.Log(c.Context(), audit.Entry{
		UserID: user.ID, Action: audit.ActionConnectionDeleted, EntityType: "connection",
		EntityID: conn.ID, IP: c.IP(), UserAgent: c.Get("User-Agent"),
	})
	c.Set("HX-Redirect", "/connections")
	return c.SendStatus(fiber.StatusOK)
}

// Test pings the target database and returns a toast fragment.
func (h *Handlers) Test(c fiber.Ctx) error {
	user := auth.CurrentUser(c)
	conn, err := h.Svc.Get(c.Context(), c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "connection not found")
	}
	entry := audit.Entry{
		UserID: user.ID, Action: audit.ActionConnectionTested, EntityType: "connection",
		EntityID: conn.ID, ConnectionID: conn.ID, IP: c.IP(), UserAgent: c.Get("User-Agent"),
	}
	if err := h.Svc.Test(c.Context(), conn); err != nil {
		entry.Status = "failure"
		entry.ErrorMessage = err.Error()
		h.Audit.Log(c.Context(), entry)
		return view.Toast(c, "error", "Connection failed: "+err.Error())
	}
	h.Audit.Log(c.Context(), entry)
	return view.Toast(c, "success", "Connection to "+conn.Name+" succeeded")
}

func inputAsConn(in Input) *Connection {
	return &Connection{
		Name: in.Name, Description: in.Description, Environment: in.Environment,
		DBType: in.DBType, Host: in.Host, Port: in.Port, DatabaseName: in.DatabaseName,
		Username: in.Username, SecretsReference: in.SecretsReference,
		SSLEnabled: in.SSLEnabled, ReadOnly: in.ReadOnly, Tags: in.Tags, IsActive: in.IsActive,
		SSHEnabled: in.SSHEnabled, SSHHost: in.SSHHost, SSHPort: in.SSHPort,
		SSHUser: in.SSHUser, SSHAuth: in.SSHAuth, SSHHostKey: in.SSHHostKey,
	}
}
