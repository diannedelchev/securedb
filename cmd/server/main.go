package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"

	"github.com/dian/securedb/internal/approvals"
	"github.com/dian/securedb/internal/audit"
	"github.com/dian/securedb/internal/auth"
	"github.com/dian/securedb/internal/config"
	"github.com/dian/securedb/internal/connections"
	"github.com/dian/securedb/internal/dashboard"
	"github.com/dian/securedb/internal/db"
	"github.com/dian/securedb/internal/pam"
	"github.com/dian/securedb/internal/policies"
	"github.com/dian/securedb/internal/query"
	"github.com/dian/securedb/internal/security"
	"github.com/dian/securedb/internal/seed"
	"github.com/dian/securedb/internal/settings"
	"github.com/dian/securedb/internal/users"
	"github.com/dian/securedb/internal/web"
	"github.com/dian/securedb/migrations"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()
	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool, migrations.FS); err != nil {
		slog.Error("migrate", "error", err)
		os.Exit(1)
	}

	enc, err := security.NewEncryptor(cfg.EncryptionKey)
	if err != nil {
		slog.Error("encryptor", "error", err)
		os.Exit(1)
	}

	if err := seed.Run(ctx, pool, enc, seed.Options{
		AdminEmail:    cfg.SeedAdminEmail,
		AdminPassword: cfg.SeedAdminPassword,
		AdminName:     cfg.SeedAdminName,
		Demo:          cfg.SeedDemoData,
	}); err != nil {
		slog.Error("seed", "error", err)
		os.Exit(1)
	}

	// Runtime configuration lives in the app database (app_settings table);
	// config.yaml/env provide the first-boot defaults.
	settingsSvc := settings.NewService(pool)
	if err := settingsSvc.EnsureDefaults(ctx, map[string]string{
		settings.KeySessionTTL:     cfg.SessionTTL.String(),
		settings.KeySessionIdleTTL: cfg.SessionIdleTTL.String(),
	}); err != nil {
		slog.Error("settings", "error", err)
		os.Exit(1)
	}

	// Services.
	auditLogger := audit.NewLogger(pool)
	userSvc := users.NewService(pool)
	sessionStore := auth.NewStore(pool, func(ctx context.Context) (time.Duration, time.Duration) {
		return settingsSvc.Duration(ctx, settings.KeySessionTTL, cfg.SessionTTL),
			settingsSvc.Duration(ctx, settings.KeySessionIdleTTL, cfg.SessionIdleTTL)
	})
	connSvc := connections.NewService(pool, enc)
	policySvc := policies.NewService(pool)
	approvalSvc := approvals.NewService(pool)
	grantSvc := pam.NewService(pool)
	querySvc := query.NewService(pool, connSvc, policySvc, approvalSvc, grantSvc, auditLogger)

	// Periodic session cleanup.
	go func() {
		for {
			time.Sleep(15 * time.Minute)
			sessionStore.Cleanup(context.Background())
		}
	}()

	// Templates (embedded, SSR).
	engine := web.NewEngine()

	app := fiber.New(fiber.Config{
		Views:             engine,
		AppName:           "SecureDB Web Client",
		ErrorHandler:      errorHandler,
		ProxyHeader:       proxyHeader(cfg),
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      15 * time.Minute, // long-running queries stream back through here
	})
	app.Use(recover.New())
	app.Use(logger.New())

	web.Register(app, web.Deps{
		Auth:        &auth.Handlers{Store: sessionStore, Users: userSvc, Audit: auditLogger, CookieSecure: cfg.CookieSecure},
		SessionSt:   sessionStore,
		Users:       userSvc,
		UserH:       &users.Handlers{Svc: userSvc, Audit: auditLogger},
		Connections: &connections.Handlers{Svc: connSvc, Audit: auditLogger},
		Query:       &query.Handlers{Svc: querySvc, Conns: connSvc, Policies: policySvc, Audit: auditLogger},
		Approvals:   &approvals.Handlers{Svc: approvalSvc, Grants: grantSvc, Conns: connSvc, Audit: auditLogger},
		Grants:      &pam.Handlers{Svc: grantSvc, Audit: auditLogger},
		Audit:       &audit.Handlers{Logger: auditLogger},
		Policies:    &policies.Handlers{Svc: policySvc, Audit: auditLogger, Pool: pool},
		Dashboard:   &dashboard.Handlers{Pool: pool, Sessions: sessionStore},
		Settings:    &settings.Handlers{Svc: settingsSvc, Audit: auditLogger},
	})

	slog.Info("SecureDB listening", "addr", cfg.Addr)
	if err := app.Listen(cfg.Addr); err != nil {
		slog.Error("server", "error", err)
		os.Exit(1)
	}
}

func errorHandler(c fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	msg := "Something went wrong."
	if fe, ok := err.(*fiber.Error); ok {
		code = fe.Code
		msg = fe.Message
	}
	slog.Error("request failed", "path", c.Path(), "code", code, "error", err)
	if c.Get("HX-Request") == "true" {
		return c.Status(code).Render("partials/toast", fiber.Map{"Kind": "error", "Message": msg})
	}
	return c.Status(code).Render("error", fiber.Map{
		"Title": "Error", "Message": msg, "User": c.Locals("current_user"), "Path": c.Path(),
	}, "layouts/main")
}

func proxyHeader(cfg *config.Config) string {
	if cfg.TrustProxyIP {
		return "X-Forwarded-For"
	}
	return ""
}
