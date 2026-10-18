// Package seed provisions roles, default policies, masking rules and the
// initial login account. Seeding is idempotent: the account is only created
// when the users table is empty (roles and policies are always upserted).
package seed

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/diannedelchev/securedb/internal/policies"
	"github.com/diannedelchev/securedb/internal/security"
	"github.com/diannedelchev/securedb/internal/users"
)

// Options controls what gets provisioned on first boot.
type Options struct {
	// Admin is the single login account created when no users exist.
	AdminEmail    string
	AdminPassword string
	AdminName     string
}

func Run(ctx context.Context, pool *pgxpool.Pool, opts Options) error {
	if err := seedRoles(ctx, pool); err != nil {
		return err
	}
	if err := seedPolicies(ctx, pool); err != nil {
		return err
	}
	if err := seedMaskingRules(ctx, pool); err != nil {
		return err
	}
	var userCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&userCount); err != nil {
		return err
	}
	if userCount > 0 {
		return nil
	}
	return seedAdmin(ctx, pool, opts)
}

// seedAdmin creates the single initial login account from configuration.
func seedAdmin(ctx context.Context, pool *pgxpool.Pool, opts Options) error {
	if opts.AdminEmail == "" {
		return fmt.Errorf("seed.admin.email is required to create the initial account")
	}
	password := opts.AdminPassword
	generated := false
	if password == "" {
		var err error
		password, err = security.RandomToken(12)
		if err != nil {
			return err
		}
		generated = true
	}
	if len(password) < 8 {
		return fmt.Errorf("seed.admin.password must be at least 8 characters")
	}
	name := opts.AdminName
	if name == "" {
		name = "Administrator"
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	var id string
	err = pool.QueryRow(ctx,
		`INSERT INTO users (email, display_name, password_hash) VALUES ($1,$2,$3) RETURNING id`,
		opts.AdminEmail, name, string(hash)).Scan(&id)
	if err != nil {
		return fmt.Errorf("create admin account: %w", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_roles (user_id, role_id) SELECT $1, id FROM roles WHERE name=$2`,
		id, users.RoleAdmin); err != nil {
		return err
	}
	if generated {
		// One-time credential — shown only in the server log on first boot.
		slog.Warn("no seed.admin.password configured — generated a one-time password",
			"email", opts.AdminEmail, "password", password)
	} else {
		slog.Info("initial admin account created", "email", opts.AdminEmail)
	}
	return nil
}

func seedRoles(ctx context.Context, pool *pgxpool.Pool) error {
	descriptions := map[string]string{
		users.RoleAdmin:     "Full administrative access",
		users.RoleDBA:       "Database administration and approval rights",
		users.RoleDeveloper: "Read/write access per policy",
		users.RoleQA:        "Read access to test environments",
		users.RoleAnalyst:   "Read-only analytical access",
		users.RoleAuditor:   "Read-only access to audit trails",
	}
	for _, role := range users.AllRoles {
		_, err := pool.Exec(ctx,
			`INSERT INTO roles (name, description) VALUES ($1,$2) ON CONFLICT (name) DO NOTHING`,
			role, descriptions[role])
		if err != nil {
			return fmt.Errorf("seed role %s: %w", role, err)
		}
	}
	return nil
}

func seedPolicies(ctx context.Context, pool *pgxpool.Pool) error {
	for _, env := range []string{"development", "staging", "production"} {
		p := policies.DefaultPolicy(env)
		_, err := pool.Exec(ctx,
			`INSERT INTO security_policies
			 (environment, max_rows, timeout_seconds, allow_export, require_approval_writes,
			  allow_write_queries, mask_sensitive_columns, allowed_schemas, blocked_keywords)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			 ON CONFLICT (environment) DO NOTHING`,
			p.Environment, p.MaxRows, p.TimeoutSeconds, p.AllowExport, p.RequireApprovalWrites,
			p.AllowWriteQueries, p.MaskSensitiveColumns, p.AllowedSchemas, p.BlockedKeywords)
		if err != nil {
			return fmt.Errorf("seed policy %s: %w", env, err)
		}
	}
	return nil
}

func seedMaskingRules(ctx context.Context, pool *pgxpool.Pool) error {
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM masking_rules`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	for _, r := range policies.DefaultMaskingRules() {
		_, err := pool.Exec(ctx,
			`INSERT INTO masking_rules (column_pattern, strategy, description, is_active) VALUES ($1,$2,$3,TRUE)`,
			r.ColumnPattern, r.Strategy, r.Description)
		if err != nil {
			return err
		}
	}
	return nil
}
