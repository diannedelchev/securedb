package users

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// Role names. Kept as constants so policy checks stay typo-safe.
const (
	RoleAdmin     = "admin"
	RoleDBA       = "dba"
	RoleDeveloper = "developer"
	RoleQA        = "qa"
	RoleAnalyst   = "analyst"
	RoleAuditor   = "auditor"
)

var AllRoles = []string{RoleAdmin, RoleDBA, RoleDeveloper, RoleQA, RoleAnalyst, RoleAuditor}

type User struct {
	ID          string
	Email       string
	DisplayName string
	IsActive    bool
	Roles       []string
	LastLoginAt *time.Time
	CreatedAt   time.Time
}

func (u *User) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// LastLoginFmt renders the nullable last-login time for templates.
func (u *User) LastLoginFmt() string {
	if u.LastLoginAt == nil {
		return "never"
	}
	return u.LastLoginAt.Local().Format("Jan 02 15:04")
}

// PermSummary is a short human description of what the user's roles allow.
func (u *User) PermSummary() string {
	switch {
	case u.HasRole(RoleAdmin):
		return "full access · approver"
	case u.HasRole(RoleDBA):
		return "all databases · approver"
	case u.HasRole(RoleDeveloper):
		return "write per policy · prod on approval"
	case u.HasRole(RoleQA):
		return "read/write non-prod"
	case u.HasRole(RoleAnalyst):
		return "read-only queries"
	case u.HasRole(RoleAuditor):
		return "audit read-only"
	}
	return "no roles assigned"
}

// PrimaryRole picks the highest-privilege role for the badge.
func (u *User) PrimaryRole() string {
	for _, r := range AllRoles {
		if u.HasRole(r) {
			return r
		}
	}
	return ""
}

func (u *User) IsAdmin() bool      { return u.HasRole(RoleAdmin) }
func (u *User) IsApprover() bool   { return u.HasRole(RoleAdmin) || u.HasRole(RoleDBA) }
func (u *User) IsPrivileged() bool { return u.HasRole(RoleAdmin) || u.HasRole(RoleDBA) }

// CanQuery and CanWrite define execution capabilities, independently of
// approval windows. Multiple roles grant the union of their capabilities.
func (u *User) CanQuery() bool {
	return u != nil && u.IsActive && (u.IsPrivileged() || u.HasRole(RoleDeveloper) || u.HasRole(RoleQA) || u.HasRole(RoleAnalyst))
}
func (u *User) CanWrite(environment string) bool {
	return u.CanQuery() && (u.IsPrivileged() || u.HasRole(RoleDeveloper) || (u.HasRole(RoleQA) && environment != "production"))
}

func (u *User) RoleLabel() string { return strings.Join(u.Roles, ", ") }

type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

func (s *Service) Authenticate(ctx context.Context, email, password string) (*User, error) {
	var (
		u    User
		hash string
	)
	err := s.pool.QueryRow(ctx,
		`SELECT id, email, display_name, password_hash, is_active FROM users WHERE lower(email)=lower($1)`,
		email).Scan(&u.ID, &u.Email, &u.DisplayName, &hash, &u.IsActive)
	if err != nil {
		// Run a dummy compare to keep timing consistent for unknown users.
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$7EqJtq98hPqEX7fNZaFWoOhi5B1qGDXlON/nS0V8u1sT1a2b3c4d6"), []byte(password))
		return nil, fmt.Errorf("invalid credentials")
	}
	if !u.IsActive {
		return nil, fmt.Errorf("account disabled")
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return nil, fmt.Errorf("invalid credentials")
	}
	u.Roles, err = s.rolesFor(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	_, _ = s.pool.Exec(ctx, `UPDATE users SET last_login_at=now(), updated_at=now() WHERE id=$1`, u.ID)
	return &u, nil
}

func (s *Service) GetByID(ctx context.Context, id string) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, email, display_name, is_active, last_login_at, created_at FROM users WHERE id=$1`,
		id).Scan(&u.ID, &u.Email, &u.DisplayName, &u.IsActive, &u.LastLoginAt, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	u.Roles, err = s.rolesFor(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Service) rolesFor(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=$1 ORDER BY r.name`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		roles = append(roles, name)
	}
	return roles, rows.Err()
}

func (s *Service) List(ctx context.Context) ([]*User, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT u.id, u.email, u.display_name, u.is_active, u.last_login_at, u.created_at,
		        COALESCE(string_agg(r.name, ',' ORDER BY r.name), '')
		 FROM users u
		 LEFT JOIN user_roles ur ON ur.user_id = u.id
		 LEFT JOIN roles r ON r.id = ur.role_id
		 GROUP BY u.id ORDER BY u.created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		var u User
		var roleCSV string
		if err := rows.Scan(&u.ID, &u.Email, &u.DisplayName, &u.IsActive, &u.LastLoginAt, &u.CreatedAt, &roleCSV); err != nil {
			return nil, err
		}
		if roleCSV != "" {
			u.Roles = strings.Split(roleCSV, ",")
		}
		out = append(out, &u)
	}
	return out, rows.Err()
}

func (s *Service) Create(ctx context.Context, email, displayName, password string, roles []string) (*User, error) {
	if email == "" || displayName == "" || len(password) < 8 {
		return nil, fmt.Errorf("email, name and a password of at least 8 characters are required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var id string
	err = tx.QueryRow(ctx,
		`INSERT INTO users (email, display_name, password_hash) VALUES ($1,$2,$3) RETURNING id`,
		strings.ToLower(strings.TrimSpace(email)), strings.TrimSpace(displayName), string(hash)).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	if err := assignRolesTx(ctx, tx, id, roles); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GetByID(ctx, id)
}

// SetRoles replaces the role set of a user.
func (s *Service) SetRoles(ctx context.Context, userID string, roles []string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM user_roles WHERE user_id=$1`, userID); err != nil {
		return err
	}
	if err := assignRolesTx(ctx, tx, userID, roles); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) SetActive(ctx context.Context, userID string, active bool) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET is_active=$2, updated_at=now() WHERE id=$1`, userID, active)
	return err
}

// Preference keys stored in user_preferences.
const PrefEditorLayout = "editor_layout"

// GetPreference returns the stored value for a per-user preference key, or ""
// when the user has never set it.
func (s *Service) GetPreference(ctx context.Context, userID, key string) (string, error) {
	var v string
	err := s.pool.QueryRow(ctx,
		`SELECT value FROM user_preferences WHERE user_id=$1 AND key=$2`, userID, key).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetPreference upserts a per-user preference value.
func (s *Service) SetPreference(ctx context.Context, userID, key, value string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO user_preferences (user_id, key, value) VALUES ($1,$2,$3)
		 ON CONFLICT (user_id, key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`,
		userID, key, value)
	return err
}

func assignRolesTx(ctx context.Context, tx pgx.Tx, userID string, roles []string) error {
	for _, role := range roles {
		valid := false
		for _, r := range AllRoles {
			if r == role {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("unknown role %q", role)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO user_roles (user_id, role_id) SELECT $1, id FROM roles WHERE name=$2 ON CONFLICT DO NOTHING`,
			userID, role); err != nil {
			return err
		}
	}
	return nil
}
