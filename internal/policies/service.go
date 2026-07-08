package policies

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

// ForEnvironment loads the policy for an environment, falling back to safe
// defaults if none is configured.
func (s *Service) ForEnvironment(ctx context.Context, env string) (Policy, error) {
	var p Policy
	err := s.pool.QueryRow(ctx,
		`SELECT id, environment, max_rows, timeout_seconds, allow_export, require_approval_writes,
		        allow_write_queries, mask_sensitive_columns, allowed_schemas, blocked_keywords
		 FROM security_policies WHERE environment=$1`, env).
		Scan(&p.ID, &p.Environment, &p.MaxRows, &p.TimeoutSeconds, &p.AllowExport, &p.RequireApprovalWrites,
			&p.AllowWriteQueries, &p.MaskSensitiveColumns, &p.AllowedSchemas, &p.BlockedKeywords)
	if err != nil {
		return DefaultPolicy(env), nil
	}
	return p, nil
}

// DefaultPolicy is the fail-safe used when no row exists for an environment.
func DefaultPolicy(env string) Policy {
	p := Policy{
		Environment:           env,
		MaxRows:               500,
		TimeoutSeconds:        30,
		AllowExport:           true,
		AllowWriteQueries:     true,
		MaskSensitiveColumns:  true,
		BlockedKeywords:       "DROP,TRUNCATE,ALTER,CREATE,GRANT,REVOKE",
	}
	if env == "production" {
		p.RequireApprovalWrites = true
		p.AllowExport = false
	}
	return p
}

func (s *Service) List(ctx context.Context) ([]Policy, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, environment, max_rows, timeout_seconds, allow_export, require_approval_writes,
		        allow_write_queries, mask_sensitive_columns, allowed_schemas, blocked_keywords
		 FROM security_policies
		 ORDER BY CASE environment WHEN 'development' THEN 1 WHEN 'staging' THEN 2 ELSE 3 END`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Policy
	for rows.Next() {
		var p Policy
		if err := rows.Scan(&p.ID, &p.Environment, &p.MaxRows, &p.TimeoutSeconds, &p.AllowExport,
			&p.RequireApprovalWrites, &p.AllowWriteQueries, &p.MaskSensitiveColumns,
			&p.AllowedSchemas, &p.BlockedKeywords); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Service) Update(ctx context.Context, p Policy) error {
	if p.MaxRows <= 0 || p.MaxRows > 100000 {
		return fmt.Errorf("max rows must be between 1 and 100000")
	}
	if p.TimeoutSeconds <= 0 || p.TimeoutSeconds > 600 {
		return fmt.Errorf("timeout must be between 1 and 600 seconds")
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE security_policies SET max_rows=$2, timeout_seconds=$3, allow_export=$4,
		 require_approval_writes=$5, allow_write_queries=$6, mask_sensitive_columns=$7,
		 allowed_schemas=$8, blocked_keywords=$9, updated_at=now()
		 WHERE environment=$1`,
		p.Environment, p.MaxRows, p.TimeoutSeconds, p.AllowExport, p.RequireApprovalWrites,
		p.AllowWriteQueries, p.MaskSensitiveColumns, p.AllowedSchemas, p.BlockedKeywords)
	return err
}

// MaskingRules returns the active masking rules.
func (s *Service) MaskingRules(ctx context.Context) ([]MaskingRule, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, column_pattern, strategy, description, is_active FROM masking_rules ORDER BY column_pattern`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MaskingRule
	for rows.Next() {
		var r MaskingRule
		if err := rows.Scan(&r.ID, &r.ColumnPattern, &r.Strategy, &r.Description, &r.IsActive); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
