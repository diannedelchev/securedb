package query

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/diannedelchev/securedb/internal/audit"
	"github.com/google/uuid"
)

// beginExecution commits both records before the target database is contacted.
// The two databases cannot share a transaction: a running record deliberately
// means an unknown outcome, not a failed query that is safe to execute again.
func (s *Service) beginExecution(ctx context.Context, req ExecRequest, connID, database string) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	id := uuid.NewString()
	_, err = tx.Exec(ctx, `INSERT INTO query_history
		(id,user_id,connection_id,database_name,query_text,status,error_message)
		VALUES ($1,$2,$3,$4,$5,'running','Outcome not yet confirmed; review the target before retrying writes.')`,
		id, req.User.ID, connID, database, req.SQL)
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_logs
		(user_id,action,entity_type,entity_id,connection_id,ip_address,user_agent,query_text,status)
		VALUES ($1,$2,'query',$3,$4,$5,$6,$7,'running')`,
		req.User.ID, audit.ActionQueryExecuted, id, connID, req.IP, req.UserAgent, req.SQL)
	if err != nil {
		return "", err
	}
	return id, tx.Commit(ctx)
}

// finishExecution is idempotent and retries only control-plane writes, never SQL
// on the target. Detached, bounded contexts allow cancellation to be recorded.
func (s *Service) finishExecution(id, status, message string, rows, durationMS int) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err = s.saveExecutionOutcome(ctx, id, status, message, rows, durationMS)
		cancel()
		if err == nil {
			return nil
		}
	}
	slog.Error("execution outcome requires reconciliation", "history_id", id, "status", status, "error", err)
	return err
}

func (s *Service) saveExecutionOutcome(ctx context.Context, id, status, message string, rows, durationMS int) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `UPDATE query_history SET status=$2,error_message=$3,row_count=$4,duration_ms=$5,updated_at=now() WHERE id=$1`, id, status, message, rows, durationMS)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("execution history is missing")
	}
	auditStatus := "success"
	if status != "success" {
		auditStatus = "failure"
	}
	tag, err = tx.Exec(ctx, `UPDATE audit_logs SET status=$2,error_message=$3 WHERE entity_type='query' AND entity_id=$1 AND action=$4`, id, auditStatus, message, audit.ActionQueryExecuted)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("execution audit is missing")
	}
	return tx.Commit(ctx)
}
