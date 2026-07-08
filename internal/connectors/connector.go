package connectors

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"time"
)

// ConnectionConfig carries everything a connector needs to reach a target
// database. The password is decrypted just-in-time and never leaves the server.
type ConnectionConfig struct {
	Type     string // postgres | mysql | mssql
	Host     string
	Port     int
	Database string
	Username string
	Password string
	SSL      bool
	ReadOnly bool
	// SSH optionally routes the database connection through a bastion host.
	SSH SSHConfig
}

type QueryRequest struct {
	SQL     string
	MaxRows int
	Timeout time.Duration
	// IsWrite selects Exec vs Query semantics; decided by the policy engine's
	// statement classification.
	IsWrite bool
}

type QueryResult struct {
	Columns      []string
	Rows         [][]string
	RowsAffected int64
	Truncated    bool
	Duration     time.Duration
}

type DatabaseInfo struct {
	Name      string
	IsDefault bool // the database stored on the connection
}

type SchemaInfo struct {
	Name string
}

type TableInfo struct {
	Schema string
	Name   string
	Type   string // table | view
}

type ColumnInfo struct {
	Name       string
	DataType   string
	Nullable   bool
	Default    string
	IsPrimary  bool
}

type IndexInfo struct {
	Name       string
	Definition string
}

type ConstraintInfo struct {
	Name string
	Type string
	Def  string
}

// DBConnector is the interface every database driver adapter implements.
// The ConnectionConfig.Database field selects which database on the server a
// call targets — one connection record can address every database its
// credentials can reach.
type DBConnector interface {
	TestConnection(ctx context.Context, conn ConnectionConfig) error
	ExecuteQuery(ctx context.Context, conn ConnectionConfig, query QueryRequest) (QueryResult, error)
	ListDatabases(ctx context.Context, conn ConnectionConfig) ([]DatabaseInfo, error)
	ListSchemas(ctx context.Context, conn ConnectionConfig) ([]SchemaInfo, error)
	ListTables(ctx context.Context, conn ConnectionConfig, schema string) ([]TableInfo, error)
	ListColumns(ctx context.Context, conn ConnectionConfig, schema string, table string) ([]ColumnInfo, error)
}

// TableDetailer is an optional extension for connectors that can list indexes
// and constraints (PostgreSQL for now).
type TableDetailer interface {
	ListIndexes(ctx context.Context, conn ConnectionConfig, schema, table string) ([]IndexInfo, error)
	ListConstraints(ctx context.Context, conn ConnectionConfig, schema, table string) ([]ConstraintInfo, error)
}

// ForType returns the connector for a database type.
func ForType(dbType string) (DBConnector, error) {
	switch dbType {
	case "postgres":
		return &PostgresConnector{}, nil
	case "mysql":
		return &MySQLConnector{}, nil
	case "mssql":
		return &MSSQLConnector{}, nil
	default:
		return nil, fmt.Errorf("unsupported database type %q", dbType)
	}
}

// runQuery executes a request against an opened *sql.DB with timeout and row
// cap applied. Shared by the postgres and mysql connectors.
func runQuery(ctx context.Context, db *sql.DB, req QueryRequest) (QueryResult, error) {
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}
	start := time.Now()

	if req.IsWrite {
		res, err := db.ExecContext(ctx, req.SQL)
		if err != nil {
			return QueryResult{Duration: time.Since(start)}, err
		}
		affected, _ := res.RowsAffected()
		return QueryResult{RowsAffected: affected, Duration: time.Since(start)}, nil
	}

	rows, err := db.QueryContext(ctx, req.SQL)
	if err != nil {
		return QueryResult{Duration: time.Since(start)}, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return QueryResult{Duration: time.Since(start)}, err
	}
	result := QueryResult{Columns: cols}
	maxRows := req.MaxRows
	if maxRows <= 0 {
		maxRows = 500
	}
	raw := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range raw {
		ptrs[i] = &raw[i]
	}
	for rows.Next() {
		if len(result.Rows) >= maxRows {
			result.Truncated = true
			break
		}
		if err := rows.Scan(ptrs...); err != nil {
			return result, err
		}
		row := make([]string, len(cols))
		for i, v := range raw {
			row[i] = stringify(v)
		}
		result.Rows = append(result.Rows, row)
	}
	result.Duration = time.Since(start)
	if err := rows.Err(); err != nil {
		return result, err
	}
	return result, nil
}

var dbNameRe = regexp.MustCompile(`^[A-Za-z0-9_$-]{1,63}$`)

// ValidDatabaseName guards database-switch requests: names travel into DSNs,
// so only plain identifiers are accepted.
func ValidDatabaseName(name string) bool {
	return dbNameRe.MatchString(name)
}

func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return "NULL"
	case []byte:
		return string(t)
	case time.Time:
		return t.Format(time.RFC3339)
	default:
		return fmt.Sprintf("%v", t)
	}
}
