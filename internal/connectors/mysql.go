package connectors

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"time"

	mysqldrv "github.com/go-sql-driver/mysql"
)

type MySQLConnector struct{}

func (m *MySQLConnector) open(conn ConnectionConfig) (*sql.DB, error) {
	cfg := mysqlConfig(conn)
	connector, err := mysqldrv.NewConnector(cfg)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)
	return db, nil
}

func mysqlConfig(conn ConnectionConfig) *mysqldrv.Config {
	cfg := mysqldrv.NewConfig()
	cfg.User = conn.Username
	cfg.Passwd = conn.Password
	cfg.Net = "tcp"
	if conn.SSH.Enabled {
		// Keep credentials scoped to this connector rather than registering a
		// process-global dialer under a credential-derived network name.
		sshCfg := conn.SSH
		cfg.DialFunc = func(_ context.Context, _, addr string) (net.Conn, error) {
			return dialViaTunnel(sshCfg, addr)
		}
	}
	cfg.Addr = fmt.Sprintf("%s:%d", conn.Host, conn.Port)
	cfg.DBName = conn.Database
	cfg.Timeout = 10 * time.Second
	cfg.ReadTimeout = 5 * time.Minute
	cfg.ParseTime = true
	if conn.SSL {
		cfg.TLSConfig = "true"
	}
	// Keep lexical interpretation aligned with the parser (no ANSI_QUOTES or
	// NO_BACKSLASH_ESCAPES), using MySQL's standard strict session mode.
	cfg.Params = map[string]string{"sql_mode": "'ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'"}
	return cfg
}

func (m *MySQLConnector) TestConnection(ctx context.Context, conn ConnectionConfig) error {
	db, err := m.open(conn)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return db.PingContext(ctx)
}

func (m *MySQLConnector) ExecuteQuery(ctx context.Context, conn ConnectionConfig, query QueryRequest) (QueryResult, error) {
	db, err := m.open(conn)
	if err != nil {
		return QueryResult{}, err
	}
	defer db.Close()
	if conn.ReadOnly && query.IsWrite {
		// Connector-level guard in addition to policy enforcement.
		return QueryResult{}, fmt.Errorf("connection is read-only")
	}
	return runQuery(ctx, db, query)
}

// ListDatabases: in MySQL, databases and schemas are the same namespace; a
// single connection can address all of them the user has privileges on.
func (m *MySQLConnector) ListDatabases(ctx context.Context, conn ConnectionConfig) ([]DatabaseInfo, error) {
	schemas, err := m.ListSchemas(ctx, conn)
	if err != nil {
		return nil, err
	}
	out := make([]DatabaseInfo, 0, len(schemas))
	for _, s := range schemas {
		out = append(out, DatabaseInfo{Name: s.Name, IsDefault: s.Name == conn.Database})
	}
	return out, nil
}

func (m *MySQLConnector) ListSchemas(ctx context.Context, conn ConnectionConfig) ([]SchemaInfo, error) {
	db, err := m.open(conn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx,
		`SELECT schema_name FROM information_schema.schemata
		 WHERE schema_name NOT IN ('mysql','information_schema','performance_schema','sys')
		 ORDER BY schema_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SchemaInfo
	for rows.Next() {
		var s SchemaInfo
		if err := rows.Scan(&s.Name); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (m *MySQLConnector) ListTables(ctx context.Context, conn ConnectionConfig, schema string) ([]TableInfo, error) {
	db, err := m.open(conn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx,
		`SELECT table_schema, table_name,
		        CASE table_type WHEN 'VIEW' THEN 'view' ELSE 'table' END
		 FROM information_schema.tables WHERE table_schema = ?
		 ORDER BY table_type, table_name`, schema)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TableInfo
	for rows.Next() {
		var t TableInfo
		if err := rows.Scan(&t.Schema, &t.Name, &t.Type); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (m *MySQLConnector) ListColumns(ctx context.Context, conn ConnectionConfig, schema, table string) ([]ColumnInfo, error) {
	db, err := m.open(conn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx,
		`SELECT column_name, data_type, is_nullable = 'YES', COALESCE(column_default,''), column_key = 'PRI'
		 FROM information_schema.columns
		 WHERE table_schema = ? AND table_name = ?
		 ORDER BY ordinal_position`, schema, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ColumnInfo
	for rows.Next() {
		var col ColumnInfo
		if err := rows.Scan(&col.Name, &col.DataType, &col.Nullable, &col.Default, &col.IsPrimary); err != nil {
			return nil, err
		}
		out = append(out, col)
	}
	return out, rows.Err()
}
