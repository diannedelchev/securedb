package connectors

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	mysqldrv "github.com/go-sql-driver/mysql"
)

type MySQLConnector struct{}

// sshNetName registers (idempotently) a custom dial network for a given SSH
// tunnel config and returns its name for use in the DSN.
func sshNetName(sshCfg SSHConfig) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%s|%s|%s|%s",
		sshCfg.Host, sshCfg.Port, sshCfg.User, sshCfg.Password, sshCfg.PrivateKey, sshCfg.HostKeyFingerprint)))
	name := "ssh" + hex.EncodeToString(sum[:8])
	mysqldrv.RegisterDialContext(name, func(_ context.Context, addr string) (net.Conn, error) {
		return dialViaTunnel(sshCfg, addr)
	})
	return name
}

func (m *MySQLConnector) open(conn ConnectionConfig) (*sql.DB, error) {
	cfg := mysqldrv.NewConfig()
	cfg.User = conn.Username
	cfg.Passwd = conn.Password
	cfg.Net = "tcp"
	if conn.SSH.Enabled {
		cfg.Net = sshNetName(conn.SSH)
	}
	cfg.Addr = fmt.Sprintf("%s:%d", conn.Host, conn.Port)
	cfg.DBName = conn.Database
	cfg.Timeout = 10 * time.Second
	cfg.ReadTimeout = 5 * time.Minute
	cfg.ParseTime = true
	if conn.SSL {
		cfg.TLSConfig = "preferred"
	}
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)
	return db, nil
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
