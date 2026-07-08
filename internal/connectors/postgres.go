package connectors

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

type PostgresConnector struct{}

func (p *PostgresConnector) open(conn ConnectionConfig) (*sql.DB, error) {
	sslmode := "disable"
	if conn.SSL {
		sslmode = "require"
	}
	dsn := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(conn.Username, conn.Password),
		Host:   fmt.Sprintf("%s:%d", conn.Host, conn.Port),
		Path:   "/" + conn.Database,
	}
	q := url.Values{}
	q.Set("sslmode", sslmode)
	q.Set("connect_timeout", "10")
	if conn.ReadOnly {
		// Defense in depth: the policy engine already blocks writes, but a
		// read-only connection also refuses them at the database level.
		q.Set("options", "-c default_transaction_read_only=on")
	}
	dsn.RawQuery = q.Encode()

	pgxCfg, err := pgx.ParseConfig(dsn.String())
	if err != nil {
		return nil, err
	}
	if conn.SSH.Enabled {
		// Route every database connection through the SSH bastion. One SSH
		// session per DB connection; it is torn down with the connection.
		sshCfg := conn.SSH
		pgxCfg.DialFunc = func(_ context.Context, _, addr string) (net.Conn, error) {
			return dialViaTunnel(sshCfg, addr)
		}
		// The database hostname must be resolved on the bastion side, not
		// locally — pass it through unresolved.
		pgxCfg.LookupFunc = func(_ context.Context, host string) ([]string, error) {
			return []string{host}, nil
		}
	}
	db := stdlib.OpenDB(*pgxCfg)
	db.SetMaxOpenConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)
	return db, nil
}

func (p *PostgresConnector) TestConnection(ctx context.Context, conn ConnectionConfig) error {
	db, err := p.open(conn)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return db.PingContext(ctx)
}

func (p *PostgresConnector) ExecuteQuery(ctx context.Context, conn ConnectionConfig, query QueryRequest) (QueryResult, error) {
	db, err := p.open(conn)
	if err != nil {
		return QueryResult{}, err
	}
	defer db.Close()
	return runQuery(ctx, db, query)
}

// ListDatabases returns every connectable database on the server that the
// connection's credentials can see.
func (p *PostgresConnector) ListDatabases(ctx context.Context, conn ConnectionConfig) ([]DatabaseInfo, error) {
	db, err := p.open(conn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx,
		`SELECT datname FROM pg_database
		 WHERE NOT datistemplate AND datallowconn
		 ORDER BY datname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DatabaseInfo
	for rows.Next() {
		var d DatabaseInfo
		if err := rows.Scan(&d.Name); err != nil {
			return nil, err
		}
		d.IsDefault = d.Name == conn.Database
		out = append(out, d)
	}
	return out, rows.Err()
}

func (p *PostgresConnector) ListSchemas(ctx context.Context, conn ConnectionConfig) ([]SchemaInfo, error) {
	db, err := p.open(conn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx,
		`SELECT schema_name FROM information_schema.schemata
		 WHERE schema_name NOT IN ('pg_catalog','information_schema','pg_toast')
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

func (p *PostgresConnector) ListTables(ctx context.Context, conn ConnectionConfig, schema string) ([]TableInfo, error) {
	db, err := p.open(conn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx,
		`SELECT table_schema, table_name,
		        CASE table_type WHEN 'VIEW' THEN 'view' ELSE 'table' END
		 FROM information_schema.tables
		 WHERE table_schema = $1
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

func (p *PostgresConnector) ListColumns(ctx context.Context, conn ConnectionConfig, schema, table string) ([]ColumnInfo, error) {
	db, err := p.open(conn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx,
		`SELECT c.column_name, c.data_type, c.is_nullable = 'YES', COALESCE(c.column_default,''),
		        EXISTS (
		          SELECT 1 FROM information_schema.table_constraints tc
		          JOIN information_schema.key_column_usage kcu
		            ON kcu.constraint_name = tc.constraint_name AND kcu.table_schema = tc.table_schema
		          WHERE tc.constraint_type='PRIMARY KEY' AND tc.table_schema=c.table_schema
		            AND tc.table_name=c.table_name AND kcu.column_name=c.column_name
		        )
		 FROM information_schema.columns c
		 WHERE c.table_schema=$1 AND c.table_name=$2
		 ORDER BY c.ordinal_position`, schema, table)
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

func (p *PostgresConnector) ListIndexes(ctx context.Context, conn ConnectionConfig, schema, table string) ([]IndexInfo, error) {
	db, err := p.open(conn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx,
		`SELECT indexname, indexdef FROM pg_indexes WHERE schemaname=$1 AND tablename=$2 ORDER BY indexname`,
		schema, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IndexInfo
	for rows.Next() {
		var i IndexInfo
		if err := rows.Scan(&i.Name, &i.Definition); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func (p *PostgresConnector) ListConstraints(ctx context.Context, conn ConnectionConfig, schema, table string) ([]ConstraintInfo, error) {
	db, err := p.open(conn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx,
		`SELECT con.conname, con.contype::text, pg_get_constraintdef(con.oid)
		 FROM pg_constraint con
		 JOIN pg_class rel ON rel.oid = con.conrelid
		 JOIN pg_namespace ns ON ns.oid = rel.relnamespace
		 WHERE ns.nspname=$1 AND rel.relname=$2
		 ORDER BY con.conname`, schema, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConstraintInfo
	for rows.Next() {
		var ci ConstraintInfo
		if err := rows.Scan(&ci.Name, &ci.Type, &ci.Def); err != nil {
			return nil, err
		}
		switch ci.Type {
		case "p":
			ci.Type = "PRIMARY KEY"
		case "f":
			ci.Type = "FOREIGN KEY"
		case "u":
			ci.Type = "UNIQUE"
		case "c":
			ci.Type = "CHECK"
		}
		out = append(out, ci)
	}
	return out, rows.Err()
}
