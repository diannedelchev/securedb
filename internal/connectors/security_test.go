package connectors

import (
	"context"
	"database/sql"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	mysqldrv "github.com/go-sql-driver/mysql"
)

func TestMySQLTunnelIsScopedToConnector(t *testing.T) {
	conn := ConnectionConfig{Host: "db.example.com", Port: 3306}
	if mysqlConfig(conn).DialFunc != nil {
		t.Fatal("direct connections should use the native TCP dialer")
	}
	conn.SSH = SSHConfig{Enabled: true}
	first := mysqlConfig(conn)
	conn.SSH = SSHConfig{Enabled: true, Host: "bastion.example.com", User: "test"}
	second := mysqlConfig(conn)
	// These deliberately invalid configurations fail before any network call.
	// Each config must retain its own SSH options, even after another is built.
	for _, tc := range []struct {
		cfg  *mysqldrv.Config
		want string
	}{
		{first, "ssh tunnel requires a host and user"},
		{second, "ssh tunnel requires a password or a private key"},
	} {
		if tc.cfg.Net != "tcp" || tc.cfg.DialFunc == nil {
			t.Fatal("SSH should use a connector-local dialer")
		}
		_, err := tc.cfg.DialFunc(context.Background(), "tcp", "db.example.com:3306")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("dialer lost its SSH config: %v", err)
		}
	}
	// Exercise the production open path: serializing the config as a DSN
	// would silently discard DialFunc and attempt a direct TCP connection.
	conn.SSH = SSHConfig{Enabled: true}
	db, err := (&MySQLConnector{}).open(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = db.PingContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ssh tunnel requires a host and user") {
		t.Fatalf("open did not preserve the SSH dialer: %v", err)
	}
}

func TestTLSRequiresVerifiedServer(t *testing.T) {
	c := ConnectionConfig{Host: "db.example.com", Port: 5432, Database: "test", Username: "test", Password: "test", SSL: true}
	pg, err := postgresConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if pg.TLSConfig == nil || pg.TLSConfig.InsecureSkipVerify || pg.TLSConfig.ServerName != "db.example.com" {
		t.Fatal("PostgreSQL TLS does not verify server identity")
	}
	for _, fallback := range pg.Fallbacks {
		if fallback.TLSConfig == nil || fallback.TLSConfig.InsecureSkipVerify {
			t.Fatal("insecure PostgreSQL fallback")
		}
	}
	if pg.RuntimeParams["standard_conforming_strings"] != "on" {
		t.Fatal("PostgreSQL lexical mode not pinned")
	}
	c.Port = 3306
	my, err := mysqldrv.ParseDSN(mysqlConfig(c).FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	if my.TLS == nil || my.TLS.InsecureSkipVerify || my.TLS.ServerName != "db.example.com" || my.AllowFallbackToPlaintext {
		t.Fatal("MySQL TLS permits an unverified or plaintext connection")
	}
	if my.Params["sql_mode"] == "" {
		t.Fatal("MySQL lexical mode not pinned")
	}
}

func TestMySQLDatabaseReadOnlyEnforcement(t *testing.T) {
	dsn := os.Getenv("SECUREDB_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("set SECUREDB_TEST_MYSQL_DSN to run MySQL integration tests")
	}
	driverCfg, err := mysqldrv.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(driverCfg.Addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	cfg := ConnectionConfig{Type: "mysql", Host: host, Port: port, Database: driverCfg.DBName, Username: driverCfg.User, Password: driverCfg.Passwd}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	table := "security_test_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if _, err = db.ExecContext(ctx, "CREATE TABLE "+table+" (id INT PRIMARY KEY, value INT) ENGINE=InnoDB"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = db.ExecContext(context.Background(), "DROP TABLE "+table) }()
	if _, err = db.ExecContext(ctx, "INSERT INTO "+table+" VALUES (1,0)"); err != nil {
		t.Fatal(err)
	}
	m := &MySQLConnector{}
	// Deliberately mislabeled to prove the database, not just the classifier,
	// refuses a write on the read execution path.
	if _, err = m.ExecuteQuery(ctx, cfg, QueryRequest{SQL: "UPDATE " + table + " SET value=99 WHERE id=1", Timeout: time.Second * 5}); err == nil {
		t.Fatal("read path wrote to MySQL")
	}
	var value int
	if err = db.QueryRowContext(ctx, "SELECT value FROM "+table+" WHERE id=1").Scan(&value); err != nil || value != 0 {
		t.Fatalf("read-only write changed data: %d %v", value, err)
	}
	result, err := m.ExecuteQuery(ctx, cfg, QueryRequest{SQL: "SELECT id FROM " + table, Timeout: time.Second * 5})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("read-only SELECT failed: %+v %v", result, err)
	}
	cfg.ReadOnly = true
	if _, err = m.ExecuteQuery(ctx, cfg, QueryRequest{SQL: "UPDATE " + table + " SET value=1 WHERE id=1", IsWrite: true}); err == nil {
		t.Fatal("read-only connection accepted write")
	}
	// The disposable MySQL server has a self-signed certificate. SSL=true must
	// reject it, rather than silently skipping verification or using plaintext.
	cfg.SSL = true
	if err = m.TestConnection(ctx, cfg); err == nil {
		t.Fatal("untrusted MySQL certificate accepted")
	}
}
