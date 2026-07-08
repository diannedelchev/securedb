package policies

import "testing"

func devPolicy() Policy {
	p := DefaultPolicy("development")
	return p
}

func prodPolicy() Policy {
	return DefaultPolicy("production")
}

func TestAnalyzeClassification(t *testing.T) {
	cases := []struct {
		sql     string
		kind    StatementKind
		isWrite bool
	}{
		{"SELECT * FROM users", KindRead, false},
		{"  select 1", KindRead, false},
		{"WITH x AS (SELECT 1) SELECT * FROM x", KindRead, false},
		{"WITH x AS (SELECT 1) DELETE FROM t WHERE id=1", KindWrite, true},
		{"INSERT INTO t VALUES (1)", KindWrite, true},
		{"UPDATE t SET a=1 WHERE id=2", KindWrite, true},
		{"DELETE FROM t WHERE id=1", KindWrite, true},
		{"DROP TABLE t", KindDDL, true},
		{"TRUNCATE TABLE t", KindDDL, true},
		{"ALTER TABLE t ADD COLUMN x int", KindDDL, true},
		{"CREATE TABLE t (id int)", KindDDL, true},
		{"EXPLAIN SELECT * FROM t", KindRead, false},
		{"SHOW TABLES", KindRead, false},
		{"GRANT ALL ON t TO u", KindDDL, true},
		{"FLUSH PRIVILEGES", KindOther, true}, // unknown fails closed as write
	}
	for _, tc := range cases {
		a := Analyze(tc.sql)
		if a.Kind != tc.kind || a.IsWrite != tc.isWrite {
			t.Errorf("Analyze(%q) = kind %s write %v, want kind %s write %v",
				tc.sql, a.Kind, a.IsWrite, tc.kind, tc.isWrite)
		}
	}
}

func TestAnalyzeIgnoresLiteralsAndComments(t *testing.T) {
	a := Analyze(`SELECT * FROM audit WHERE msg = 'please DROP TABLE users' -- DELETE everything`)
	if a.Kind != KindRead {
		t.Fatalf("expected read, got %s", a.Kind)
	}
	d := Evaluate(CheckInput{SQL: `SELECT 'TRUNCATE' AS x FROM t`, Policy: devPolicy()})
	if !d.Allowed {
		t.Fatalf("keyword inside string literal must not block: %s", d.Reason)
	}
}

func TestMultiStatementBlocked(t *testing.T) {
	d := Evaluate(CheckInput{SQL: "SELECT 1; SELECT 2", Policy: devPolicy()})
	if d.Allowed {
		t.Fatal("multi-statement should be blocked for non-admins")
	}
	d = Evaluate(CheckInput{SQL: "SELECT 1;", Policy: devPolicy()})
	if !d.Allowed {
		t.Fatalf("single statement with trailing semicolon should pass: %s", d.Reason)
	}
}

func TestBlockedKeywords(t *testing.T) {
	for _, sql := range []string{"DROP TABLE t", "TRUNCATE t", "ALTER TABLE t DROP COLUMN c", "CREATE INDEX i ON t(c)"} {
		d := Evaluate(CheckInput{SQL: sql, Policy: devPolicy()})
		if d.Allowed {
			t.Errorf("expected %q to be blocked for normal users", sql)
		}
	}
	// Admins bypass keyword blocking.
	d := Evaluate(CheckInput{SQL: "DROP TABLE t", IsAdmin: true, IsPrivileged: true, Policy: devPolicy()})
	if !d.Allowed {
		t.Errorf("admin should bypass blocked keywords: %s", d.Reason)
	}
	// Column names containing a keyword must not match (word boundaries).
	d = Evaluate(CheckInput{SQL: "SELECT created_at FROM t", Policy: devPolicy()})
	if !d.Allowed {
		t.Errorf("created_at must not trigger CREATE keyword block: %s", d.Reason)
	}
}

func TestWriteWithoutWhere(t *testing.T) {
	d := Evaluate(CheckInput{SQL: "DELETE FROM t", Policy: devPolicy()})
	if d.Allowed || d.Reason == "" {
		t.Fatal("DELETE without WHERE must be blocked")
	}
	d = Evaluate(CheckInput{SQL: "UPDATE t SET a=1", Policy: devPolicy()})
	if d.Allowed {
		t.Fatal("UPDATE without WHERE must be blocked")
	}
	d = Evaluate(CheckInput{SQL: "UPDATE t SET a=1 WHERE id=3", Policy: devPolicy()})
	if !d.Allowed {
		t.Fatalf("UPDATE with WHERE should pass in development: %s", d.Reason)
	}
}

func TestReadOnlyConnection(t *testing.T) {
	d := Evaluate(CheckInput{SQL: "INSERT INTO t VALUES (1)", ConnReadOnly: true, Policy: devPolicy()})
	if d.Allowed {
		t.Fatal("write on read-only connection must be blocked")
	}
	// Even admins cannot write through a read-only connection.
	d = Evaluate(CheckInput{SQL: "INSERT INTO t VALUES (1)", IsAdmin: true, IsPrivileged: true, ConnReadOnly: true, Policy: devPolicy()})
	if d.Allowed {
		t.Fatal("read-only applies to admins too")
	}
	d = Evaluate(CheckInput{SQL: "SELECT 1", ConnReadOnly: true, Policy: devPolicy()})
	if !d.Allowed {
		t.Fatalf("reads on read-only connections should pass: %s", d.Reason)
	}
}

func TestProductionApproval(t *testing.T) {
	d := Evaluate(CheckInput{SQL: "UPDATE t SET a=1 WHERE id=1", Environment: "production", Policy: prodPolicy()})
	if d.Allowed || !d.RequiresApproval {
		t.Fatalf("production write must require approval, got allowed=%v approval=%v", d.Allowed, d.RequiresApproval)
	}
	// Reads never need approval.
	d = Evaluate(CheckInput{SQL: "SELECT 1", Environment: "production", Policy: prodPolicy()})
	if !d.Allowed || d.RequiresApproval {
		t.Fatal("production reads should not require approval")
	}
	// Admins bypass the approval gate.
	d = Evaluate(CheckInput{SQL: "UPDATE t SET a=1 WHERE id=1", IsAdmin: true, IsPrivileged: true, Environment: "production", Policy: prodPolicy()})
	if !d.Allowed {
		t.Fatalf("admin production write should be allowed directly: %s", d.Reason)
	}
}

func TestAllowWriteQueriesPolicy(t *testing.T) {
	p := devPolicy()
	p.AllowWriteQueries = false
	d := Evaluate(CheckInput{SQL: "INSERT INTO t VALUES (1)", Policy: p})
	if d.Allowed {
		t.Fatal("writes must be blocked when policy disables them")
	}
	d = Evaluate(CheckInput{SQL: "INSERT INTO t VALUES (1)", IsPrivileged: true, Policy: p})
	if !d.Allowed {
		t.Fatalf("privileged users may write when policy disables writes for others: %s", d.Reason)
	}
}

func TestRiskScore(t *testing.T) {
	ddl := Evaluate(CheckInput{SQL: "DROP TABLE t", IsAdmin: true, IsPrivileged: true, Environment: "production", Policy: prodPolicy()})
	sel := Evaluate(CheckInput{SQL: "SELECT 1", Policy: devPolicy()})
	if ddl.RiskScore <= sel.RiskScore {
		t.Fatalf("DDL in production (%d) must outrank a dev select (%d)", ddl.RiskScore, sel.RiskScore)
	}
}

func TestEmptyQuery(t *testing.T) {
	for _, sql := range []string{"", "   ", "-- just a comment"} {
		d := Evaluate(CheckInput{SQL: sql, Policy: devPolicy()})
		if d.Allowed {
			t.Errorf("empty query %q must not be allowed", sql)
		}
	}
}
