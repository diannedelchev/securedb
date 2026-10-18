package policies

import "testing"

func TestWriteClassificationBypasses(t *testing.T) {
	for _, tc := range []struct{ dialect, sql string }{
		{"postgres", "WITH x AS ( SELECT 1 ) DELETE FROM t WHERE id=1"},
		{"postgres", "EXPLAIN ANALYZE DELETE FROM t WHERE id=1"},
		{"postgres", "WITH x AS (DELETE FROM t WHERE id=1 RETURNING *) SELECT * FROM x"},
		{"postgres", "SELECT * INTO stolen FROM t"},
		{"mysql", "WITH x AS (SELECT 1) UPDATE t SET a=2 WHERE id=1"},
		{"mysql", "/*! UPDATE t SET a=2 WHERE id=1 */"},
		{"mysql", "SELECT * FROM t INTO OUTFILE '/tmp/stolen'"},
	} {
		t.Run(tc.dialect+tc.sql, func(t *testing.T) {
			d := Evaluate(CheckInput{SQL: tc.sql, Dialect: tc.dialect, Environment: "production", Policy: DefaultPolicy("production")})
			if d.Allowed {
				t.Fatalf("write bypassed approval: %+v", d)
			}
			d = Evaluate(CheckInput{SQL: tc.sql, Dialect: tc.dialect, IsAdmin: true, ConnReadOnly: true, Policy: DefaultPolicy("development")})
			if d.Allowed {
				t.Fatal("write bypassed read-only connection")
			}
		})
	}
}

func TestNestedWhereDoesNotBoundOuterWrite(t *testing.T) {
	for _, tc := range []struct{ dialect, sql string }{
		{"postgres", "DELETE FROM t USING (SELECT id FROM t WHERE id=1) s"},
		{"postgres", "WITH x AS (SELECT id FROM t WHERE id=1) DELETE FROM t"},
		{"postgres", "UPDATE t SET a=(SELECT id FROM t WHERE id=1)"},
		{"postgres", "WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x WHERE id=1"},
		{"mysql", "UPDATE t SET a=(SELECT id FROM s WHERE id=1)"},
	} {
		d := Evaluate(CheckInput{SQL: tc.sql, Dialect: tc.dialect, Policy: DefaultPolicy("development")})
		if d.Allowed || d.RequiresApproval {
			t.Errorf("unbounded write accepted: %s: %+v", tc.sql, d)
		}
	}
}

func TestSchemaBoundaries(t *testing.T) {
	p := DefaultPolicy("development")
	p.AllowedSchemas = "public"
	for _, dialect := range []string{"postgres", "mysql"} {
		for _, sql := range []string{"SELECT * FROM restricted.payments", "SELECT * FROM payments", "SELECT * FROM public.payments JOIN restricted.secrets ON true", "SELECT read_secret()"} {
			d := Evaluate(CheckInput{SQL: sql, Dialect: dialect, Policy: p, IsAdmin: true})
			if d.Allowed {
				t.Errorf("%s schema restriction bypass: %s", dialect, sql)
			}
		}
		d := Evaluate(CheckInput{SQL: "SELECT id FROM public.payments WHERE id=1", Dialect: dialect, Policy: p})
		if !d.Allowed {
			t.Errorf("qualified permitted read rejected for %s: %s", dialect, d.Reason)
		}
	}
	if p.AllowsSchema("PUBLIC") || p.AllowsSchema("") {
		t.Fatal("schema identity must be exact")
	}
}

func TestMaskingUsesSourceColumns(t *testing.T) {
	for _, dialect := range []string{"postgres", "mysql"} {
		for _, sql := range []string{
			"SELECT card_number AS value FROM customers",
			"SELECT card_number AS token FROM customers",
			"SELECT substring(card_number,1,8) AS value FROM customers",
			"SELECT * FROM (SELECT card_number AS value FROM customers) x",
			"WITH x AS (SELECT card_number AS value FROM customers) SELECT * FROM x",
		} {
			a := AnalyzeDialect(sql, dialect)
			if a.ParseError != "" {
				t.Fatalf("parse %s: %s", sql, a.ParseError)
			}
			rows := [][]string{{"4111111111111111"}}
			masked := ApplyQueryMasking(activeRules(), a, []string{"value"}, rows)
			if len(masked) == 0 || rows[0][0] == "4111111111111111" {
				t.Errorf("%s masking bypass: %s", dialect, sql)
			}
		}
		a := AnalyzeDialect("SELECT id, name FROM customers", dialect)
		rows := [][]string{{"1", "Alice"}}
		ApplyQueryMasking(activeRules(), a, []string{"id", "name"}, rows)
		if rows[0][1] != "Alice" {
			t.Errorf("safe direct projection was redacted: %s", dialect)
		}
	}
}

func TestInvalidAndUnsupportedSQLFailsClosed(t *testing.T) {
	for _, dialect := range []string{"postgres", "mysql"} {
		for _, sql := range []string{"SELECT 'unterminated", "COMMIT", "SET TRANSACTION READ WRITE"} {
			d := Evaluate(CheckInput{SQL: sql, Dialect: dialect, Policy: DefaultPolicy("development")})
			if d.Allowed {
				t.Errorf("%s accepted %s", dialect, sql)
			}
		}
	}
}

func TestPostgresRelationAliasesCannotRemoveMasking(t *testing.T) {
	for _, sql := range []string{
		"SELECT * FROM customers AS c(value)",
		"SELECT value FROM customers AS c(value)",
		"SELECT c FROM customers c",
		"SELECT * FROM (customers a JOIN customers b ON true) AS c(value)",
	} {
		a := Analyze(sql)
		if a.ParseError != "" {
			t.Fatal(a.ParseError)
		}
		rows := [][]string{{"4111111111111111"}}
		ApplyQueryMasking(activeRules(), a, []string{"value"}, rows)
		if rows[0][0] == "4111111111111111" {
			t.Errorf("relation alias bypass: %s", sql)
		}
	}
}
