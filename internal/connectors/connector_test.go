package connectors

import "testing"

func TestValidDatabaseName(t *testing.T) {
	valid := []string{"demodb", "demo_db", "Demo-DB", "db$1", "a", "prod2026"}
	for _, name := range valid {
		if !ValidDatabaseName(name) {
			t.Errorf("expected %q to be valid", name)
		}
	}
	invalid := []string{
		"", " ", "db name", "db;DROP", "db/other", "db?sslmode=disable",
		"db'x", "db\"x", "db\\x", "db@host", "верига",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 64 chars
	}
	for _, name := range invalid {
		if ValidDatabaseName(name) {
			t.Errorf("expected %q to be rejected", name)
		}
	}
}
