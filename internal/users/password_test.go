package users

import "testing"

func TestValidatePassword(t *testing.T) {
	if err := validatePassword("short7!"); err == nil {
		t.Fatal("7-character password accepted")
	}
	if err := validatePassword("longenough"); err != nil {
		t.Fatalf("8+ character password rejected: %v", err)
	}
}
