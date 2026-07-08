package policies

import "testing"

func activeRules() []MaskingRule {
	rules := DefaultMaskingRules()
	for i := range rules {
		rules[i].IsActive = true
	}
	return rules
}

func TestMaskEmail(t *testing.T) {
	got := MaskValue("email", "john@domain.com")
	if got != "jo***@domain.com" {
		t.Errorf("email mask = %q, want jo***@domain.com", got)
	}
	if MaskValue("email", "not-an-email") != "********" {
		t.Error("invalid email should be fully redacted")
	}
}

func TestMaskPhone(t *testing.T) {
	got := MaskValue("phone", "+359881234123")
	want := "+359******123"
	if got != want {
		t.Errorf("phone mask = %q, want %q", got, want)
	}
	if MaskValue("phone", "123") != "********" {
		t.Error("short phone should be fully redacted")
	}
}

func TestMaskCard(t *testing.T) {
	got := MaskValue("card", "4111 1111 1111 1234")
	if got != "**** **** **** 1234" {
		t.Errorf("card mask = %q", got)
	}
	got = MaskValue("card", "4111111111111234")
	if got != "**** **** **** 1234" {
		t.Errorf("card mask without spaces = %q", got)
	}
}

func TestMaskRedactAndNull(t *testing.T) {
	if MaskValue("redact", "supersecret") != "********" {
		t.Error("redact must fully mask")
	}
	if MaskValue("redact", "NULL") != "NULL" {
		t.Error("NULL must pass through unmasked")
	}
	if MaskValue("redact", "") != "" {
		t.Error("empty must pass through")
	}
}

func TestRuleForColumn(t *testing.T) {
	rules := activeRules()
	cases := map[string]bool{
		"email":          true,
		"user_email":     true,
		"EMAIL_ADDRESS":  true,
		"phone_number":   true,
		"card_number":    true,
		"password_hash":  true,
		"api_token":      true,
		"client_secret":  true,
		"national_id":    true,
		"egn":            true,
		"iban_code":      true,
		"first_name":     false,
		"amount":         false,
		"id":             false,
	}
	for col, want := range cases {
		got := RuleForColumn(rules, col) != nil
		if got != want {
			t.Errorf("RuleForColumn(%q) matched=%v, want %v", col, got, want)
		}
	}
}

func TestApplyMasking(t *testing.T) {
	rules := activeRules()
	cols := []string{"id", "email", "phone", "card_number", "name"}
	rows := [][]string{
		{"1", "john@domain.com", "+359881234123", "4111111111111234", "John"},
		{"2", "NULL", "NULL", "NULL", "Jane"},
	}
	masked := ApplyMasking(rules, cols, rows)
	if len(masked) != 3 {
		t.Fatalf("expected 3 masked columns, got %d", len(masked))
	}
	if rows[0][1] != "jo***@domain.com" {
		t.Errorf("email not masked: %q", rows[0][1])
	}
	if rows[0][3] != "**** **** **** 1234" {
		t.Errorf("card not masked: %q", rows[0][3])
	}
	if rows[0][4] != "John" || rows[0][0] != "1" {
		t.Error("non-sensitive columns must be untouched")
	}
	if rows[1][1] != "NULL" {
		t.Error("NULL values must pass through")
	}
	// Inactive rules must not match.
	for i := range rules {
		rules[i].IsActive = false
	}
	if RuleForColumn(rules, "email") != nil {
		t.Error("inactive rule must not match")
	}
}
