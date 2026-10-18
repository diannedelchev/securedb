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
		"card_number":   true,
		"password_hash": true,
		"client_secret": true,
		"national_id":   true,
		"egn":           true,
		"iban_code":     true,
		"first_name":    false,
		"amount":        false,
		"id":            false,
		// A token suffix cannot exempt a column matching a sensitive rule.
		"api_token":    false,
		"card_token":   true,
		"pan_token":    true,
		"secret_token": true,
		"TOKEN":        false,
	}
	for col, want := range cases {
		got := RuleForColumn(rules, col) != nil
		if got != want {
			t.Errorf("RuleForColumn(%q) matched=%v, want %v", col, got, want)
		}
	}
}

func TestApplyMaskingDoesNotExemptSensitiveTokenColumns(t *testing.T) {
	rules := activeRules()
	cols := []string{"id", "api_token", "card_token", "client_secret"}
	rows := [][]string{{"1", "tok_live_9f8e7d6c5b4a", "tok_card_4111", "cs_live_1a2b3c4d5e6f"}}
	masked := ApplyMasking(rules, cols, rows)
	if _, ok := masked[1]; ok {
		t.Error("api_token must not be masked")
	}
	if _, ok := masked[2]; !ok {
		t.Error("card_token must be masked")
	}
	if rows[0][1] != "tok_live_9f8e7d6c5b4a" || rows[0][2] == "tok_card_4111" {
		t.Errorf("token values altered: %q %q", rows[0][1], rows[0][2])
	}
	if rows[0][3] != "********" {
		t.Errorf("client_secret should still be redacted, got %q", rows[0][3])
	}
}

func TestApplyMasking(t *testing.T) {
	rules := activeRules()
	cols := []string{"id", "email", "phone", "card_number", "iban", "name"}
	rows := [][]string{
		{"1", "john@domain.com", "+359881234123", "4111111111111234", "BG80BNBG96611020345678", "John"},
		{"2", "NULL", "NULL", "NULL", "NULL", "Jane"},
	}
	masked := ApplyMasking(rules, cols, rows)
	if len(masked) != 2 {
		t.Fatalf("expected 2 masked columns (card, iban), got %d", len(masked))
	}
	if rows[0][1] != "john@domain.com" || rows[0][2] != "+359881234123" {
		t.Errorf("email/phone must not be masked: %q %q", rows[0][1], rows[0][2])
	}
	if rows[0][3] != "**** **** **** 1234" {
		t.Errorf("card not masked: %q", rows[0][3])
	}
	if rows[0][4] != "BG8*****************78" {
		t.Errorf("iban not masked: %q", rows[0][4])
	}
	if rows[0][5] != "John" || rows[0][0] != "1" {
		t.Error("non-sensitive columns must be untouched")
	}
	if rows[1][3] != "NULL" {
		t.Error("NULL values must pass through")
	}
	// Inactive rules must not match.
	for i := range rules {
		rules[i].IsActive = false
	}
	if RuleForColumn(rules, "card_number") != nil {
		t.Error("inactive rule must not match")
	}
}
