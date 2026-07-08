package policies

import "strings"

// MaskingRule masks result-set values for columns whose name contains the
// pattern (case-insensitive).
type MaskingRule struct {
	ID            string
	ColumnPattern string
	Strategy      string // email | phone | card | redact | partial
	Description   string
	IsActive      bool
}

// DefaultMaskingRules seeds the standard sensitive-column patterns.
func DefaultMaskingRules() []MaskingRule {
	return []MaskingRule{
		{ColumnPattern: "email", Strategy: "email", Description: "Email addresses"},
		{ColumnPattern: "phone", Strategy: "phone", Description: "Phone numbers"},
		{ColumnPattern: "iban", Strategy: "partial", Description: "IBAN account numbers"},
		{ColumnPattern: "pan", Strategy: "card", Description: "Card primary account numbers"},
		{ColumnPattern: "card", Strategy: "card", Description: "Card numbers"},
		{ColumnPattern: "password", Strategy: "redact", Description: "Passwords"},
		{ColumnPattern: "token", Strategy: "redact", Description: "API and auth tokens"},
		{ColumnPattern: "secret", Strategy: "redact", Description: "Secrets"},
		{ColumnPattern: "national_id", Strategy: "redact", Description: "National ID numbers"},
		{ColumnPattern: "egn", Strategy: "redact", Description: "Bulgarian EGN"},
	}
}

// RuleForColumn finds the first active rule whose pattern is contained in the
// column name. Returns nil when the column is not sensitive.
func RuleForColumn(rules []MaskingRule, column string) *MaskingRule {
	col := strings.ToLower(column)
	for i := range rules {
		r := &rules[i]
		if !r.IsActive {
			continue
		}
		if strings.Contains(col, strings.ToLower(r.ColumnPattern)) {
			return r
		}
	}
	return nil
}

// MaskValue applies a strategy to a single value. NULLs pass through so result
// grids stay readable.
func MaskValue(strategy, value string) string {
	if value == "" || value == "NULL" {
		return value
	}
	switch strategy {
	case "email":
		return maskEmail(value)
	case "phone":
		return maskPhone(value)
	case "card":
		return maskCard(value)
	case "partial":
		return maskPartial(value)
	default: // redact
		return "********"
	}
}

// ApplyMasking masks matching columns in-place and returns the set of masked
// column indexes for UI badges.
func ApplyMasking(rules []MaskingRule, columns []string, rows [][]string) map[int]string {
	masked := map[int]string{}
	for i, col := range columns {
		if r := RuleForColumn(rules, col); r != nil {
			masked[i] = r.Strategy
		}
	}
	if len(masked) == 0 {
		return masked
	}
	for _, row := range rows {
		for i, strategy := range masked {
			if i < len(row) {
				row[i] = MaskValue(strategy, row[i])
			}
		}
	}
	return masked
}

// maskEmail: jo***@domain.com
func maskEmail(v string) string {
	at := strings.Index(v, "@")
	if at <= 0 {
		return "********"
	}
	local, domain := v[:at], v[at:]
	keep := 2
	if len(local) < keep {
		keep = len(local)
	}
	return local[:keep] + "***" + domain
}

// maskPhone: +359******123 (keep up to 4 leading chars and last 3 digits)
func maskPhone(v string) string {
	if len(v) <= 7 {
		return "********"
	}
	head := 4
	tail := 3
	stars := len(v) - head - tail
	if stars < 2 {
		return "********"
	}
	return v[:head] + strings.Repeat("*", stars) + v[len(v)-tail:]
}

// maskCard: **** **** **** 1234
func maskCard(v string) string {
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, v)
	if len(digits) < 4 {
		return "****"
	}
	return "**** **** **** " + digits[len(digits)-4:]
}

// maskPartial: keep first 3 and last 2 characters (IBANs, account numbers).
func maskPartial(v string) string {
	if len(v) <= 6 {
		return "********"
	}
	return v[:3] + strings.Repeat("*", len(v)-5) + v[len(v)-2:]
}
