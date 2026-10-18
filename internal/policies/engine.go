package policies

import (
	"regexp"
	"strings"
)

// Policy is the effective security policy for an environment.
type Policy struct {
	ID                    string
	Environment           string
	MaxRows               int
	TimeoutSeconds        int
	AllowExport           bool
	RequireApprovalWrites bool
	AllowWriteQueries     bool
	MaskSensitiveColumns  bool
	AllowedSchemas        string // comma-separated; empty = all
	BlockedKeywords       string // comma-separated
}

func (p Policy) BlockedKeywordList() []string {
	var out []string
	for _, k := range strings.Split(p.BlockedKeywords, ",") {
		if k = strings.ToUpper(strings.TrimSpace(k)); k != "" {
			out = append(out, k)
		}
	}
	return out
}

func (p Policy) AllowedSchemaList() []string {
	var out []string
	for _, s := range strings.Split(p.AllowedSchemas, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

type StatementKind string

const (
	KindRead  StatementKind = "read"
	KindWrite StatementKind = "write"
	KindDDL   StatementKind = "ddl"
	KindOther StatementKind = "other"
)

// Analysis records dialect-parsed statement types, bounds and result provenance.
// Normalized text supplements operation checks for configured keyword filters.
type Analysis struct {
	Kind           StatementKind
	FirstKeyword   string
	IsWrite        bool
	HasWhere       bool
	MultiStatement bool
	Normalized     string
	ParseError     string
	UnboundedWrite bool
	Relations      []Relation
	SourceColumns  []string // direct projection columns, in result order; * means wildcard
	RedactAll      bool     // result provenance cannot be established safely
	IndirectAccess bool     // routines/casts or unsupported statements may access other schemas
	Operations     []string
}

var wsRe = regexp.MustCompile(`\s+`)

// stripSQL removes comments and string literals, returning an uppercased,
// whitespace-collapsed version suitable for keyword scanning.
func stripSQL(sql string) string {
	var b strings.Builder
	i := 0
	n := len(sql)
	for i < n {
		c := sql[i]
		switch {
		case c == '\'' || c == '"' || c == '`':
			quote := c
			i++
			for i < n {
				if sql[i] == quote {
					// handle escaped '' inside strings
					if quote == '\'' && i+1 < n && sql[i+1] == '\'' {
						i += 2
						continue
					}
					i++
					break
				}
				if sql[i] == '\\' && i+1 < n {
					i++
				}
				i++
			}
			b.WriteString(" 'x' ")
		case c == '-' && i+1 < n && sql[i+1] == '-':
			for i < n && sql[i] != '\n' {
				i++
			}
		case c == '#':
			for i < n && sql[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && sql[i+1] == '*':
			i += 2
			for i+1 < n && !(sql[i] == '*' && sql[i+1] == '/') {
				i++
			}
			i += 2
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
			i++
		}
	}
	return strings.TrimSpace(wsRe.ReplaceAllString(strings.ToUpper(b.String()), " "))
}

var readKeywords = map[string]bool{
	"SELECT": true, "WITH": true, "SHOW": true, "EXPLAIN": true,
	"DESCRIBE": true, "DESC": true, "VALUES": true, "TABLE": true,
}

var writeKeywords = map[string]bool{
	"INSERT": true, "UPDATE": true, "DELETE": true, "MERGE": true,
	"REPLACE": true, "UPSERT": true, "CALL": true, "SET": true, "COPY": true,
}

var ddlKeywords = map[string]bool{
	"CREATE": true, "DROP": true, "ALTER": true, "TRUNCATE": true,
	"GRANT": true, "REVOKE": true, "RENAME": true, "COMMENT": true, "VACUUM": true,
}

// Analyze uses PostgreSQL syntax for historical display and callers without a dialect.
// Execution always supplies the connection's dialect to AnalyzeDialect.
func Analyze(sql string) Analysis { return AnalyzeDialect(sql, "postgres") }

// CheckInput bundles everything the policy engine needs for a decision.
type CheckInput struct {
	SQL          string
	Dialect      string
	IsAdmin      bool
	IsPrivileged bool // admin or dba
	ConnReadOnly bool
	Environment  string
	Policy       Policy
}

// Decision is the outcome of a policy evaluation.
type Decision struct {
	Allowed          bool
	RequiresApproval bool
	Reason           string
	RiskScore        int
	Analysis         Analysis
}

// Evaluate applies the guardrails, in order of severity. Reasons are meant to
// be shown verbatim to the user and stored in the audit trail.
func Evaluate(in CheckInput) Decision {
	a := AnalyzeDialect(in.SQL, in.Dialect)
	d := Decision{Analysis: a, RiskScore: riskScore(a, in.Environment)}

	if a.ParseError != "" {
		d.Reason = "query cannot be safely analyzed: " + a.ParseError
		return d
	}
	if strings.TrimSpace(a.Normalized) == "" {
		d.Reason = "empty query"
		return d
	}
	if a.MultiStatement && !in.IsAdmin {
		d.Reason = "multiple statements per request are not allowed"
		return d
	}
	if !in.IsAdmin && a.Kind == KindOther {
		d.Reason = "unsupported statement type"
		return d
	}
	if err := in.Policy.CheckSchemas(a); err != nil {
		d.Reason = err.Error()
		return d
	}
	// Blocked keywords apply to everyone except admins.
	if !in.IsAdmin {
		for _, kw := range in.Policy.BlockedKeywordList() {
			if regexp.MustCompile(`\b` + regexp.QuoteMeta(kw) + `\b`).MatchString(a.Normalized + " " + strings.Join(a.Operations, " ")) {
				d.Reason = "statement contains blocked keyword " + kw
				return d
			}
		}
		if a.UnboundedWrite {
			d.Reason = "UPDATE or DELETE without its own WHERE clause is not allowed"
			return d
		}
	}
	if a.IsWrite {
		if in.ConnReadOnly {
			d.Reason = "connection is read-only"
			return d
		}
		if !in.Policy.AllowWriteQueries && !in.IsPrivileged {
			d.Reason = "write queries are disabled by policy for the " + in.Environment + " environment"
			return d
		}
		if in.Environment == "production" && in.Policy.RequireApprovalWrites && !in.IsAdmin {
			d.Allowed = false
			d.RequiresApproval = true
			d.Reason = "production write queries require approval"
			return d
		}
	}
	d.Allowed = true
	return d
}

// Risk computes the risk score for a statement in an environment without a
// full policy evaluation (used for display in history views).
func Risk(sql, environment string) int {
	return riskScore(Analyze(sql), environment)
}

func riskScore(a Analysis, environment string) int {
	score := 10
	switch a.Kind {
	case KindDDL:
		score = 90
	case KindWrite, KindOther:
		score = 50
		if a.UnboundedWrite {
			score = 85
		}
	}
	switch environment {
	case "production":
		score += 10
	case "staging":
		score += 5
	}
	if score > 100 {
		score = 100
	}
	return score
}
