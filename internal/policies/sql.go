package policies

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	mysqlparser "github.com/pingcap/tidb/pkg/parser"
	"github.com/pingcap/tidb/pkg/parser/ast"
	_ "github.com/pingcap/tidb/pkg/parser/test_driver"
	pgparser "github.com/wasilibs/go-pgquery/parser"
)

type Relation struct{ Schema, Name string }

// AnalyzeDialect parses the same dialect the target will execute. Parser errors
// are hard blocks, including for admins; never retry with a different dialect.
func AnalyzeDialect(sql, dialect string) Analysis {
	a := Analysis{Normalized: stripSQL(sql), Kind: KindRead}
	var err error
	switch dialect {
	case "", "postgres":
		err = analyzePostgres(sql, &a)
	case "mysql":
		err = analyzeMySQL(sql, &a)
	default:
		err = fmt.Errorf("unsupported database dialect %q", dialect)
	}
	if err != nil {
		a.ParseError = err.Error()
		a.Kind = KindOther
		a.IsWrite = true
		a.RedactAll = true
	}
	return a
}

func (a *Analysis) operation(op string) {
	if a.FirstKeyword == "" {
		a.FirstKeyword = op
	}
	a.Operations = append(a.Operations, op)
	switch {
	case ddlKeywords[op]:
		a.Kind = KindDDL
		a.IsWrite = true
	case writeKeywords[op]:
		if a.Kind != KindDDL {
			a.Kind = KindWrite
		}
		a.IsWrite = true
	case readKeywords[op]:
	default:
		a.Kind = KindOther
		a.IsWrite = true
		a.IndirectAccess = true
	}
}

// Schema restrictions require explicit qualification. An implicit search_path,
// routine body or session command cannot be authorized from its SQL text.
func (p Policy) CheckSchemas(a Analysis) error {
	if len(p.AllowedSchemaList()) == 0 {
		return nil
	}
	if a.IndirectAccess || a.Kind == KindDDL || a.Kind == KindOther {
		return fmt.Errorf("statement cannot be verified against allowed schemas")
	}
	for _, r := range a.Relations {
		if r.Schema == "" {
			return fmt.Errorf("schema-qualified table names are required by policy")
		}
		if !p.AllowsSchema(r.Schema) {
			return fmt.Errorf("schema %q is not allowed by policy", r.Schema)
		}
	}
	return nil
}

func (p Policy) AllowsSchema(schema string) bool {
	allowed := p.AllowedSchemaList()
	if len(allowed) == 0 {
		return true
	}
	for _, s := range allowed {
		if s == schema {
			return true
		}
	}
	return false
}

func object(v any) map[string]any                   { m, _ := v.(map[string]any); return m }
func textField(m map[string]any, key string) string { s, _ := m[key].(string); return s }

func pgOperation(name string) string {
	switch name {
	case "SelectStmt":
		return "SELECT"
	case "InsertStmt":
		return "INSERT"
	case "UpdateStmt":
		return "UPDATE"
	case "DeleteStmt":
		return "DELETE"
	case "MergeStmt":
		return "MERGE"
	case "ExplainStmt":
		return "EXPLAIN"
	case "VariableShowStmt":
		return "SHOW"
	case "TruncateStmt":
		return "TRUNCATE"
	case "GrantStmt", "GrantRoleStmt":
		return "GRANT"
	case "ViewStmt", "IndexStmt":
		return "CREATE"
	case "RenameStmt":
		return "RENAME"
	case "CommentStmt":
		return "COMMENT"
	case "VacuumStmt":
		return "VACUUM"
	}
	for _, prefix := range []string{"Create", "Alter", "Drop"} {
		if strings.HasPrefix(name, prefix) {
			return strings.ToUpper(prefix)
		}
	}
	return "UNSUPPORTED"
}

func analyzePostgres(sql string, a *Analysis) error {
	raw, err := pgparser.ParseToJSON(sql)
	if err != nil {
		return err
	}
	var tree struct {
		Stmts []struct {
			Stmt map[string]any `json:"stmt"`
		} `json:"stmts"`
	}
	if err := json.Unmarshal([]byte(raw), &tree); err != nil {
		return err
	}
	a.MultiStatement = len(tree.Stmts) > 1
	a.RedactAll = len(tree.Stmts) != 1
	aliases := map[string]bool{}
	selects := 0
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case []any:
			for _, item := range x {
				walk(item)
			}
		case map[string]any:
			for key, value := range x {
				m := object(value)
				switch key {
				case "SelectStmt":
					selects++
					if m["intoClause"] != nil {
						a.operation("CREATE")
					}
				case "InsertStmt", "UpdateStmt", "DeleteStmt", "MergeStmt":
					a.operation(pgOperation(key))
					if key == "UpdateStmt" || key == "DeleteStmt" {
						a.UnboundedWrite = a.UnboundedWrite || m["whereClause"] == nil
						a.HasWhere = a.HasWhere || m["whereClause"] != nil
					}
					// MERGE has several conditional/unconditional actions; until
					// those are supported, non-admins must not bypass WHERE checks.
					if key == "MergeStmt" {
						a.UnboundedWrite = true
					}
				case "RangeVar":
					a.Relations = append(a.Relations, Relation{textField(m, "schemaname"), textField(m, "relname")})
					aliases[textField(m, "relname")] = true
					aliases[textField(object(m["alias"]), "aliasname")] = true
					if object(m["alias"])["colnames"] != nil {
						a.RedactAll = true
					}
					if m["catalogname"] != nil {
						a.IndirectAccess = true
					}
				case "FuncCall", "TypeCast", "RangeFunction":
					a.IndirectAccess = true
					a.RedactAll = true
				case "A_Expr":
					if names, ok := m["name"].([]any); ok && len(names) > 1 {
						a.IndirectAccess = true
					}
				case "WithClause", "RangeSubselect", "SubLink":
					a.RedactAll = true
				}
				walk(value)
			}
		}
	}
	for _, stmt := range tree.Stmts {
		for key := range stmt.Stmt {
			a.operation(pgOperation(key))
		}
		walk(stmt.Stmt)
	}
	if selects > 1 {
		a.RedactAll = true
	}
	if len(tree.Stmts) == 1 {
		s := object(tree.Stmts[0].Stmt["SelectStmt"])
		if s == nil {
			a.RedactAll = true
			return nil
		}
		if from, ok := s["fromClause"].([]any); ok {
			for _, source := range from {
				if !plainPGSource(object(source)) {
					a.RedactAll = true
					a.IndirectAccess = true
				}
			}
		}
		targets, _ := s["targetList"].([]any)
		for _, target := range targets {
			val := object(object(object(target)["ResTarget"])["val"])
			if val["A_Const"] != nil {
				a.SourceColumns = append(a.SourceColumns, "")
				continue
			}
			fields, _ := object(val["ColumnRef"])["fields"].([]any)
			if len(fields) == 0 {
				a.RedactAll = true
				continue
			}
			last := object(fields[len(fields)-1])
			name := textField(object(last["String"]), "sval")
			if last["A_Star"] != nil {
				name = "*"
			}
			if name == "" || (len(fields) == 1 && aliases[name]) {
				a.RedactAll = true
			}
			a.SourceColumns = append(a.SourceColumns, name)
		}
	}
	return nil
}

// Only base relations and joins have wildcard names we can trust. Table
// functions (including JSON/XML table constructors) can rename sensitive data.
func plainPGSource(source map[string]any) bool {
	if source["RangeVar"] != nil {
		return true
	}
	if join := object(source["JoinExpr"]); join != nil {
		if object(join["alias"])["colnames"] != nil {
			return false
		}
		return plainPGSource(object(join["larg"])) && plainPGSource(object(join["rarg"]))
	}
	return false
}

type mysqlVisitor struct {
	a       *Analysis
	selects int
}

func (v *mysqlVisitor) Enter(n ast.Node) (ast.Node, bool) {
	switch x := n.(type) {
	case *ast.SelectStmt:
		v.selects++
		if x.SelectIntoOpt != nil {
			v.a.operation("COPY")
		}
		if x.With != nil {
			v.a.RedactAll = true
		}
	case *ast.UpdateStmt:
		v.a.operation("UPDATE")
		v.a.UnboundedWrite = v.a.UnboundedWrite || x.Where == nil
		v.a.HasWhere = v.a.HasWhere || x.Where != nil
	case *ast.DeleteStmt:
		v.a.operation("DELETE")
		v.a.UnboundedWrite = v.a.UnboundedWrite || x.Where == nil
		v.a.HasWhere = v.a.HasWhere || x.Where != nil
	case *ast.InsertStmt:
		v.a.operation("INSERT")
	case *ast.TableSource:
		switch x.Source.(type) {
		case *ast.TableName, *ast.Join:
		default:
			v.a.RedactAll = true
			v.a.IndirectAccess = true
		}
	case *ast.TableName:
		v.a.Relations = append(v.a.Relations, Relation{x.Schema.O, x.Name.O})
	case *ast.FuncCallExpr:
		v.a.IndirectAccess = true
		v.a.RedactAll = true
	case *ast.SubqueryExpr, *ast.SetOprStmt:
		v.a.RedactAll = true
	}
	return n, false
}
func (v *mysqlVisitor) Leave(n ast.Node) (ast.Node, bool) { return n, true }

func mysqlOperation(n ast.StmtNode) string {
	switch n.(type) {
	case *ast.SelectStmt, *ast.SetOprStmt:
		return "SELECT"
	case *ast.UpdateStmt:
		return "UPDATE"
	case *ast.DeleteStmt:
		return "DELETE"
	case *ast.InsertStmt:
		return "INSERT"
	case *ast.ExplainStmt:
		return "EXPLAIN"
	case *ast.ShowStmt:
		return "SHOW"
	}
	return pgOperation(reflect.TypeOf(n).Elem().Name())
}

func analyzeMySQL(sql string, a *Analysis) error {
	p := mysqlparser.New()
	stmts, _, err := p.ParseSQL(sql)
	if err != nil {
		return err
	}
	a.MultiStatement = len(stmts) > 1
	a.RedactAll = len(stmts) != 1
	v := &mysqlVisitor{a: a}
	for _, s := range stmts {
		a.operation(mysqlOperation(s))
		s.Accept(v)
	}
	if v.selects > 1 {
		a.RedactAll = true
	}
	if len(stmts) == 1 {
		s, ok := stmts[0].(*ast.SelectStmt)
		if !ok {
			a.RedactAll = true
			switch stmts[0].(type) {
			case *ast.UpdateStmt, *ast.DeleteStmt, *ast.InsertStmt:
			default:
				a.IndirectAccess = true
			}
			return nil
		}
		if s.Fields == nil {
			a.RedactAll = true
			return nil
		}
		for _, f := range s.Fields.Fields {
			if f.WildCard != nil {
				a.SourceColumns = append(a.SourceColumns, "*")
				continue
			}
			if _, ok := f.Expr.(ast.ValueExpr); ok {
				a.SourceColumns = append(a.SourceColumns, "")
				continue
			}
			if col, ok := f.Expr.(*ast.ColumnNameExpr); ok {
				a.SourceColumns = append(a.SourceColumns, col.Name.Name.O)
			} else {
				a.RedactAll = true
			}
		}
	}
	return nil
}
