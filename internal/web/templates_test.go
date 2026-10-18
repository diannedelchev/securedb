package web

import (
	"bytes"
	"strings"
	"testing"

	"github.com/diannedelchev/securedb/internal/connectors"
	"github.com/diannedelchev/securedb/internal/query"
)

func TestResultExportPolicyAndAttribution(t *testing.T) {
	engine := NewEngine()
	for _, allowed := range []bool{false, true} {
		var out bytes.Buffer
		result := query.Outcome{Status: "success", HistoryID: "origin-id", AllowExport: allowed, Result: &connectors.QueryResult{Columns: []string{"name"}, Rows: [][]string{{"Alice"}}}}
		if err := engine.Render(&out, "partials/query_result", map[string]any{"Outcome": result}); err != nil {
			t.Fatal(err)
		}
		html := out.String()
		if !strings.Contains(html, `data-history-id="origin-id"`) {
			t.Fatal("result lost origin identity")
		}
		if strings.Contains(html, "Export CSV") != allowed {
			t.Fatal("result export controls ignored policy")
		}
		if strings.Contains(html, `data-allow-export="true"`) != allowed {
			t.Fatal("client policy attribute incorrect")
		}
	}
}
