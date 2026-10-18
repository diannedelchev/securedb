package web

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/template/html/v2"
)

//go:embed all:templates
var templateFS embed.FS

// NewEngine builds the SSR template engine from the embedded templates.
func NewEngine() *html.Engine {
	sub, err := fs.Sub(templateFS, "templates")
	if err != nil {
		panic(err)
	}
	engine := html.NewFileSystem(http.FS(sub), ".html")
	engine.AddFuncMap(map[string]any{
		"fmtTime": func(t time.Time) string {
			return t.Local().Format("Jan 02 15:04")
		},
		"fmtTimeFull": func(t time.Time) string {
			return t.Local().Format("2006-01-02 15:04:05")
		},
		"truncate": func(n int, s string) string {
			s = strings.Join(strings.Fields(s), " ")
			if len(s) <= n {
				return s
			}
			return s[:n] + "…"
		},
		"upper": strings.ToUpper,
		"title": func(s string) string {
			if s == "" {
				return s
			}
			return strings.ToUpper(s[:1]) + s[1:]
		},
		"replace": strings.ReplaceAll,
		"envClass": func(env string) string {
			switch env {
			case "production":
				return "badge-prod"
			case "staging":
				return "badge-staging"
			default:
				return "badge-dev"
			}
		},
		"statusClass": func(status string) string {
			switch status {
			case "success", "approved":
				return "badge-success"
			case "error", "failure", "rejected":
				return "badge-error"
			case "blocked", "expired", "cancelled":
				return "badge-warning"
			case "pending", "pending_approval":
				return "badge-pending"
			default:
				return "badge-neutral"
			}
		},
		"addOne": func(n int) int { return n + 1 },
		"initials": func(name string) string {
			parts := strings.Fields(name)
			out := ""
			for i, p := range parts {
				if i > 1 {
					break
				}
				out += strings.ToUpper(p[:1])
			}
			if out == "" {
				out = "?"
			}
			return out
		},
		"dict": func(kv ...any) (map[string]any, error) {
			if len(kv)%2 != 0 {
				return nil, fmt.Errorf("dict needs key/value pairs")
			}
			m := make(map[string]any, len(kv)/2)
			for i := 0; i < len(kv); i += 2 {
				k, ok := kv[i].(string)
				if !ok {
					return nil, fmt.Errorf("dict keys must be strings")
				}
				m[k] = kv[i+1]
			}
			return m, nil
		},
	})
	return engine
}
