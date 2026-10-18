package main

import (
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v3"

	"github.com/diannedelchev/securedb/internal/config"
)

func TestWithProxy(t *testing.T) {
	off := withProxy(fiber.Config{}, &config.Config{})
	if off.TrustProxy || off.ProxyHeader != "" {
		t.Fatalf("proxy trust must stay off by default: %+v", off)
	}

	on := withProxy(fiber.Config{}, &config.Config{TrustProxyIP: true})
	if !on.TrustProxy || on.ProxyHeader != fiber.HeaderXForwardedFor {
		t.Fatalf("trust_proxy_ip must enable Fiber's TrustProxy with the forwarded header: %+v", on)
	}
	if !on.TrustProxyConfig.Loopback || !on.TrustProxyConfig.Private {
		t.Fatalf("loopback and private-network proxies must be trusted: %+v", on.TrustProxyConfig)
	}
}

// clientIP serves one request over a real loopback socket (Fiber's in-memory
// test transport cannot present a trusted peer) and returns what c.IP() — the
// address every audit entry records — resolved to.
func clientIP(t *testing.T, trust bool, forwardedFor string) string {
	t.Helper()
	app := fiber.New(withProxy(fiber.Config{}, &config.Config{TrustProxyIP: trust}))
	app.Get("/", func(c fiber.Ctx) error { return c.SendString(c.IP()) })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = app.Listener(ln, fiber.ListenConfig{DisableStartupMessage: true}) }()
	t.Cleanup(func() { _ = app.Shutdown() })

	req, err := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(fiber.HeaderXForwardedFor, forwardedFor)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestClientIPBehindProxy(t *testing.T) {
	const forwarded = "203.0.113.9"
	if got := clientIP(t, true, forwarded); got != forwarded {
		t.Fatalf("trust_proxy_ip=true: c.IP() = %q, want the forwarded client %q", got, forwarded)
	}
	if got := clientIP(t, false, forwarded); got != "127.0.0.1" {
		t.Fatalf("trust_proxy_ip=false: c.IP() = %q, want the peer address (header must be ignored)", got)
	}
}
