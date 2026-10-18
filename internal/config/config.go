// Package config loads application configuration with the precedence:
// built-in defaults < config.yaml < environment variables.
//
// Runtime-tunable settings (session timeouts) additionally live in the
// app_settings table in the application database — see internal/settings.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// File mirrors the structure of config.yaml.
type File struct {
	App struct {
		Addr          string `yaml:"addr"`
		Env           string `yaml:"env"`
		CookieSecure  bool   `yaml:"cookie_secure"`
		TrustProxyIP  bool   `yaml:"trust_proxy_ip"`
		EncryptionKey string `yaml:"encryption_key"`
	} `yaml:"app"`
	Database struct {
		// Either a full URL...
		URL string `yaml:"url"`
		// ...or discrete fields for an existing PostgreSQL server.
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		Name     string `yaml:"name"`
		User     string `yaml:"user"`
		Password string `yaml:"password"`
		SSLMode  string `yaml:"sslmode"`
	} `yaml:"database"`
	Sessions struct {
		TTL     string `yaml:"ttl"`
		IdleTTL string `yaml:"idle_ttl"`
	} `yaml:"sessions"`
	Seed struct {
		Admin struct {
			Email    string `yaml:"email"`
			Password string `yaml:"password"`
			Name     string `yaml:"name"`
		} `yaml:"admin"`
	} `yaml:"seed"`
}

// Config is the resolved runtime configuration.
type Config struct {
	Addr           string
	DatabaseURL    string
	EncryptionKey  string
	SessionTTL     time.Duration
	SessionIdleTTL time.Duration
	CookieSecure   bool
	TrustProxyIP   bool
	Env            string

	SeedAdminEmail    string
	SeedAdminPassword string
	SeedAdminName     string
}

// Load reads config.yaml (path from CONFIG_FILE, default ./config.yaml if it
// exists) and applies environment-variable overrides.
func Load() (*Config, error) {
	cfg := &Config{
		Addr:           ":8080",
		Env:            "development",
		SessionTTL:     8 * time.Hour,
		SessionIdleTTL: 45 * time.Minute,
		SeedAdminEmail: "admin@securedb.local",
		SeedAdminName:  "Administrator",
	}

	path := os.Getenv("CONFIG_FILE")
	optional := false
	if path == "" {
		path = "config.yaml"
		optional = true
	}
	if raw, err := os.ReadFile(path); err == nil {
		var f File
		if err := yaml.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		applyFile(cfg, &f)
	} else if !optional {
		return nil, fmt.Errorf("read config file %s: %w", path, err)
	}

	applyEnv(cfg)

	if cfg.DatabaseURL == "" {
		cfg.DatabaseURL = "postgres://securedb:securedb@localhost:5432/securedb?sslmode=disable"
	}
	if cfg.EncryptionKey == "" {
		return nil, fmt.Errorf("encryption key is required: set app.encryption_key in config.yaml or APP_ENCRYPTION_KEY (generate with: openssl rand -hex 32)")
	}
	return cfg, nil
}

func applyFile(cfg *Config, f *File) {
	set := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	set(&cfg.Addr, f.App.Addr)
	set(&cfg.Env, f.App.Env)
	set(&cfg.EncryptionKey, f.App.EncryptionKey)
	cfg.CookieSecure = f.App.CookieSecure
	cfg.TrustProxyIP = f.App.TrustProxyIP

	if f.Database.URL != "" {
		cfg.DatabaseURL = f.Database.URL
	} else if f.Database.Host != "" {
		sslmode := f.Database.SSLMode
		if sslmode == "" {
			sslmode = "disable"
		}
		port := f.Database.Port
		if port == 0 {
			port = 5432
		}
		u := url.URL{
			Scheme:   "postgres",
			User:     url.UserPassword(f.Database.User, f.Database.Password),
			Host:     fmt.Sprintf("%s:%d", f.Database.Host, port),
			Path:     "/" + f.Database.Name,
			RawQuery: "sslmode=" + sslmode,
		}
		cfg.DatabaseURL = u.String()
	}

	if d, err := time.ParseDuration(f.Sessions.TTL); err == nil && f.Sessions.TTL != "" {
		cfg.SessionTTL = d
	}
	if d, err := time.ParseDuration(f.Sessions.IdleTTL); err == nil && f.Sessions.IdleTTL != "" {
		cfg.SessionIdleTTL = d
	}

	set(&cfg.SeedAdminEmail, f.Seed.Admin.Email)
	set(&cfg.SeedAdminPassword, f.Seed.Admin.Password)
	set(&cfg.SeedAdminName, f.Seed.Admin.Name)
}

func applyEnv(cfg *Config) {
	set := func(dst *string, key string) {
		if v := os.Getenv(key); v != "" {
			*dst = v
		}
	}
	set(&cfg.Addr, "APP_ADDR")
	set(&cfg.Env, "APP_ENV")
	set(&cfg.DatabaseURL, "DATABASE_URL")
	set(&cfg.EncryptionKey, "APP_ENCRYPTION_KEY")
	set(&cfg.SeedAdminEmail, "SEED_ADMIN_EMAIL")
	set(&cfg.SeedAdminPassword, "SEED_ADMIN_PASSWORD")
	set(&cfg.SeedAdminName, "SEED_ADMIN_NAME")
	if v := os.Getenv("SESSION_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.SessionTTL = d
		}
	}
	if v := os.Getenv("SESSION_IDLE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.SessionIdleTTL = d
		}
	}
	if v := os.Getenv("COOKIE_SECURE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.CookieSecure = b
		}
	}
	if v := os.Getenv("TRUST_PROXY_IP"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.TrustProxyIP = b
		}
	}
}
