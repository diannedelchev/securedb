package connectors

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHConfig describes an optional SSH tunnel (bastion/jump host) in front of
// the database. Credentials are decrypted just-in-time, like the DB password.
type SSHConfig struct {
	Enabled    bool
	Host       string
	Port       int
	User       string
	Password   string // password auth
	PrivateKey string // PEM-encoded key auth (takes precedence when set)
	// HostKeyFingerprint optionally pins the bastion's public key
	// ("SHA256:..." as printed by ssh-keygen -lf). Empty accepts any host key
	// — acceptable for development, pin it for production.
	HostKeyFingerprint string
}

// dialSSH opens the SSH connection to the bastion.
func dialSSH(cfg SSHConfig) (*ssh.Client, error) {
	if cfg.Host == "" || cfg.User == "" {
		return nil, fmt.Errorf("ssh tunnel requires a host and user")
	}
	port := cfg.Port
	if port == 0 {
		port = 22
	}

	var auth []ssh.AuthMethod
	if cfg.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(cfg.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("parse ssh private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if cfg.Password != "" {
		auth = append(auth, ssh.Password(cfg.Password))
	}
	if len(auth) == 0 {
		return nil, fmt.Errorf("ssh tunnel requires a password or a private key")
	}

	hostKeyCallback := ssh.InsecureIgnoreHostKey() // dev default; pin below for production
	if cfg.HostKeyFingerprint != "" {
		expected := cfg.HostKeyFingerprint
		hostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			got := ssh.FingerprintSHA256(key)
			if got != expected {
				return fmt.Errorf("ssh host key mismatch: got %s, pinned %s", got, expected)
			}
			return nil
		}
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", cfg.Host, port), &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("ssh connect to %s:%d: %w", cfg.Host, port, err)
	}
	return client, nil
}

// tunnelConn wraps a forwarded connection so closing it also tears down its
// SSH client (we dial one SSH session per database connection).
type tunnelConn struct {
	net.Conn
	client *ssh.Client
}

func (c *tunnelConn) Close() error {
	err := c.Conn.Close()
	_ = c.client.Close()
	return err
}

// dialViaTunnel connects to addr (host:port of the database) through the SSH
// bastion described by cfg.
func dialViaTunnel(cfg SSHConfig, addr string) (net.Conn, error) {
	client, err := dialSSH(cfg)
	if err != nil {
		return nil, err
	}
	conn, err := client.Dial("tcp", addr)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("ssh forward to %s: %w", addr, err)
	}
	return &tunnelConn{Conn: conn, client: client}, nil
}
