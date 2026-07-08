package connections

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dian/securedb/internal/connectors"
	"github.com/dian/securedb/internal/security"
)

type Connection struct {
	ID                string
	Name              string
	Description       string
	Environment       string
	DBType            string
	Host              string
	Port              int
	DatabaseName      string
	Username          string
	PasswordEncrypted string
	SecretsReference  string
	SSLEnabled        bool
	ReadOnly          bool
	OwnerID           string
	OwnerEmail        string
	Tags              string
	IsActive          bool
	LastUsed          *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time

	// SSH tunnel (bastion) settings; credentials encrypted at rest.
	SSHEnabled           bool
	SSHHost              string
	SSHPort              int
	SSHUser              string
	SSHAuth              string // password | key
	SSHPasswordEncrypted string
	SSHKeyEncrypted      string
	SSHHostKey           string // optional pinned fingerprint (SHA256:...)
}

// LastUsedFmt renders the nullable last-used time for templates.
func (c *Connection) LastUsedFmt() string {
	if c.LastUsed == nil {
		return "never used"
	}
	return "used " + c.LastUsed.Local().Format("Jan 02 15:04")
}

func (c *Connection) IsProduction() bool { return c.Environment == "production" }

func (c *Connection) TagList() []string {
	if strings.TrimSpace(c.Tags) == "" {
		return nil
	}
	parts := strings.Split(c.Tags, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// DBTypeLabel is used for display badges.
func (c *Connection) DBTypeLabel() string {
	switch c.DBType {
	case "postgres":
		return "PostgreSQL"
	case "mysql":
		return "MySQL"
	case "mssql":
		return "SQL Server"
	}
	return c.DBType
}

type Input struct {
	Name             string
	Description      string
	Environment      string
	DBType           string
	Host             string
	Port             int
	DatabaseName     string
	Username         string
	Password         string // empty on update = keep existing
	SecretsReference string
	SSLEnabled       bool
	ReadOnly         bool
	Tags             string
	IsActive         bool

	SSHEnabled  bool
	SSHHost     string
	SSHPort     int
	SSHUser     string
	SSHAuth     string
	SSHPassword string // empty on update = keep existing
	SSHKey      string // empty on update = keep existing
	SSHHostKey  string
}

func (in *Input) Validate() error {
	var problems []string
	if strings.TrimSpace(in.Name) == "" {
		problems = append(problems, "name is required")
	}
	switch in.Environment {
	case "development", "staging", "production":
	default:
		problems = append(problems, "environment must be development, staging or production")
	}
	switch in.DBType {
	case "postgres", "mysql", "mssql":
	default:
		problems = append(problems, "database type must be postgres, mysql or mssql")
	}
	if strings.TrimSpace(in.Host) == "" {
		problems = append(problems, "host is required")
	}
	if in.Port <= 0 || in.Port > 65535 {
		problems = append(problems, "port must be between 1 and 65535")
	}
	if strings.TrimSpace(in.DatabaseName) == "" {
		problems = append(problems, "database name is required")
	}
	if strings.TrimSpace(in.Username) == "" {
		problems = append(problems, "username is required")
	}
	if in.SSHEnabled {
		if strings.TrimSpace(in.SSHHost) == "" {
			problems = append(problems, "ssh host is required when the tunnel is enabled")
		}
		if strings.TrimSpace(in.SSHUser) == "" {
			problems = append(problems, "ssh user is required when the tunnel is enabled")
		}
		if in.SSHPort <= 0 || in.SSHPort > 65535 {
			problems = append(problems, "ssh port must be between 1 and 65535")
		}
		if in.SSHAuth != "password" && in.SSHAuth != "key" {
			problems = append(problems, "ssh auth must be password or key")
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

type Service struct {
	pool *pgxpool.Pool
	enc  *security.Encryptor
}

func NewService(pool *pgxpool.Pool, enc *security.Encryptor) *Service {
	return &Service{pool: pool, enc: enc}
}

const connCols = `c.id, c.name, c.description, c.environment, c.db_type, c.host, c.port,
	c.database_name, c.username, c.password_encrypted, c.secrets_reference, c.ssl_enabled,
	c.read_only, c.owner_id, COALESCE(u.email,''), c.tags, c.is_active,
	(SELECT max(h.created_at) FROM query_history h WHERE h.connection_id = c.id),
	c.ssh_enabled, c.ssh_host, c.ssh_port, c.ssh_user, c.ssh_auth,
	c.ssh_password_encrypted, c.ssh_key_encrypted, c.ssh_host_key,
	c.created_at, c.updated_at`

func scanConn(row interface{ Scan(...any) error }) (*Connection, error) {
	var c Connection
	err := row.Scan(&c.ID, &c.Name, &c.Description, &c.Environment, &c.DBType, &c.Host, &c.Port,
		&c.DatabaseName, &c.Username, &c.PasswordEncrypted, &c.SecretsReference, &c.SSLEnabled,
		&c.ReadOnly, &c.OwnerID, &c.OwnerEmail, &c.Tags, &c.IsActive, &c.LastUsed,
		&c.SSHEnabled, &c.SSHHost, &c.SSHPort, &c.SSHUser, &c.SSHAuth,
		&c.SSHPasswordEncrypted, &c.SSHKeyEncrypted, &c.SSHHostKey,
		&c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Service) List(ctx context.Context) ([]*Connection, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+connCols+` FROM database_connections c LEFT JOIN users u ON u.id=c.owner_id ORDER BY c.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Connection
	for rows.Next() {
		c, err := scanConn(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Service) Get(ctx context.Context, id string) (*Connection, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+connCols+` FROM database_connections c LEFT JOIN users u ON u.id=c.owner_id WHERE c.id=$1`, id)
	return scanConn(row)
}

func (s *Service) Create(ctx context.Context, ownerID string, in Input) (*Connection, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	if in.Password == "" && in.SecretsReference == "" {
		return nil, fmt.Errorf("a password or a secrets reference is required")
	}
	encrypted := ""
	if in.Password != "" {
		var err error
		encrypted, err = s.enc.Encrypt(in.Password)
		if err != nil {
			return nil, fmt.Errorf("encrypt credentials: %w", err)
		}
	}
	sshPass, sshKey, err := s.encryptSSH(in.SSHPassword, in.SSHKey)
	if err != nil {
		return nil, err
	}
	var id string
	err = s.pool.QueryRow(ctx,
		`INSERT INTO database_connections
		 (name, description, environment, db_type, host, port, database_name, username,
		  password_encrypted, secrets_reference, ssl_enabled, read_only, owner_id, tags, is_active,
		  ssh_enabled, ssh_host, ssh_port, ssh_user, ssh_auth, ssh_password_encrypted, ssh_key_encrypted, ssh_host_key)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23) RETURNING id`,
		in.Name, in.Description, in.Environment, in.DBType, in.Host, in.Port, in.DatabaseName,
		in.Username, encrypted, in.SecretsReference, in.SSLEnabled, in.ReadOnly, ownerID, in.Tags, in.IsActive,
		in.SSHEnabled, in.SSHHost, sshPortOrDefault(in.SSHPort), in.SSHUser, sshAuthOrDefault(in.SSHAuth),
		sshPass, sshKey, strings.TrimSpace(in.SSHHostKey)).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

func sshPortOrDefault(p int) int {
	if p <= 0 {
		return 22
	}
	return p
}

func sshAuthOrDefault(a string) string {
	if a != "key" {
		return "password"
	}
	return a
}

// encryptSSH encrypts non-empty tunnel credentials.
func (s *Service) encryptSSH(password, key string) (string, string, error) {
	encPass, encKey := "", ""
	var err error
	if password != "" {
		if encPass, err = s.enc.Encrypt(password); err != nil {
			return "", "", fmt.Errorf("encrypt ssh password: %w", err)
		}
	}
	if key != "" {
		if encKey, err = s.enc.Encrypt(key); err != nil {
			return "", "", fmt.Errorf("encrypt ssh key: %w", err)
		}
	}
	return encPass, encKey, nil
}

func (s *Service) Update(ctx context.Context, id string, in Input) (*Connection, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	existing, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	encrypted := existing.PasswordEncrypted
	if in.Password != "" {
		encrypted, err = s.enc.Encrypt(in.Password)
		if err != nil {
			return nil, fmt.Errorf("encrypt credentials: %w", err)
		}
	}
	// Keep existing tunnel credentials when the form leaves them blank.
	sshPass, sshKey, err := s.encryptSSH(in.SSHPassword, in.SSHKey)
	if err != nil {
		return nil, err
	}
	if sshPass == "" {
		sshPass = existing.SSHPasswordEncrypted
	}
	if sshKey == "" {
		sshKey = existing.SSHKeyEncrypted
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE database_connections SET
		 name=$2, description=$3, environment=$4, db_type=$5, host=$6, port=$7, database_name=$8,
		 username=$9, password_encrypted=$10, secrets_reference=$11, ssl_enabled=$12, read_only=$13,
		 tags=$14, is_active=$15,
		 ssh_enabled=$16, ssh_host=$17, ssh_port=$18, ssh_user=$19, ssh_auth=$20,
		 ssh_password_encrypted=$21, ssh_key_encrypted=$22, ssh_host_key=$23, updated_at=now()
		 WHERE id=$1`,
		id, in.Name, in.Description, in.Environment, in.DBType, in.Host, in.Port, in.DatabaseName,
		in.Username, encrypted, in.SecretsReference, in.SSLEnabled, in.ReadOnly, in.Tags, in.IsActive,
		in.SSHEnabled, in.SSHHost, sshPortOrDefault(in.SSHPort), in.SSHUser, sshAuthOrDefault(in.SSHAuth),
		sshPass, sshKey, strings.TrimSpace(in.SSHHostKey))
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

func (s *Service) Delete(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM database_connections WHERE id=$1`, id)
	return err
}

// Config resolves a stored connection into a connector config, decrypting the
// credential just-in-time. The plaintext password never leaves this process.
func (s *Service) Config(conn *Connection) (connectors.ConnectionConfig, error) {
	cfg := connectors.ConnectionConfig{
		Type:     conn.DBType,
		Host:     conn.Host,
		Port:     conn.Port,
		Database: conn.DatabaseName,
		Username: conn.Username,
		SSL:      conn.SSLEnabled,
		ReadOnly: conn.ReadOnly,
	}
	if conn.SSHEnabled {
		cfg.SSH = connectors.SSHConfig{
			Enabled:            true,
			Host:               conn.SSHHost,
			Port:               conn.SSHPort,
			User:               conn.SSHUser,
			HostKeyFingerprint: conn.SSHHostKey,
		}
		if conn.SSHPasswordEncrypted != "" {
			pw, err := s.enc.Decrypt(conn.SSHPasswordEncrypted)
			if err != nil {
				return cfg, fmt.Errorf("decrypt ssh credentials: %w", err)
			}
			cfg.SSH.Password = pw
		}
		if conn.SSHKeyEncrypted != "" {
			key, err := s.enc.Decrypt(conn.SSHKeyEncrypted)
			if err != nil {
				return cfg, fmt.Errorf("decrypt ssh key: %w", err)
			}
			cfg.SSH.PrivateKey = key
		}
	}
	if conn.PasswordEncrypted != "" {
		pw, err := s.enc.Decrypt(conn.PasswordEncrypted)
		if err != nil {
			return cfg, fmt.Errorf("decrypt credentials: %w", err)
		}
		cfg.Password = pw
		return cfg, nil
	}
	if conn.SecretsReference != "" {
		// Placeholder for AWS Secrets Manager / HashiCorp Vault resolution.
		return cfg, fmt.Errorf("secrets reference %q cannot be resolved yet (no secrets backend configured)", conn.SecretsReference)
	}
	return cfg, fmt.Errorf("connection has no stored credential")
}

// Test opens a connection to the target database and pings it.
func (s *Service) Test(ctx context.Context, conn *Connection) error {
	cfg, err := s.Config(conn)
	if err != nil {
		return err
	}
	connector, err := connectors.ForType(conn.DBType)
	if err != nil {
		return err
	}
	return connector.TestConnection(ctx, cfg)
}
