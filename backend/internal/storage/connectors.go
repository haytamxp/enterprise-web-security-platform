package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	ConnectorScopeEventsIngest    = "events:ingest"
	ConnectorScopeIncidentsCreate = "incidents:create"
	connectorKeyPrefix            = "ewc_"
)

var (
	ErrInvalidConnectorKey     = errors.New("invalid connector key")
	ErrConnectorNotFound       = errors.New("connector not found")
	ErrConnectorTenantNotFound = errors.New("active tenant not found")
)

type Connector struct {
	ID         string
	TenantID   string
	Name       string
	KeyID      string
	APIKey     string
	Scopes     []string
	IsActive   bool
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

func validateConnectorScopes(scopes []string) error {
	if len(scopes) == 0 || len(scopes) > 2 {
		return errors.New("connector must have one or two scopes")
	}

	allowed := map[string]bool{
		ConnectorScopeEventsIngest:    true,
		ConnectorScopeIncidentsCreate: true,
	}

	seen := make(map[string]bool)

	for _, scope := range scopes {
		if !allowed[scope] {
			return fmt.Errorf("unsupported connector scope: %s", scope)
		}
		if seen[scope] {
			return fmt.Errorf("duplicate connector scope: %s", scope)
		}
		seen[scope] = true
	}

	return nil
}

func generateConnectorKey() (keyID, apiKey string, err error) {
	idBytes := make([]byte, 8)
	secretBytes := make([]byte, 32)

	if _, err = rand.Read(idBytes); err != nil {
		return "", "", fmt.Errorf("generate connector key ID: %w", err)
	}

	if _, err = rand.Read(secretBytes); err != nil {
		return "", "", fmt.Errorf("generate connector secret: %w", err)
	}

	keyID = hex.EncodeToString(idBytes)
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)

	apiKey = connectorKeyPrefix + keyID + "." + secret

	return keyID, apiKey, nil
}

// CreateConnector creates a tenant-scoped machine identity.
// The raw API key is returned once and must never be persisted.
func (s *Store) CreateConnector(
	ctx context.Context,
	tenantID string,
	name string,
	scopes []string,
	expiresAt *time.Time,
) (*Connector, error) {
	if s == nil || s.DB == nil {
		return nil, errors.New("connector storage is unavailable")
	}

	tenantID = strings.TrimSpace(tenantID)
	name = strings.TrimSpace(name)

	if tenantID == "" {
		return nil, errors.New("tenant ID is required")
	}
	if name == "" || len(name) > 120 {
		return nil, errors.New("connector name must contain 1 to 120 bytes")
	}
	if err := validateConnectorScopes(scopes); err != nil {
		return nil, err
	}
	if expiresAt != nil && !expiresAt.After(time.Now()) {
		return nil, errors.New("connector expiry must be in the future")
	}

	keyID, apiKey, err := generateConnectorKey()
	if err != nil {
		return nil, err
	}

	keyHash := sha256.Sum256([]byte(apiKey))
	scopesJSON, err := json.Marshal(scopes)
	if err != nil {
		return nil, fmt.Errorf("encode connector scopes: %w", err)
	}

	connector := &Connector{
		APIKey: apiKey,
		KeyID:  keyID,
		Scopes: append([]string(nil), scopes...),
	}

	var expiry sql.NullTime
	var returnedScopes string

	err = s.DB.QueryRowContext(ctx, `
INSERT INTO connectors (
tenant_id,
name,
key_id,
key_hash,
scopes,
expires_at
)
SELECT
tenant_id,
$2,
$3,
$4,
$5::jsonb,
$6
FROM tenants
WHERE tenant_id = $1::uuid
  AND is_active = TRUE
RETURNING
connector_id::text,
tenant_id::text,
name,
key_id,
scopes::text,
is_active,
created_at,
expires_at
`,
		tenantID,
		name,
		keyID,
		keyHash[:],
		string(scopesJSON),
		expiresAt,
	).Scan(
		&connector.ID,
		&connector.TenantID,
		&connector.Name,
		&connector.KeyID,
		&returnedScopes,
		&connector.IsActive,
		&connector.CreatedAt,
		&expiry,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrConnectorTenantNotFound
		}
		return nil, fmt.Errorf("create connector: %w", err)
	}

	if expiry.Valid {
		connector.ExpiresAt = &expiry.Time
	}

	return connector, nil
}

func parseConnectorKey(apiKey string) (string, error) {
	if len(apiKey) != 64 || strings.TrimSpace(apiKey) != apiKey {
		return "", ErrInvalidConnectorKey
	}

	if !strings.HasPrefix(apiKey, connectorKeyPrefix) {
		return "", ErrInvalidConnectorKey
	}

	remainder := strings.TrimPrefix(apiKey, connectorKeyPrefix)
	keyID, secret, found := strings.Cut(remainder, ".")

	if !found || len(keyID) != 16 || secret == "" {
		return "", ErrInvalidConnectorKey
	}

	if _, err := hex.DecodeString(keyID); err != nil {
		return "", ErrInvalidConnectorKey
	}

	secretBytes, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(secretBytes) != 32 {
		return "", ErrInvalidConnectorKey
	}

	return keyID, nil
}

// AuthenticateConnector verifies a connector key and records its last use.
func (s *Store) AuthenticateConnector(
	ctx context.Context,
	apiKey string,
) (*Connector, error) {
	if s == nil || s.DB == nil {
		return nil, errors.New("connector storage is unavailable")
	}

	keyID, err := parseConnectorKey(apiKey)
	if err != nil {
		return nil, ErrInvalidConnectorKey
	}

	presentedHash := sha256.Sum256([]byte(apiKey))

	connector := &Connector{}
	var storedHash []byte
	var scopesJSON string

	err = s.DB.QueryRowContext(ctx, `
SELECT
c.connector_id::text,
c.tenant_id::text,
c.name,
c.key_id,
c.key_hash,
c.scopes::text
FROM connectors c
JOIN tenants t ON t.tenant_id = c.tenant_id
WHERE c.key_id = $1
  AND c.is_active = TRUE
  AND c.revoked_at IS NULL
  AND t.is_active = TRUE
  AND (c.expires_at IS NULL OR c.expires_at > NOW())
`, keyID).Scan(
		&connector.ID,
		&connector.TenantID,
		&connector.Name,
		&connector.KeyID,
		&storedHash,
		&scopesJSON,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalidConnectorKey
	}
	if err != nil {
		return nil, fmt.Errorf("authenticate connector: %w", err)
	}

	if len(storedHash) != sha256.Size ||
		subtle.ConstantTimeCompare(storedHash, presentedHash[:]) != 1 {
		return nil, ErrInvalidConnectorKey
	}

	if err := json.Unmarshal([]byte(scopesJSON), &connector.Scopes); err != nil {
		return nil, fmt.Errorf("decode connector scopes: %w", err)
	}

	result, err := s.DB.ExecContext(ctx, `
UPDATE connectors
SET last_used_at = NOW()
WHERE connector_id = $1::uuid
  AND is_active = TRUE
  AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > NOW())
`, connector.ID)

	if err != nil {
		return nil, fmt.Errorf("update connector last use: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("check connector activity: %w", err)
	}
	if rows != 1 {
		return nil, ErrInvalidConnectorKey
	}

	return connector, nil
}

// RevokeConnector revokes a connector only within the supplied tenant.
func (s *Store) RevokeConnector(
	ctx context.Context,
	tenantID string,
	connectorID string,
) error {
	if s == nil || s.DB == nil {
		return errors.New("connector storage is unavailable")
	}

	result, err := s.DB.ExecContext(ctx, `
UPDATE connectors
SET is_active = FALSE,
    revoked_at = NOW()
WHERE tenant_id = $1::uuid
  AND connector_id = $2::uuid
  AND is_active = TRUE
  AND revoked_at IS NULL
`, tenantID, connectorID)

	if err != nil {
		return fmt.Errorf("revoke connector: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check connector revocation: %w", err)
	}
	if rows == 0 {
		return ErrConnectorNotFound
	}

	return nil
}
