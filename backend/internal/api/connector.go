package api

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/database"
)

var connectorUUIDPattern = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`,
)

var allowedConnectorScopes = map[string]bool{
	"events:ingest":    true,
	"incidents:create": true,
}

type ConnectorResponse struct {
	ConnectorID string     `json:"connector_id"`
	Name        string     `json:"name"`
	KeyID       string     `json:"key_id"`
	Scopes      []string   `json:"scopes"`
	IsActive    bool       `json:"is_active"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	Credential  string     `json:"credential,omitempty"`
}

type ConnectorCreateRequest struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	ExpiresAt *string  `json:"expires_at"`
}

type ConnectorUpdateRequest struct {
	Name      *string  `json:"name"`
	Scopes    []string `json:"scopes"`
	ExpiresAt *string  `json:"expires_at"`
}

type connectorScanner interface {
	Scan(dest ...any) error
}

const connectorSelectColumns = `
connector_id::text,
name,
key_id,
scopes,
is_active,
created_at,
expires_at,
last_used_at,
revoked_at
`

func connectorWriteJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func connectorWriteError(w http.ResponseWriter, status int, message string) {
	connectorWriteJSON(w, status, map[string]string{"error": message})
}

func connectorDecodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		return err
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("request must contain one JSON object")
		}
		return err
	}
	return nil
}

func connectorAdminIdentity(w http.ResponseWriter, r *http.Request) (AuthIdentity, bool) {
	identity, ok := AuthIdentityFromContext(r.Context())
	if !ok {
		connectorWriteError(w, http.StatusUnauthorized, "Authentication required")
		return AuthIdentity{}, false
	}
	if identity.Role != "admin" {
		connectorWriteError(w, http.StatusForbidden, "Administrator role required")
		return AuthIdentity{}, false
	}
	return identity, true
}

func connectorValidUUID(value string) bool {
	return connectorUUIDPattern.MatchString(value)
}

func connectorValidateScopes(scopes []string) ([]string, error) {
	if len(scopes) < 1 || len(scopes) > 2 {
		return nil, errors.New("scopes must contain one or two supported permissions")
	}

	seen := make(map[string]bool)
	result := make([]string, 0, len(scopes))

	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if !allowedConnectorScopes[scope] {
			return nil, errors.New("only events:ingest and incidents:create scopes are currently supported")
		}
		if seen[scope] {
			return nil, errors.New("duplicate connector scope")
		}
		seen[scope] = true
		result = append(result, scope)
	}

	return result, nil
}

func connectorParseExpiry(value *string) (*time.Time, error) {
	if value == nil || strings.TrimSpace(*value) == "" {
		return nil, nil
	}

	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*value))
	if err != nil {
		return nil, errors.New("expires_at must use RFC3339 format")
	}
	if !parsed.After(time.Now()) {
		return nil, errors.New("expires_at must be in the future")
	}

	utc := parsed.UTC()
	return &utc, nil
}

func connectorGenerateCredentials() (string, string, []byte, error) {
	keyIDBytes := make([]byte, 12)
	if _, err := rand.Read(keyIDBytes); err != nil {
		return "", "", nil, err
	}

	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", "", nil, err
	}

	keyID := base64.RawURLEncoding.EncodeToString(keyIDBytes)
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	hash := sha256.Sum256([]byte(secret))

	return keyID, secret, hash[:], nil
}

func connectorScan(scanner connectorScanner) (ConnectorResponse, error) {
	var item ConnectorResponse
	var scopesJSON []byte
	var expiresAt, lastUsedAt, revokedAt sql.NullTime

	err := scanner.Scan(
		&item.ConnectorID,
		&item.Name,
		&item.KeyID,
		&scopesJSON,
		&item.IsActive,
		&item.CreatedAt,
		&expiresAt,
		&lastUsedAt,
		&revokedAt,
	)
	if err != nil {
		return item, err
	}

	if err := json.Unmarshal(scopesJSON, &item.Scopes); err != nil {
		return item, err
	}
	if item.Scopes == nil {
		item.Scopes = make([]string, 0)
	}
	if expiresAt.Valid {
		item.ExpiresAt = &expiresAt.Time
	}
	if lastUsedAt.Valid {
		item.LastUsedAt = &lastUsedAt.Time
	}
	if revokedAt.Valid {
		item.RevokedAt = &revokedAt.Time
	}

	return item, nil
}

func connectorSQLState(err error) string {
	type stateError interface {
		SQLState() string
	}
	var state stateError
	if errors.As(err, &state) {
		return state.SQLState()
	}
	return ""
}

func connectorParsePage(r *http.Request) (int, int, bool) {
	limit := 50
	offset := 0

	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 100 {
			return 0, 0, false
		}
		limit = value
	}

	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 {
			return 0, 0, false
		}
		offset = value
	}

	return limit, offset, true
}

// CreateConnectorHandler creates a connector and returns its credential once.
//
// @Summary Create connector
// @Description Creates a tenant-scoped connector. The plaintext credential is returned only once.
// @Tags Connectors
// @Accept json
// @Produce json
// @Param body body ConnectorCreateRequest true "Connector configuration"
// @Success 201 {object} ConnectorResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Router /api/v1/connectors [post]
func CreateConnectorHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := connectorAdminIdentity(w, r)
	if !ok {
		return
	}

	var request ConnectorCreateRequest
	if err := connectorDecodeJSON(w, r, &request); err != nil {
		connectorWriteError(w, http.StatusBadRequest, "Invalid JSON request body")
		return
	}

	request.Name = strings.TrimSpace(request.Name)
	if request.Name == "" || len(request.Name) > 120 {
		connectorWriteError(w, http.StatusBadRequest, "name must contain 1-120 characters")
		return
	}

	scopes, err := connectorValidateScopes(request.Scopes)
	if err != nil {
		connectorWriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	expiresAt, err := connectorParseExpiry(request.ExpiresAt)
	if err != nil {
		connectorWriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	keyID, secret, keyHash, err := connectorGenerateCredentials()
	if err != nil {
		connectorWriteError(w, http.StatusInternalServerError, "Could not generate connector credentials")
		return
	}

	scopesJSON, err := json.Marshal(scopes)
	if err != nil {
		connectorWriteError(w, http.StatusInternalServerError, "Could not encode connector scopes")
		return
	}

	item, err := connectorScan(database.DB.QueryRowContext(
		r.Context(),
		`INSERT INTO connectors (
tenant_id, name, key_id, key_hash, scopes, expires_at
)
VALUES ($1, $2, $3, $4, $5::jsonb, $6)
RETURNING `+connectorSelectColumns,
		identity.TenantID,
		request.Name,
		keyID,
		keyHash,
		string(scopesJSON),
		expiresAt,
	))
	if err != nil {
		if connectorSQLState(err) == "23505" {
			connectorWriteError(w, http.StatusConflict, "Connector key ID already exists. Retry the request.")
			return
		}
		if connectorSQLState(err) == "23514" {
			connectorWriteError(w, http.StatusBadRequest, "Connector configuration violates a database constraint")
			return
		}
		connectorWriteError(w, http.StatusInternalServerError, "Could not create connector")
		return
	}

	item.Credential = keyID + "." + secret
	connectorWriteJSON(w, http.StatusCreated, item)
}

// ListConnectorsHandler lists connectors belonging to the authenticated tenant.
//
// @Summary List connectors
// @Description Lists connectors for the administrator's tenant. Secrets and hashes are never returned.
// @Tags Connectors
// @Produce json
// @Param is_active query bool false "Filter by active state"
// @Param limit query int false "Maximum results (1-100)"
// @Param offset query int false "Pagination offset"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Router /api/v1/connectors [get]
func ListConnectorsHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := connectorAdminIdentity(w, r)
	if !ok {
		return
	}

	limit, offset, valid := connectorParsePage(r)
	if !valid {
		connectorWriteError(w, http.StatusBadRequest, "limit must be 1-100 and offset must be zero or greater")
		return
	}

	query := `SELECT ` + connectorSelectColumns + ` FROM connectors WHERE tenant_id=$1`
	args := []any{identity.TenantID}

	if raw := strings.TrimSpace(r.URL.Query().Get("is_active")); raw != "" {
		isActive, err := strconv.ParseBool(raw)
		if err != nil {
			connectorWriteError(w, http.StatusBadRequest, "is_active must be true or false")
			return
		}
		args = append(args, isActive)
		query += " AND is_active=$" + strconv.Itoa(len(args))
	}

	args = append(args, limit)
	limitPosition := len(args)
	args = append(args, offset)
	offsetPosition := len(args)

	query += " ORDER BY created_at DESC, connector_id LIMIT $" +
		strconv.Itoa(limitPosition) + " OFFSET $" + strconv.Itoa(offsetPosition)

	rows, err := database.DB.QueryContext(r.Context(), query, args...)
	if err != nil {
		connectorWriteError(w, http.StatusInternalServerError, "Could not list connectors")
		return
	}
	defer rows.Close()

	items := make([]ConnectorResponse, 0)
	for rows.Next() {
		item, err := connectorScan(rows)
		if err != nil {
			connectorWriteError(w, http.StatusInternalServerError, "Could not read connectors")
			return
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		connectorWriteError(w, http.StatusInternalServerError, "Could not read connectors")
		return
	}

	connectorWriteJSON(w, http.StatusOK, map[string]any{
		"items":  items,
		"count":  len(items),
		"limit":  limit,
		"offset": offset,
	})
}

// GetConnectorHandler retrieves one connector.
//
// @Summary Get connector
// @Tags Connectors
// @Produce json
// @Param connector_id path string true "Connector UUID"
// @Success 200 {object} ConnectorResponse
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/v1/connectors/{connector_id} [get]
func GetConnectorHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := connectorAdminIdentity(w, r)
	if !ok {
		return
	}

	connectorID := strings.TrimSpace(r.PathValue("connector_id"))
	if !connectorValidUUID(connectorID) {
		connectorWriteError(w, http.StatusBadRequest, "Invalid connector_id")
		return
	}

	item, err := connectorScan(database.DB.QueryRowContext(
		r.Context(),
		`SELECT `+connectorSelectColumns+`
 FROM connectors
 WHERE tenant_id=$1 AND connector_id=$2`,
		identity.TenantID,
		connectorID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		connectorWriteError(w, http.StatusNotFound, "Connector not found")
		return
	}
	if err != nil {
		connectorWriteError(w, http.StatusInternalServerError, "Could not retrieve connector")
		return
	}

	connectorWriteJSON(w, http.StatusOK, item)
}

// UpdateConnectorHandler updates connector metadata, scopes, or expiry.
//
// @Summary Update connector
// @Tags Connectors
// @Accept json
// @Produce json
// @Param connector_id path string true "Connector UUID"
// @Param body body ConnectorUpdateRequest true "Connector changes"
// @Success 200 {object} ConnectorResponse
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Router /api/v1/connectors/{connector_id} [patch]
func UpdateConnectorHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := connectorAdminIdentity(w, r)
	if !ok {
		return
	}

	connectorID := strings.TrimSpace(r.PathValue("connector_id"))
	if !connectorValidUUID(connectorID) {
		connectorWriteError(w, http.StatusBadRequest, "Invalid connector_id")
		return
	}

	var request ConnectorUpdateRequest
	if err := connectorDecodeJSON(w, r, &request); err != nil {
		connectorWriteError(w, http.StatusBadRequest, "Invalid JSON request body")
		return
	}

	if request.Name == nil && request.Scopes == nil && request.ExpiresAt == nil {
		connectorWriteError(w, http.StatusBadRequest, "At least one field must be provided")
		return
	}

	var nameValue any
	if request.Name != nil {
		name := strings.TrimSpace(*request.Name)
		if name == "" || len(name) > 120 {
			connectorWriteError(w, http.StatusBadRequest, "name must contain 1-120 characters")
			return
		}
		nameValue = name
	}

	var scopesValue any
	if request.Scopes != nil {
		scopes, err := connectorValidateScopes(request.Scopes)
		if err != nil {
			connectorWriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		scopesJSON, err := json.Marshal(scopes)
		if err != nil {
			connectorWriteError(w, http.StatusInternalServerError, "Could not encode connector scopes")
			return
		}
		scopesValue = string(scopesJSON)
	}

	var expiryValue string
	expiryProvided := request.ExpiresAt != nil
	if expiryProvided {
		expiresAt, err := connectorParseExpiry(request.ExpiresAt)
		if err != nil {
			connectorWriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if expiresAt != nil {
			expiryValue = expiresAt.Format(time.RFC3339Nano)
		}
	}

	item, err := connectorScan(database.DB.QueryRowContext(
		r.Context(),
		`UPDATE connectors
 SET name=COALESCE($1,name),
     scopes=COALESCE($2::jsonb,scopes),
     expires_at=CASE WHEN $3 THEN NULLIF($4,'')::timestamptz ELSE expires_at END
 WHERE tenant_id=$5
   AND connector_id=$6
   AND is_active=TRUE
   AND revoked_at IS NULL
 RETURNING `+connectorSelectColumns,
		nameValue,
		scopesValue,
		expiryProvided,
		expiryValue,
		identity.TenantID,
		connectorID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		var exists bool
		checkErr := database.DB.QueryRowContext(
			r.Context(),
			`SELECT EXISTS(
SELECT 1 FROM connectors
WHERE tenant_id=$1 AND connector_id=$2
)`,
			identity.TenantID,
			connectorID,
		).Scan(&exists)
		if checkErr != nil {
			connectorWriteError(w, http.StatusInternalServerError, "Could not verify connector")
			return
		}
		if !exists {
			connectorWriteError(w, http.StatusNotFound, "Connector not found")
			return
		}
		connectorWriteError(w, http.StatusConflict, "Inactive or revoked connectors cannot be updated")
		return
	}
	if err != nil {
		if connectorSQLState(err) == "23514" {
			connectorWriteError(w, http.StatusBadRequest, "Connector configuration violates a database constraint")
			return
		}
		connectorWriteError(w, http.StatusInternalServerError, "Could not update connector")
		return
	}

	connectorWriteJSON(w, http.StatusOK, item)
}

// RotateConnectorSecretHandler replaces a connector key ID and secret.
// The plaintext credential is returned only once.
//
// @Summary Rotate connector secret
// @Description Replaces the connector key ID and secret. The new plaintext credential is returned once.
// @Tags Connectors
// @Produce json
// @Param connector_id path string true "Connector UUID"
// @Success 200 {object} ConnectorResponse
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Router /api/v1/connectors/{connector_id}/rotate-secret [post]
func RotateConnectorSecretHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := connectorAdminIdentity(w, r)
	if !ok {
		return
	}

	connectorID := strings.TrimSpace(r.PathValue("connector_id"))
	if !connectorValidUUID(connectorID) {
		connectorWriteError(w, http.StatusBadRequest, "Invalid connector_id")
		return
	}

	keyID, secret, keyHash, err := connectorGenerateCredentials()
	if err != nil {
		connectorWriteError(w, http.StatusInternalServerError, "Could not generate connector credentials")
		return
	}

	item, err := connectorScan(database.DB.QueryRowContext(
		r.Context(),
		`UPDATE connectors
 SET key_id=$1, key_hash=$2
 WHERE tenant_id=$3
   AND connector_id=$4
   AND is_active=TRUE
   AND revoked_at IS NULL
   AND (expires_at IS NULL OR expires_at > NOW())
 RETURNING `+connectorSelectColumns,
		keyID,
		keyHash,
		identity.TenantID,
		connectorID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		var exists bool
		checkErr := database.DB.QueryRowContext(
			r.Context(),
			`SELECT EXISTS(
SELECT 1 FROM connectors
WHERE tenant_id=$1 AND connector_id=$2
)`,
			identity.TenantID,
			connectorID,
		).Scan(&exists)
		if checkErr != nil {
			connectorWriteError(w, http.StatusInternalServerError, "Could not verify connector")
			return
		}
		if !exists {
			connectorWriteError(w, http.StatusNotFound, "Connector not found")
			return
		}
		connectorWriteError(w, http.StatusConflict, "Only active, non-expired connectors can rotate their secret")
		return
	}
	if err != nil {
		if connectorSQLState(err) == "23505" {
			connectorWriteError(w, http.StatusConflict, "Generated key ID already exists. Retry the request.")
			return
		}
		connectorWriteError(w, http.StatusInternalServerError, "Could not rotate connector secret")
		return
	}

	item.Credential = keyID + "." + secret
	connectorWriteJSON(w, http.StatusOK, item)
}

// RevokeConnectorHandler permanently revokes a connector credential.
//
// @Summary Revoke connector
// @Description Disables a connector and records its revocation timestamp.
// @Tags Connectors
// @Produce json
// @Param connector_id path string true "Connector UUID"
// @Success 200 {object} ConnectorResponse
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/v1/connectors/{connector_id}/revoke [post]
func RevokeConnectorHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := connectorAdminIdentity(w, r)
	if !ok {
		return
	}

	connectorID := strings.TrimSpace(r.PathValue("connector_id"))
	if !connectorValidUUID(connectorID) {
		connectorWriteError(w, http.StatusBadRequest, "Invalid connector_id")
		return
	}

	item, err := connectorScan(database.DB.QueryRowContext(
		r.Context(),
		`UPDATE connectors
 SET is_active=FALSE,
     revoked_at=COALESCE(revoked_at,NOW())
 WHERE tenant_id=$1 AND connector_id=$2
 RETURNING `+connectorSelectColumns,
		identity.TenantID,
		connectorID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		connectorWriteError(w, http.StatusNotFound, "Connector not found")
		return
	}
	if err != nil {
		connectorWriteError(w, http.StatusInternalServerError, "Could not revoke connector")
		return
	}

	connectorWriteJSON(w, http.StatusOK, item)
}
