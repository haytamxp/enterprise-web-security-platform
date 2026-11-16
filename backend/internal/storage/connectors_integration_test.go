package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"strconv"
	"testing"
	"time"
)

func TestConnectorCreateAuthenticateAndRevoke(t *testing.T) {
	store, ctx := openTenantIngestTestStore(t)
	tenantID := getDefaultTenantID(t, ctx, store)

	name := "connector-test-" + strconv.FormatInt(time.Now().UnixNano(), 10)

	connector, err := store.CreateConnector(
		ctx,
		tenantID,
		name,
		[]string{ConnectorScopeEventsIngest},
		nil,
	)
	if err != nil {
		t.Fatalf("create connector: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = store.DB.ExecContext(
			cleanupCtx,
			`DELETE FROM connectors WHERE connector_id = $1::uuid`,
			connector.ID,
		)
	})

	if connector.APIKey == "" {
		t.Fatal("connector API key was not returned")
	}

	expectedHash := sha256.Sum256([]byte(connector.APIKey))

	var storedHash []byte
	err = store.DB.QueryRowContext(ctx, `
SELECT key_hash
FROM connectors
WHERE connector_id = $1::uuid
`, connector.ID).Scan(&storedHash)

	if err != nil {
		t.Fatalf("read stored connector hash: %v", err)
	}

	if len(storedHash) != sha256.Size {
		t.Fatalf("expected a %d-byte SHA-256 hash, got %d bytes", sha256.Size, len(storedHash))
	}

	if !bytes.Equal(storedHash, expectedHash[:]) {
		t.Fatal("stored API key hash does not match the generated key hash")
	}

	authenticated, err := store.AuthenticateConnector(ctx, connector.APIKey)
	if err != nil {
		t.Fatalf("authenticate connector: %v", err)
	}

	if authenticated.ID != connector.ID || authenticated.TenantID != tenantID {
		t.Fatal("authenticated connector identity did not match")
	}

	if len(authenticated.Scopes) != 1 ||
		authenticated.Scopes[0] != ConnectorScopeEventsIngest {
		t.Fatal("connector scopes did not match")
	}

	var lastUsed sql.NullTime
	err = store.DB.QueryRowContext(ctx, `
SELECT last_used_at
FROM connectors
WHERE connector_id = $1::uuid
`, connector.ID).Scan(&lastUsed)

	if err != nil || !lastUsed.Valid {
		t.Fatal("connector last_used_at was not updated")
	}

	tampered := connector.APIKey[:len(connector.APIKey)-1] + "A"
	if tampered == connector.APIKey {
		tampered = connector.APIKey[:len(connector.APIKey)-1] + "B"
	}

	_, err = store.AuthenticateConnector(ctx, tampered)
	if !errors.Is(err, ErrInvalidConnectorKey) {
		t.Fatalf("expected invalid key rejection, got %v", err)
	}

	if err := store.RevokeConnector(ctx, tenantID, connector.ID); err != nil {
		t.Fatalf("revoke connector: %v", err)
	}

	_, err = store.AuthenticateConnector(ctx, connector.APIKey)
	if !errors.Is(err, ErrInvalidConnectorKey) {
		t.Fatalf("expected revoked key rejection, got %v", err)
	}
}
