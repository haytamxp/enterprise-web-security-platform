package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/storage"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Connector creation failed:", err)
		os.Exit(1)
	}
}

func requiredEnv(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func run() error {
	databaseURL, err := requiredEnv("DATABASE_URL")
	if err != nil {
		return err
	}

	tenantID, err := requiredEnv("EWSTRP_TENANT_ID")
	if err != nil {
		return err
	}

	name, err := requiredEnv("EWSTRP_CONNECTOR_NAME")
	if err != nil {
		return err
	}

	scopeInput, err := requiredEnv("EWSTRP_CONNECTOR_SCOPES")
	if err != nil {
		return err
	}

	expectedDatabase, err := requiredEnv("EWSTRP_CONFIRM_DATABASE")
	if err != nil {
		return err
	}

	keyFile, err := requiredEnv("EWSTRP_CONNECTOR_KEY_FILE")
	if err != nil {
		return err
	}

	keyFile, err = filepath.Abs(keyFile)
	if err != nil {
		return fmt.Errorf("resolve connector key file path: %w", err)
	}

	if _, err := os.Stat(keyFile); err == nil {
		return errors.New("connector key file already exists; choose a new file path")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect connector key file: %w", err)
	}

	scopes := make([]string, 0, 2)
	for _, scope := range strings.Split(scopeInput, ",") {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			scopes = append(scopes, scope)
		}
	}

	openCtx, openCancel := context.WithTimeout(
		context.Background(),
		15*time.Second,
	)
	store, err := storage.Open(openCtx, databaseURL)
	openCancel()

	if err != nil {
		return errors.New("database connection failed")
	}
	defer store.DB.Close()

	var databaseName string
	verifyCtx, verifyCancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	err = store.DB.QueryRowContext(
		verifyCtx,
		`SELECT current_database()`,
	).Scan(&databaseName)
	verifyCancel()

	if err != nil {
		return fmt.Errorf("database verification failed: %w", err)
	}

	if databaseName != expectedDatabase {
		return fmt.Errorf(
			"database confirmation mismatch: connected to %q",
			databaseName,
		)
	}

	expiry := time.Now().UTC().Add(90 * 24 * time.Hour)

	// The timeout starts only when all configuration is already available.
	createCtx, createCancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)

	connector, err := store.CreateConnector(
		createCtx,
		tenantID,
		name,
		scopes,
		&expiry,
	)
	createCancel()

	if err != nil {
		return fmt.Errorf("create connector: %w", err)
	}

	if err := writeKeyFile(keyFile, connector.APIKey); err != nil {
		revokeCtx, revokeCancel := context.WithTimeout(
			context.Background(),
			10*time.Second,
		)
		revokeErr := store.RevokeConnector(
			revokeCtx,
			tenantID,
			connector.ID,
		)
		revokeCancel()

		if revokeErr != nil {
			return fmt.Errorf(
				"saving key failed (%v); automatic connector revocation also failed (%v)",
				err,
				revokeErr,
			)
		}

		return fmt.Errorf(
			"saving key failed; connector %s was automatically revoked: %w",
			connector.ID,
			err,
		)
	}

	fmt.Println()
	fmt.Println("Connector created successfully.")
	fmt.Println("Connector ID:", connector.ID)
	fmt.Println("Tenant ID:", connector.TenantID)
	fmt.Println("Name:", connector.Name)
	fmt.Println("Scopes:", strings.Join(connector.Scopes, ", "))
	fmt.Println("Expires at:", connector.ExpiresAt.UTC().Format(time.RFC3339))
	fmt.Println("API key saved locally; it was not printed.")
	fmt.Println("Key file:", keyFile)

	return nil
}

func writeKeyFile(path string, key string) error {
	directory := filepath.Dir(path)

	if err := os.MkdirAll(directory, 0700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}

	file, err := os.OpenFile(
		path,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0600,
	)
	if err != nil {
		return fmt.Errorf("create protected key file: %w", err)
	}

	_, writeErr := file.WriteString(key + "\n")
	syncErr := file.Sync()
	closeErr := file.Close()

	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return errors.Join(writeErr, syncErr, closeErr)
	}

	return nil
}
