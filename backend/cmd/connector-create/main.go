package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
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

func run() error {
	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	store, err := storage.Open(ctx, databaseURL)
	if err != nil {
		return errors.New("database connection failed")
	}
	defer store.DB.Close()

	var databaseName string
	if err := store.DB.QueryRowContext(ctx, `SELECT current_database()`).Scan(&databaseName); err != nil {
		return errors.New("database verification failed")
	}

	fmt.Println("Connected database:", databaseName)

	reader := bufio.NewReader(os.Stdin)

	confirmation, err := readLine(reader, "Type the database name to confirm: ")
	if err != nil || confirmation != databaseName {
		return errors.New("database confirmation failed")
	}

	tenantID, err := readLine(reader, "Tenant UUID: ")
	if err != nil || tenantID == "" {
		return errors.New("tenant ID is required")
	}

	name, err := readLine(reader, "Connector name: ")
	if err != nil || name == "" {
		return errors.New("connector name is required")
	}

	fmt.Println("Available scopes:")
	fmt.Println("  events:ingest")
	fmt.Println("  incidents:create")

	scopeInput, err := readLine(reader, "Scopes (comma-separated): ")
	if err != nil {
		return errors.New("scope input failed")
	}

	scopes := make([]string, 0, 2)
	for _, scope := range strings.Split(scopeInput, ",") {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			scopes = append(scopes, scope)
		}
	}

	expiry := time.Now().UTC().Add(90 * 24 * time.Hour)

	connector, err := store.CreateConnector(
		ctx,
		tenantID,
		name,
		scopes,
		&expiry,
	)
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("Connector created successfully.")
	fmt.Println("Connector ID:", connector.ID)
	fmt.Println("Tenant ID:", connector.TenantID)
	fmt.Println("Name:", connector.Name)
	fmt.Println("Scopes:", strings.Join(connector.Scopes, ", "))
	fmt.Println("Expires at:", connector.ExpiresAt.UTC().Format(time.RFC3339))
	fmt.Println()
	fmt.Println("API KEY (shown once; store it securely):")
	fmt.Println(connector.APIKey)
	fmt.Println()
	fmt.Println("The raw API key is not stored in PostgreSQL.")

	return nil
}

func readLine(reader *bufio.Reader, prompt string) (string, error) {
	fmt.Print(prompt)
	value, err := reader.ReadString('\n')
	if err != nil && len(value) == 0 {
		return "", err
	}
	return strings.TrimSpace(value), nil
}
