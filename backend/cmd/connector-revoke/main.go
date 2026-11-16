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
		fmt.Fprintln(os.Stderr, "Connector revocation failed:", err)
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

	connectorID, err := readLine(reader, "Connector UUID to revoke: ")
	if err != nil || connectorID == "" {
		return errors.New("connector ID is required")
	}

	if err := store.RevokeConnector(ctx, tenantID, connectorID); err != nil {
		return err
	}

	fmt.Println("Connector revoked successfully.")
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
