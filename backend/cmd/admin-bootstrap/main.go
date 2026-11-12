package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/auth"
	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/storage"
	"golang.org/x/term"
)

func main() {
	if err := run(); err != nil {
		if errors.Is(err, storage.ErrAdminAlreadyExists) {
			fmt.Fprintln(os.Stderr, "Bootstrap refused: an admin account already exists.")
		} else {
			fmt.Fprintf(os.Stderr, "Admin bootstrap failed: %v\n", err)
		}
		os.Exit(1)
	}

	fmt.Fprintln(os.Stdout, "Initial administrator account created successfully.")
}

func run() error {
	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if databaseURL == "" {
		return errors.New("database configuration is missing")
	}

	ctx := context.Background()

	store, err := storage.Open(ctx, databaseURL)
	if err != nil {
		return errors.New("database connection failed")
	}
	defer store.DB.Close()

	var databaseName string
	if err := store.DB.QueryRowContext(
		ctx,
		`SELECT current_database()`,
	).Scan(&databaseName); err != nil {
		return errors.New("database verification failed")
	}

	fmt.Fprintf(os.Stdout, "\nConnected database: %s\n", databaseName)

	reader := bufio.NewReader(os.Stdin)

	confirmation, err := readLine(
		reader,
		"Type the database name to confirm: ",
	)
	if err != nil || confirmation != databaseName {
		return errors.New("database confirmation failed")
	}

	email, err := readLine(reader, "Admin email: ")
	if err != nil || email == "" || len(email) > 254 {
		return errors.New("invalid email")
	}

	parsedEmail, err := mail.ParseAddress(email)
	if err != nil || parsedEmail.Address != email {
		return errors.New("invalid email")
	}

	password, err := readSecret("Admin password (hidden): ")
	if err != nil {
		return errors.New("password input failed: use an interactive PowerShell terminal")
	}
	defer wipe(password)

	passwordConfirmation, err := readSecret("Confirm password (hidden): ")
	if err != nil {
		return errors.New("password confirmation input failed: use an interactive PowerShell terminal")
	}
	defer wipe(passwordConfirmation)

	if subtle.ConstantTimeCompare(password, passwordConfirmation) != 1 {
		return errors.New("passwords do not match")
	}

	if len(password) < 12 {
		return errors.New("password must contain at least 12 bytes")
	}

	passwordHash, err := auth.HashPassword(string(password))
	wipe(password)
	if err != nil {
		return errors.New("password must be non-empty and no longer than bcrypt's 72-byte limit")
	}

	bootstrapCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	_, err = store.BootstrapAdmin(
		bootstrapCtx,
		email,
		passwordHash,
	)
	if err != nil {
		if errors.Is(err, storage.ErrAdminAlreadyExists) {
			return storage.ErrAdminAlreadyExists
		}
		return errors.New("database rejected admin creation; check the users schema and database logs")
	}

	return nil
}

func readLine(reader *bufio.Reader, prompt string) (string, error) {
	fmt.Fprint(os.Stdout, prompt)

	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", errors.New("terminal input failed")
	}
	if err != nil && len(value) == 0 {
		return "", errors.New("terminal input is empty")
	}

	return strings.TrimSpace(value), nil
}

func readSecret(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stdout, prompt)

	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stdout)

	if err != nil {
		return nil, errors.New("password must be entered through an interactive terminal")
	}

	return value, nil
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
