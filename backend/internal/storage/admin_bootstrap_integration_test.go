package storage

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func openAdminBootstrapTestStore(t *testing.T) (*Store, context.Context) {
	t.Helper()

	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured; PostgreSQL integration test skipped")
	}

	parsedURL, err := url.Parse(databaseURL)
	if err != nil || strings.Trim(parsedURL.Path, "/") != "ewstrp_test" {
		t.Fatal("TEST_DATABASE_URL must point to the isolated ewstrp_test database")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	store, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal("could not connect to the isolated test database")
	}
	t.Cleanup(func() {
		_ = store.DB.Close()
	})

	var databaseName string
	if err := store.DB.QueryRowContext(ctx, `SELECT current_database()`).Scan(&databaseName); err != nil {
		t.Fatal("could not verify the test database")
	}
	if databaseName != "ewstrp_test" {
		t.Fatal("integration test connected to an unexpected database")
	}

	return store, ctx
}

func requireNoExistingAdmin(t *testing.T, ctx context.Context, store *Store) {
	t.Helper()

	var count int
	if err := store.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE role = 'admin'`,
	).Scan(&count); err != nil {
		t.Fatal("could not inspect existing admin accounts")
	}

	if count != 0 {
		t.Skip("ewstrp_test already contains an admin; refusing to alter existing test data")
	}
}

func cleanupBootstrapTestUsers(t *testing.T, store *Store, emails ...string) {
	t.Helper()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		for _, email := range emails {
			_, _ = store.DB.ExecContext(
				ctx,
				`DELETE FROM users WHERE email = $1`,
				email,
			)
		}
	})
}

func TestBootstrapAdminCreatesOnlyOneAdmin(t *testing.T) {
	store, ctx := openAdminBootstrapTestStore(t)
	requireNoExistingAdmin(t, ctx, store)

	suffix := time.Now().Format("20060102150405.000000000")
	firstEmail := "bootstrap-first-" + suffix + "@example.invalid"
	secondEmail := "bootstrap-second-" + suffix + "@example.invalid"

	cleanupBootstrapTestUsers(t, store, firstEmail, secondEmail)

	first, err := store.BootstrapAdmin(ctx, firstEmail, "test-password-hash")
	if err != nil {
		t.Fatal("first admin bootstrap failed")
	}

	if first.Email != firstEmail || first.Role != "admin" || !first.IsActive {
		t.Fatal("first bootstrap returned unexpected user data")
	}

	_, err = store.BootstrapAdmin(ctx, secondEmail, "another-test-password-hash")
	if !errors.Is(err, ErrAdminAlreadyExists) {
		t.Fatal("second bootstrap should have been rejected")
	}

	var count int
	if err := store.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE role = 'admin'`,
	).Scan(&count); err != nil {
		t.Fatal("could not verify admin count")
	}

	if count != 1 {
		t.Fatalf("expected exactly one admin, got %d", count)
	}
}

func TestBootstrapAdminSerializesConcurrentAttempts(t *testing.T) {
	store, ctx := openAdminBootstrapTestStore(t)
	requireNoExistingAdmin(t, ctx, store)

	suffix := time.Now().Format("20060102150405.000000000")
	firstEmail := "bootstrap-concurrent-a-" + suffix + "@example.invalid"
	secondEmail := "bootstrap-concurrent-b-" + suffix + "@example.invalid"

	cleanupBootstrapTestUsers(t, store, firstEmail, secondEmail)

	type result struct {
		err error
	}

	start := make(chan struct{})
	results := make(chan result, 2)

	emails := []string{firstEmail, secondEmail}
	for _, email := range emails {
		go func(email string) {
			<-start
			_, err := store.BootstrapAdmin(ctx, email, "concurrent-test-password-hash")
			results <- result{err: err}
		}(email)
	}

	close(start)

	successCount := 0
	rejectedCount := 0

	for range emails {
		res := <-results

		switch {
		case res.err == nil:
			successCount++
		case errors.Is(res.err, ErrAdminAlreadyExists):
			rejectedCount++
		default:
			t.Fatal("concurrent bootstrap returned an unexpected error")
		}
	}

	if successCount != 1 || rejectedCount != 1 {
		t.Fatalf(
			"expected one successful bootstrap and one rejection; got success=%d rejected=%d",
			successCount,
			rejectedCount,
		)
	}

	var count int
	if err := store.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE role = 'admin'`,
	).Scan(&count); err != nil {
		t.Fatal("could not verify admin count after concurrent attempts")
	}

	if count != 1 {
		t.Fatalf("expected exactly one admin after concurrent attempts, got %d", count)
	}
}
