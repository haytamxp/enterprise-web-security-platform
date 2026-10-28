package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/httpapi"
	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/storage"
)

func main() {
	logger := log.New(os.Stdout, "ewstrp-api ", log.LstdFlags|log.LUTC)
	if err := run(logger); err != nil {
		logger.Fatal(err)
	}
}

func run(logger *log.Logger) error {
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	databaseURL := os.Getenv("DATABASE_URL")
	store, err := storage.Open(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("database initialization failed: %w", err)
	}
	defer store.DB.Close()

	server := &http.Server{
		Addr:              addr,
		Handler:           httpapi.NewWithStore(store),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Printf("Starting API on %s", addr)
		errCh <- server.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("HTTP server: %w", err)
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Printf("Graceful shutdown failed: %v", err)
			if closeErr := server.Close(); closeErr != nil {
				return errors.Join(err, closeErr)
			}
			return err
		}
	}
	return nil
}
