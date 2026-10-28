package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/httpapi"
	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/storage"
)

func main() {
	logger := log.New(os.Stdout, "ewstrp-api ", log.LstdFlags|log.LUTC)

	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	databaseURL := os.Getenv("DATABASE_URL")
	store, err := storage.Open(ctx, databaseURL)
	if err != nil {
		logger.Fatalf("Database initialization failed: %v", err)
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
			logger.Fatalf("HTTP server: %v", err)
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Printf("Graceful shutdown failed: %v", err)
			_ = server.Close()
		}
	}
}
