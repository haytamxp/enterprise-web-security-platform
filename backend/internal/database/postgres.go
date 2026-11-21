package database

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

var DB *sql.DB

// Connect initialise la connexion à PostgreSQL
func Connect() error {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return fmt.Errorf("DATABASE_URL n'est pas défini dans le .env")
	}

	var err error
	DB, err = sql.Open("pgx", dbURL)
	if err != nil {
		return fmt.Errorf("erreur d'ouverture de la DB: %w", err)
	}

	DB.SetMaxOpenConns(25)
	DB.SetMaxIdleConns(25)
	DB.SetConnMaxLifetime(5 * time.Minute)

	if err := DB.Ping(); err != nil {
		return fmt.Errorf("impossible de joindre la DB: %w", err)
	}

	return nil
}