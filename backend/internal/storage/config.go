package storage

import "github.com/jackc/pgx/v5"

func newConfig(databaseURL string) (*pgx.ConnConfig, error) {
	return pgx.ParseConfig(databaseURL)
}
