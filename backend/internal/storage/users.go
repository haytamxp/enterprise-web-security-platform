package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// User represents a persisted platform user.
type User struct {
	ID           string
	Email        string
	PasswordHash string
	Role         string
	IsActive     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	LastLoginAt  *time.Time
}

// CreateUser stores a user using an already-computed password hash.
// The caller must hash the password before calling this method.
func (s *Store) CreateUser(
	ctx context.Context,
	email string,
	passwordHash string,
	role string,
) (*User, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	if email == "" {
		return nil, fmt.Errorf("create user: email is required")
	}
	if passwordHash == "" {
		return nil, fmt.Errorf("create user: password hash is required")
	}

	switch role {
	case "admin", "analyst", "responder", "viewer":
	default:
		return nil, fmt.Errorf("create user: invalid role")
	}

	user := &User{}
	var lastLogin sql.NullTime

	err := s.DB.QueryRowContext(ctx, `
		INSERT INTO users (email, password_hash, role)
		VALUES ($1, $2, $3)
		RETURNING
			user_id::text,
			email,
			password_hash,
			role,
			is_active,
			created_at,
			updated_at,
			last_login_at
	`, email, passwordHash, role).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
		&lastLogin,
	)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	if lastLogin.Valid {
		user.LastLoginAt = &lastLogin.Time
	}

	return user, nil
}

// GetUserByEmail retrieves a user without revealing whether an account
// exists to an unauthenticated client. HTTP handlers must handle errors safely.
func (s *Store) GetUserByEmail(
	ctx context.Context,
	email string,
) (*User, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	user := &User{}
	var lastLogin sql.NullTime

	err := s.DB.QueryRowContext(ctx, `
		SELECT
			user_id::text,
			email,
			password_hash,
			role,
			is_active,
			created_at,
			updated_at,
			last_login_at
		FROM users
		WHERE LOWER(email) = $1
	`, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
		&lastLogin,
	)
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}

	if lastLogin.Valid {
		user.LastLoginAt = &lastLogin.Time
	}

	return user, nil
}

// UpdateLastLogin records a successful login.
func (s *Store) UpdateLastLogin(ctx context.Context, userID string) error {
	result, err := s.DB.ExecContext(ctx, `
		UPDATE users
		SET last_login_at = NOW(),
		    updated_at = NOW()
		WHERE user_id = $1::uuid
	`, userID)
	if err != nil {
		return fmt.Errorf("update last login: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check last login update: %w", err)
	}
	if rows == 0 {
		return sql.ErrNoRows
	}

	return nil
}
