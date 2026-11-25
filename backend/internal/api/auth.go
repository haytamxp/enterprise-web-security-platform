package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/database"
)

// LoginHandler authenticates an existing user and returns a JWT.
//
// @Summary      User login
// @Description  Authenticates a user and returns a JWT token
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        credentials body map[string]string true "Email and password"
// @Success      200 {object} map[string]string
// @Failure      401 {string} string "Invalid credentials"
// @Router       /auth/login [post]
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON request", http.StatusBadRequest)
		return
	}

	req.Email = strings.TrimSpace(req.Email)

	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	var (
		userID         string
		tenantID       string
		email          string
		dbPasswordHash string
		role           string
		isActive       bool
	)

	query := `
		SELECT
			user_id::text,
			tenant_id::text,
			email,
			password_hash,
			role,
			is_active
		FROM users
		WHERE LOWER(email) = LOWER($1)
	`

	err := database.DB.QueryRow(query, req.Email).Scan(
		&userID,
		&tenantID,
		&email,
		&dbPasswordHash,
		&role,
		&isActive,
	)

	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	if err != nil {
		http.Error(w, "Authentication service unavailable", http.StatusInternalServerError)
		return
	}

	if !isActive {
		http.Error(w, "Account is inactive", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword(
		[]byte(dbPasswordHash),
		[]byte(req.Password),
	); err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		http.Error(w, "Authentication unavailable", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	expiresAt := now.Add(24 * time.Hour)

	claims := AuthClaims{
		UserID:   userID,
		TenantID: tenantID,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   email,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		http.Error(w, "Could not create authentication token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})
}

// RegisterHandler allows an authenticated tenant administrator
// to create an analyst account inside their own tenant.
//
// @Summary      Register user
// @Description  Allows a tenant administrator to create an analyst account
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        credentials body map[string]string true "Email and password"
// @Success      201 {object} map[string]string
// @Failure      400 {string} string "Invalid data"
// @Failure      401 {string} string "Authentication required"
// @Failure      403 {string} string "Administrator access required"
// @Failure      409 {string} string "Email already exists"
// @Router       /auth/register [post]
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := AuthIdentityFromContext(r.Context())
	if !ok {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	if identity.Role != "admin" {
		http.Error(w, "Administrator access required", http.StatusForbidden)
		return
	}

	if identity.TenantID == "" {
		http.Error(w, "Invalid administrator tenant", http.StatusUnauthorized)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON request", http.StatusBadRequest)
		return
	}

	req.Email = strings.TrimSpace(req.Email)

	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(req.Password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		http.Error(w, "Could not secure password", http.StatusInternalServerError)
		return
	}

	query := `
		INSERT INTO users (email, password_hash, role, tenant_id)
		VALUES ($1, $2, 'analyst', $3)
		RETURNING user_id::text
	`

	var newID string

	err = database.DB.QueryRow(
		query,
		req.Email,
		string(hashedPassword),
		identity.TenantID,
	).Scan(&newID)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			http.Error(w, "Email already exists", http.StatusConflict)
			return
		}

		http.Error(w, "Could not create user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "User created successfully",
		"user_id": newID,
	})
}
