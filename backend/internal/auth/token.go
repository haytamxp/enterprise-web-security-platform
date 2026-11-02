package auth

import (
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	RoleAdmin     = "admin"
	RoleAnalyst   = "analyst"
	RoleResponder = "responder"
	RoleViewer    = "viewer"

	MaxTokenTTL = 24 * time.Hour
)

var ErrInvalidToken = errors.New("invalid or expired token")

type TokenClaims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

type TokenManager struct {
	secret []byte
	issuer string
	ttl    time.Duration
}

func NewTokenManager(secret, issuer string, ttl time.Duration) (*TokenManager, error) {
	if len([]byte(secret)) < 32 {
		return nil, errors.New("JWT secret must contain at least 32 bytes")
	}

	if strings.TrimSpace(issuer) == "" {
		return nil, errors.New("JWT issuer is required")
	}

	if ttl <= 0 || ttl > MaxTokenTTL {
		return nil, errors.New("JWT TTL must be between 0 and 24 hours")
	}

	return &TokenManager{
		secret: []byte(secret),
		issuer: issuer,
		ttl:    ttl,
	}, nil
}

func validRole(role string) bool {
	switch role {
	case RoleAdmin, RoleAnalyst, RoleResponder, RoleViewer:
		return true
	default:
		return false
	}
}

// Issue creates a signed JWT for an authenticated user.
func (m *TokenManager) Issue(userID, role string) (string, time.Time, error) {
	if m == nil {
		return "", time.Time{}, errors.New("token manager is not configured")
	}

	if strings.TrimSpace(userID) == "" {
		return "", time.Time{}, errors.New("user ID is required")
	}

	if !validRole(role) {
		return "", time.Time{}, errors.New("invalid user role")
	}

	now := time.Now().UTC()
	expiresAt := now.Add(m.ttl)

	claims := TokenClaims{
		Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(m.secret)
	if err != nil {
		return "", time.Time{}, err
	}

	return signedToken, expiresAt, nil
}

// Verify validates the token signature and registered claims.
func (m *TokenManager) Verify(rawToken string) (*TokenClaims, error) {
	if m == nil || rawToken == "" || len(rawToken) > 8192 {
		return nil, ErrInvalidToken
	}

	claims := &TokenClaims{}

	token, err := jwt.ParseWithClaims(
		rawToken,
		claims,
		func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, ErrInvalidToken
			}
			return m.secret, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(m.issuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)

	if err != nil || token == nil || !token.Valid {
		return nil, ErrInvalidToken
	}

	if claims.Subject == "" ||
		claims.IssuedAt == nil ||
		claims.ExpiresAt == nil ||
		!validRole(claims.Role) {
		return nil, ErrInvalidToken
	}

	return claims, nil
}
