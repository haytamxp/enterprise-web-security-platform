package auth

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

const bcryptMaxPasswordBytes = 72

// HashPassword hashes a password before it is stored in the database.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password is required")
	}

	// bcrypt only supports passwords up to 72 bytes.
	if len([]byte(password)) > bcryptMaxPasswordBytes {
		return "", errors.New("password exceeds bcrypt's 72-byte limit")
	}

	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

// VerifyPassword reports whether the password matches the stored hash.
// Invalid hashes and incorrect passwords both return false.
func VerifyPassword(password, passwordHash string) bool {
	if password == "" || passwordHash == "" {
		return false
	}

	if len([]byte(password)) > bcryptMaxPasswordBytes {
		return false
	}

	return bcrypt.CompareHashAndPassword(
		[]byte(passwordHash),
		[]byte(password),
	) == nil
}
