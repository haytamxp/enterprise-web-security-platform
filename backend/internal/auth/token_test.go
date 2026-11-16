package auth

import (
	"strings"
	"testing"
	"time"
)

func TestNewTokenManagerRejectsWeakSecret(t *testing.T) {
	_, err := NewTokenManager("short-secret", "ewstrp-api", 15*time.Minute)
	if err == nil {
		t.Fatal("expected weak JWT secret to be rejected")
	}
}

func TestNewTokenManagerRejectsInvalidTTL(t *testing.T) {
	secret := strings.Repeat("x", 32)

	_, err := NewTokenManager(secret, "ewstrp-api", 0)
	if err == nil {
		t.Fatal("expected zero TTL to be rejected")
	}

	_, err = NewTokenManager(secret, "ewstrp-api", 25*time.Hour)
	if err == nil {
		t.Fatal("expected excessive TTL to be rejected")
	}
}

func TestTokenIssueAndVerify(t *testing.T) {
	manager, err := NewTokenManager(
		strings.Repeat("s", 32),
		"ewstrp-api",
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("create token manager: %v", err)
	}

	signed, expiresAt, err := manager.Issue("user-123", "00000000-0000-4000-8000-000000000001", RoleAdmin)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	if signed == "" {
		t.Fatal("expected a signed token")
	}

	if !expiresAt.After(time.Now()) {
		t.Fatal("expected future expiration")
	}

	claims, err := manager.Verify(signed)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}

	if claims.Subject != "user-123" {
		t.Fatalf("unexpected subject: %s", claims.Subject)
	}

	if claims.Role != RoleAdmin {
		t.Fatalf("unexpected role: %s", claims.Role)
	}

	if claims.Issuer != "ewstrp-api" {
		t.Fatalf("unexpected issuer: %s", claims.Issuer)
	}
}

func TestTokenRejectsTampering(t *testing.T) {
	manager, err := NewTokenManager(
		strings.Repeat("s", 32),
		"ewstrp-api",
		15*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}

	signed, _, err := manager.Issue("user-123", "00000000-0000-4000-8000-000000000001", RoleAnalyst)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(signed, ".")
	parts[1] = "a" + parts[1][1:]
	tampered := strings.Join(parts, ".")

	if _, err := manager.Verify(tampered); err == nil {
		t.Fatal("expected tampered token to be rejected")
	}
}

func TestTokenRejectsWrongIssuer(t *testing.T) {
	secret := strings.Repeat("s", 32)

	issuerA, err := NewTokenManager(secret, "issuer-a", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	issuerB, err := NewTokenManager(secret, "issuer-b", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	signed, _, err := issuerA.Issue("user-123", "00000000-0000-4000-8000-000000000001", RoleViewer)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := issuerB.Verify(signed); err == nil {
		t.Fatal("expected token from another issuer to be rejected")
	}
}

func TestTokenRejectsExpiredToken(t *testing.T) {
	manager, err := NewTokenManager(
		strings.Repeat("s", 32),
		"ewstrp-api",
		time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}

	signed, _, err := manager.Issue("user-123", "00000000-0000-4000-8000-000000000001", RoleResponder)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(20 * time.Millisecond)

	if _, err := manager.Verify(signed); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestTokenRejectsInvalidRole(t *testing.T) {
	manager, err := NewTokenManager(
		strings.Repeat("s", 32),
		"ewstrp-api",
		15*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := manager.Issue("user-123", "00000000-0000-4000-8000-000000000001", "superuser"); err == nil {
		t.Fatal("expected invalid role to be rejected")
	}
}
