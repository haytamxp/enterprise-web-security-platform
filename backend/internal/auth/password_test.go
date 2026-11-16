package auth

import "testing"

func TestHashAndVerifyPassword(t *testing.T) {
	password := "Example-Strong-Password-2026!"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	if hash == password {
		t.Fatal("password must not be stored as plaintext")
	}

	if !VerifyPassword(password, hash) {
		t.Fatal("VerifyPassword() rejected the correct password")
	}

	if VerifyPassword("Wrong-Password-2026!", hash) {
		t.Fatal("VerifyPassword() accepted an incorrect password")
	}
}

func TestHashPasswordRejectsInvalidInput(t *testing.T) {
	if _, err := HashPassword(""); err == nil {
		t.Fatal("HashPassword() accepted an empty password")
	}

	longPassword := make([]byte, 73)
	for i := range longPassword {
		longPassword[i] = 'a'
	}

	if _, err := HashPassword(string(longPassword)); err == nil {
		t.Fatal("HashPassword() accepted a password longer than 72 bytes")
	}
}

func TestVerifyPasswordRejectsInvalidInput(t *testing.T) {
	if VerifyPassword("", "some-hash") {
		t.Fatal("VerifyPassword() accepted an empty password")
	}

	if VerifyPassword("some-password", "") {
		t.Fatal("VerifyPassword() accepted an empty hash")
	}

	if VerifyPassword("some-password", "not-a-valid-bcrypt-hash") {
		t.Fatal("VerifyPassword() accepted an invalid hash")
	}
}
