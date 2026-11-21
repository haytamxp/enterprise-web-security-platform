package models

import "time"

// Incident représente un incident envoyé par P2
type Incident struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Source      string    `json:"source"`
	CreatedAt   time.Time `json:"created_at"`
}

// User représente un utilisateur de la plateforme P3
type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
	Role         string `json:"role"`
}