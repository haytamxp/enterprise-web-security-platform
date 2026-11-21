package api

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/database"
)

// @Summary      Connexion utilisateur
// @Description  Authentifie un utilisateur et retourne un token JWT
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        credentials body map[string]string true "Email et mot de passe"
// @Success      200 {object} map[string]string
// @Failure      401 {string} string "Identifiants invalides"
// @Router       /auth/login [post]
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Requête JSON invalide", http.StatusBadRequest)
		return
	}

	var dbPasswordHash string
	err := database.DB.QueryRow("SELECT password_hash FROM users WHERE email = $1", req.Email).Scan(&dbPasswordHash)
	if err != nil {
		http.Error(w, "Identifiants invalides", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(dbPasswordHash), []byte(req.Password)); err != nil {
		http.Error(w, "Identifiants invalides", http.StatusUnauthorized)
		return
	}

	secret := []byte(os.Getenv("JWT_SECRET"))
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": req.Email,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})
	tokenString, _ := token.SignedString(secret)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

// @Summary      Inscription utilisateur
// @Description  Crée un nouvel utilisateur dans la base de données
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        credentials body map[string]string true "Email, mot de passe et rôle (admin/analyst)"
// @Success      201 {object} map[string]string
// @Failure      400 {string} string "Données invalides"
// @Failure      409 {string} string "Email déjà utilisé"
// @Router       /auth/register [post]
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Requête JSON invalide", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email et mot de passe requis", http.StatusBadRequest)
		return
	}

	if req.Role == "" {
		req.Role = "analyst"
	}

	// 1. Récupérer un tenant_id existant (le premier trouvé)
	var tenantID string
	err := database.DB.QueryRow("SELECT tenant_id FROM tenants LIMIT 1").Scan(&tenantID)
	if err != nil {
		http.Error(w, "Aucun tenant trouvé dans la base de données", http.StatusInternalServerError)
		return
	}

	// 2. Hacher le mot de passe
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Erreur lors du hachage du mot de passe", http.StatusInternalServerError)
		return
	}

	// 3. Insérer l'utilisateur avec le tenant_id
	query := `INSERT INTO users (email, password_hash, role, tenant_id) VALUES ($1, $2, $3, $4) RETURNING user_id`
	var newID string
	err = database.DB.QueryRow(query, req.Email, string(hashedPassword), req.Role, tenantID).Scan(&newID)

	if err != nil {
		// On affiche la vraie erreur pour comprendre
		http.Error(w, "Erreur DB: "+err.Error(), http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Utilisateur créé avec succès",
		"user_id": newID,
	})
}