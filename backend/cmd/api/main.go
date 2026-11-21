package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/api"
	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/database"
)

// @title           Orchid WebShield P3 API
// @version         1.0
// @description     Security API pour la plateforme Orchid WebShield.
// @host            localhost:8080
// @BasePath        /api/v1
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Tapez "Bearer " suivi de votre token JWT.
func main() {
	// 1. Charger les variables d'environnement
	_ = godotenv.Load("../.env")
	_ = godotenv.Load("../../.env")

	// 2. Connexion à la base de données
	if err := database.Connect(); err != nil {
		log.Fatalf("Erreur fatale DB: %v", err)
	}
	log.Println("✅ Connecté à PostgreSQL")

	// 3. Configuration du serveur HTTP
	router := api.NewRouter()
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}

	log.Printf("🚀 Serveur démarré sur http://%s", addr)
	log.Printf("📚 Swagger UI: http://%s/swagger/index.html", addr)

	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("Erreur serveur: %v", err)
	}
}