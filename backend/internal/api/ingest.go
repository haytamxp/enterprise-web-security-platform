package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/database"
)

// @Summary      Ingestion d'incident P2
// @Description  Reçoit un incident envoyé par le module P2 et le stocke en base
// @Tags         Ingestion
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        incident body map[string]interface{} true "Incident P2"
// @Success      201 {object} map[string]string
// @Failure      400 {string} string "JSON invalide"
// @Router       /incidents [post]
func CreateIncidentHandler(w http.ResponseWriter, r *http.Request) {
	var payload map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "JSON invalide", http.StatusBadRequest)
		return
	}

	// On extrait les données envoyées par P2
	title, _ := payload["title"].(string)
	severity, _ := payload["severity"].(string)
	description, _ := payload["description"].(string)

	// On récupère un tenant_id existant (le premier trouvé)
	var tenantID string
	err := database.DB.QueryRow("SELECT tenant_id FROM tenants LIMIT 1").Scan(&tenantID)
	if err != nil {
		http.Error(w, "Aucun tenant trouvé dans la base", http.StatusInternalServerError)
		return
	}

	// On génère des valeurs par défaut pour les champs obligatoires manquants
	correlationID := fmt.Sprintf("corr-%d", time.Now().Unix())
	occurredAt := time.Now()
	
	// On prépare la requête SQL avec TOUTES les colonnes obligatoires
	query := `INSERT INTO incidents (
		incident_id, schema_version, asset_id, occurred_at, severity, 
		confidence, title, correlation_id, description, tenant_id
	) VALUES (
		gen_random_uuid(), '1.0', 'asset-default', $1, $2, 
		0.85, $3, $4, $5, $6
	) RETURNING id`

	var newID int64
	err = database.DB.QueryRow(query, 
		occurredAt, severity, title, correlationID, description, tenantID,
	).Scan(&newID)

	if err != nil {
		http.Error(w, fmt.Sprintf("Erreur DB: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status":      "success",
		"incident_id": fmt.Sprintf("%d", newID),
	})
}