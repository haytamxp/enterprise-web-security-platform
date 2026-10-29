import json
from correlator import IncidentCorrelator

# On crée une instance du corrélateur (fenêtre de 5 minutes)
correlator = IncidentCorrelator(time_window_seconds=300)

# On simule 5 échecs de connexion depuis la même IP
print("--- Simulation de 5 échecs de connexion ---")
incident = None

for i in range(5):
    # Faux événement normalisé (comme si Wazuh l'avait généré)
    event = {
        "event_id": f"evt-test-{i}",
        "schema_version": "1.0",
        "source_product": "wazuh",
        "event_type": "alert",
        "asset_id": "asset-web-01",
        "timestamp": f"2026-10-29T16:00:0{i}Z",
        "severity": 3,
        "confidence": 0.85,
        "correlation_id": None,
        "src_ip": "192.168.1.100",
        "dest_ip": "192.168.1.50",
        "rule_id": "5710",
        "signature": "sshd: authentication failed",
        "description": "Failed password for invalid user",
        "raw_ref": None
    }
    
    # On passe l'événement au corrélateur
    incident = correlator.process_event(event)
    
    if incident:
        print(f"✅ Incident généré après {i+1} échecs !")
        break
    else:
        print(f"   Événement {i+1} traité... (pas encore d'incident)")

if incident:
    print("\n--- DÉTAILS DE L'INCIDENT ---")
    print(json.dumps(incident, indent=2))
else:
    print("\n❌ Aucun incident généré. Vérifie la logique du corrélateur.")