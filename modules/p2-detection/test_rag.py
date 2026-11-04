from rag_engine import enrich_incident_with_rag
import json

# On simule un incident de Brute Force (comme celui généré par ton corrélateur)
fake_incident = {
    "incident_id": "inc-test-001",
    "title": "Brute Force Detected",
    "severity": "high",
    "description": "5 échecs d'authentification depuis 192.168.1.100",
    "asset_id": "asset-web-01",
    "event_ids": ["evt-1", "evt-2"]
}

print("--- Test du RAG ---")
enriched = enrich_incident_with_rag(fake_incident)
print(json.dumps(enriched, indent=2, ensure_ascii=False))