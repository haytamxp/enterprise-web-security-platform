import requests
import json
import urllib3
from normalizer import normalize_wazuh_alert
from deduplicator import EventDeduplicator
from correlator import IncidentCorrelator # <-- Nouvel import

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INDEXER_URL = "https://192.168.100.52:9200"
INDEXER_USER = "admin"
INDEXER_PASS = "admin"

def get_alerts_from_wazuh(limit=10):
    # ... (garde la même fonction que tout à l'heure) ...
    url = f"{INDEXER_URL}/wazuh-alerts-*/_search?size={limit}&sort=timestamp:desc"
    try:
        response = requests.get(url, auth=(INDEXER_USER, INDEXER_PASS), verify=False)
        if response.status_code == 200:
            hits = response.json().get('hits', {}).get('hits', [])
            return [hit['_source'] for hit in hits]
    except Exception as e:
        print(f"Erreur: {e}")
    return []

if __name__ == "__main__":
    print("--- Démarrage du Pipeline P2 ---")
    dedup = EventDeduplicator(window_seconds=60)
    correlator = IncidentCorrelator(time_window_seconds=300) # 5 minutes de fenêtre
    
    # Augmente le limit à 50 pour avoir plus de données à corréler
    raw_alerts = get_alerts_from_wazuh(limit=50) 
    print(f"{len(raw_alerts)} alertes brutes récupérées.\n")
    
    incidents_generated = 0

    for raw in raw_alerts:
        # 1. Normalisation
        normalized_event = normalize_wazuh_alert(raw)
        
        # 2. Déduplication (on ignore les événements trop répétitifs)
        if not dedup.is_duplicate(normalized_event):
            
            # 3. Corrélation
            incident = correlator.process_event(normalized_event)
            
            if incident:
                # Si un incident est généré, on l'envoie à P3 !
                print("\n" + "="*50)
                print(f"🚨 INCIDENT GÉNÉRÉ : {incident['title']}")
                print(f"   Sévérité : {incident['severity'].upper()}")
                print(f"   Description : {incident['description']}")
                print(f"   Nombre d'événements liés : {len(incident['event_ids'])}")
                print(f"   [P3] Envoi de l'incident {incident['incident_id']} à l'API...")
                print("="*50 + "\n")
                incidents_generated += 1
            else:
                print(f"[Événement normalisé] {normalized_event['signature']}")

    print(f"\n--- Fin du pipeline. {incidents_generated} incidents générés. ---")