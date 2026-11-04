import os
import json
import requests
import urllib3
from dotenv import load_dotenv
from normalizer import normalize_wazuh_alert
from deduplicator import EventDeduplicator
from correlator import IncidentCorrelator
from rag_engine import enrich_incident_with_rag

# Charger les variables d'environnement
load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://192.168.100.52:9200")
INDEXER_USER = os.getenv("WAZUH_USER", "admin")
INDEXER_PASS = os.getenv("WAZUH_PASSWORD", "admin")

def get_alerts_from_wazuh(limit=50):
    url = f"{INDEXER_URL}/wazuh-alerts-*/_search?size={limit}&sort=timestamp:desc"
    try:
        response = requests.get(url, auth=(INDEXER_USER, INDEXER_PASS), verify=False, timeout=10)
        if response.status_code == 200:
            hits = response.json().get('hits', {}).get('hits', [])
            return [hit['_source'] for hit in hits]
    except Exception as e:
        print(f"Erreur Wazuh: {e}")
    return []

def send_incident_to_p3(incident):
    print(f"\n📤 [ENVOI P3] Incident {incident['incident_id']}")
    print(f"   Titre : {incident['title']}")
    print(f"   Sévérité : {incident['severity']}")
    print(f"   Recommandation IA : {incident['ai_recommendation'][:100]}...")

if __name__ == "__main__":
    print("--- 🚀 Démarrage du Pipeline P2 ---")
    dedup = EventDeduplicator(window_seconds=60)
    correlator = IncidentCorrelator(time_window_seconds=300)
    
    raw_alerts = get_alerts_from_wazuh()
    print(f"🔍 {len(raw_alerts)} alertes récupérées.\n")
    
    incidents_generated = 0

    for raw in raw_alerts:
        normalized_event = normalize_wazuh_alert(raw)
        
        if not dedup.is_duplicate(normalized_event):
            incident = correlator.process_event(normalized_event)
            
            if incident:
                incidents_generated += 1
                print("\n" + "="*60)
                print(f"🚨 INCIDENT GÉNÉRÉ : {incident['title']}")
                
                # Enrichissement avec l'IA (RAG)
                print("🤖 Analyse IA en cours...")
                incident = enrich_incident_with_rag(incident)
                
                # Envoi P3
                send_incident_to_p3(incident)
                print("="*60 + "\n")

    print(f"--- Fin. {incidents_generated} incidents traités. ---")