import requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# L'Indexer écoute sur le port 9200
INDEXER_URL = "https://192.168.100.52:9200"
INDEXER_USER = "admin"
INDEXER_PASS = "admin"

def fetch_alerts_from_indexer(limit=5):
    """Interroge l'Indexer Wazuh pour récupérer les dernières alertes"""
    # On cherche dans les index wazuh-alerts-*, on trie par date décroissante
    url = f"{INDEXER_URL}/wazuh-alerts-*/_search?size={limit}&sort=timestamp:desc"
    
    try:
        response = requests.get(
            url, 
            auth=(INDEXER_USER, INDEXER_PASS), # Authentification basique
            verify=False
        )
        
        if response.status_code == 200:
            data = response.json()
            hits = data.get('hits', {}).get('hits', [])
            # On extrait le champ _source qui contient la vraie alerte
            return [hit['_source'] for hit in hits]
        else:
            print(f"Erreur Indexer ({response.status_code}): {response.text}")
            return []
    except Exception as e:
        print(f"Erreur de connexion à l'Indexer: {e}")
        return []

if __name__ == "__main__":
    print("Récupération des alertes depuis l'Indexer Wazuh...")
    alerts = fetch_alerts_from_indexer()
    
    print(f"{len(alerts)} alertes trouvées.\n")
    for alert in alerts:
        rule = alert.get('rule', {})
        print(f"Date: {alert.get('timestamp')}")
        print(f"Agent: {alert.get('agent', {}).get('name')}")
        print(f"Règle: {rule.get('description')} (Niveau: {rule.get('level')})")
        print("-" * 40)