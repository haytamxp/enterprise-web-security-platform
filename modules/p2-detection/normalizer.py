import json
import uuid
from datetime import datetime

# 1. Charger la table des actifs
with open('asset_map.json', 'r') as f:
    ASSET_MAP = json.load(f)

def get_asset_id(ip_or_domain):
    """Retourne l'ID de l'actif ou 'unknown-asset' si non trouvé"""
    return ASSET_MAP.get(ip_or_domain, "unknown-asset")

def normalize_suricata_event(raw_event):
    """
    Prend un événement EVE JSON de Suricata (dictionnaire) 
    et le transforme selon le contrat P2 -> P3.
    """
    # Vérifier si c'est bien une alerte
    if raw_event.get("event_type") != "alert":
        return None

    alert_info = raw_event.get("alert", {})
    
    # Création de l'événement normalisé
    normalized = {
        "event_id": f"evt-{uuid.uuid4().hex[:12]}",
        "schema_version": "1.0",
        "source_product": "suricata",
        "event_type": "alert",
        "asset_id": get_asset_id(raw_event.get("dest_ip")),
        "timestamp": raw_event.get("timestamp"),
        "severity": alert_info.get("severity", 3), 
        "confidence": 0.90, # Valeur par défaut pour Suricata
        "correlation_id": None,
        "src_ip": raw_event.get("src_ip"),
        "dest_ip": raw_event.get("dest_ip"),
        "rule_id": str(alert_info.get("signature_id")),
        "signature": alert_info.get("signature"),
        "description": alert_info.get("category", ""),
        "raw_ref": None
    }
    
    return normalized

# --- TEST RAPIDE (Simule une lecture de log) ---
if __name__ == "__main__":
    # Copiez-collez ici l'une des alertes JSON que vous avez vues dans le Dashboard Wazuh
    # (ou utilisez celle-ci comme exemple)
    example_suricata_alert = {
        "timestamp": "2026-10-24T10:55:35.467815-0400",
        "event_type": "alert",
        "src_ip": "192.168.116.129",
        "dest_ip": "192.168.116.254",
        "alert": {
            "signature_id": 2022973,
            "signature": "ET INFO Possible Kali Linux hostname in DHCP Request Packet",
            "severity": 1
        }
    }

    result = normalize_suricata_event(example_suricata_alert)
    print("--- Événement Normalisé ---")
    print(json.dumps(result, indent=2))