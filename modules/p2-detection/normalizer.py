import json
import uuid

# Table de correspondance des actifs
with open('asset_map.json', 'r') as f:
    ASSET_MAP = json.load(f)

def get_asset_id(ip):
    return ASSET_MAP.get(ip, "unknown-asset")

def normalize_wazuh_alert(raw_alert):
    """
    Transforme une alerte brute de Wazuh (peu importe la source)
    selon le contrat P2 -> P3.
    """
    rule = raw_alert.get('rule', {})
    data = raw_alert.get('data', {})
    
    # 1. Détecter la source (Suricata ou Wazuh système)
    decoder = raw_alert.get('decoder', {}).get('name', '').lower()
    source_product = "suricata" if "suricata" in decoder or "json" in decoder else "wazuh"
    
    # 2. Extraire les IPs si elles existent
    src_ip = data.get('srcip') or data.get('src_ip')
    dest_ip = data.get('dstip') or data.get('dest_ip') or data.get('dstuser')
    
    # 3. Convertir le niveau Wazuh (0-15) en sévérité (1-5)
    wazuh_level = rule.get('level', 1)
    severity = min(5, max(1, wazuh_level // 2))
    
    # 4. Construire l'événement normalisé (conforme au contrat P3)
    normalized = {
        "event_id": f"evt-{uuid.uuid4().hex[:12]}",
        "schema_version": "1.0",
        "source_product": source_product,
        "event_type": "alert", 
        "asset_id": get_asset_id(dest_ip),
        "timestamp": raw_alert.get('timestamp'),
        "severity": severity,
        "confidence": 0.85, # Valeur par défaut
        "correlation_id": None,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "rule_id": str(rule.get('id')),
        "signature": rule.get('description'),
        "description": rule.get('description'),
        "raw_ref": raw_alert.get('id')
    }
    
    return normalized