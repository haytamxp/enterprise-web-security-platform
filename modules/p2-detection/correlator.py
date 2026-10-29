import time
import uuid

class IncidentCorrelator:
    def __init__(self, time_window_seconds=300):
        self.time_window = time_window_seconds
        self.event_history = [] 

    def _clean_old_events(self):
        now = time.time()
        self.event_history = [
            ev for ev in self.event_history 
            if now - ev['internal_timestamp'] < self.time_window
        ]

    def process_event(self, event):
        event['internal_timestamp'] = time.time()
        self.event_history.append(event)
        self._clean_old_events()

        # --- RÈGLE A : Brute Force (5 échecs d'authentification) ---
        # On cherche les mots-clés "failed", "failure", "authentication failed", etc.
        sig_lower = event['signature'].lower()
        is_auth_failure = any(keyword in sig_lower for keyword in ["authentication fail", "failed password", "user login failed"])
        
        if is_auth_failure:
            # Compter combien d'échecs on a pour la même IP source
            failures = [ev for ev in self.event_history 
                        if ev['src_ip'] == event['src_ip'] 
                        and any(kw in ev['signature'].lower() for kw in ["authentication fail", "failed password", "user login failed"])]
            
            if len(failures) >= 5:
                incident = self._generate_incident(
                    title="Brute Force Detected",
                    description=f"{len(failures)} échecs d'authentification depuis {event['src_ip']}",
                    severity="high",
                    events=failures
                )
                # On vide l'historique pour ne pas recréer le même incident
                self.event_history = [ev for ev in self.event_history if ev['src_ip'] != event['src_ip']]
                return incident

        # --- RÈGLE B : Alerte critique (niveau 5) ---
        if event['severity'] >= 5 and event['asset_id'] != "unknown-asset":
            incident = self._generate_incident(
                title="Critical Vulnerability Exploited",
                description=f"Alerte critique détectée sur {event['asset_id']} : {event['signature']}",
                severity="critical",
                events=[event]
            )
            return incident

        return None

    def _generate_incident(self, title, description, severity, events):
        correlation_id = f"corr-{uuid.uuid4().hex[:8]}"
        
        for ev in events:
            ev['correlation_id'] = correlation_id

        incident = {
            "incident_id": f"inc-{uuid.uuid4().hex[:8]}",
            "schema_version": "1.0",
            "asset_id": events[0]['asset_id'],
            "timestamp": events[-1]['timestamp'],
            "severity": severity,
            "confidence": 0.90,
            "title": title,
            "correlation_id": correlation_id,
            "event_ids": [ev['event_id'] for ev in events],
            "description": description,
            "playbook_ref": None,
            "status": "open"
        }
        return incident