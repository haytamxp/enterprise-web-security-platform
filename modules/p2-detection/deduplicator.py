import time

class EventDeduplicator:
    def __init__(self, window_seconds=60):
        self.window_seconds = window_seconds
        self.seen_events = {} 

    def is_duplicate(self, event):
        # La clé est basée sur l'actif, la règle et la signature
        key = f"{event['asset_id']}_{event['rule_id']}_{event['signature']}"
        now = time.time()
        
        # Nettoyer les vieux événements
        self.seen_events = {k: v for k, v in self.seen_events.items() if now - v < self.window_seconds}
        
        if key in self.seen_events:
            self.seen_events[key] = now # On prolonge la fenêtre
            return True
        else:
            self.seen_events[key] = now
            return False