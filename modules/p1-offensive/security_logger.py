
#!/usr/bin/env python3
"""
Security Logger — journalisation des événements de sécurité.

Responsabilités :
- Enregistrer les événements du Circuit Breaker.
- Conserver les informations au format JSONL.
- Ajouter automatiquement un timestamp UTC.
- Créer le dossier de logs s'il n'existe pas.
- Ne pas mélanger les logs avec ceux du Scope Manager.
- Garantir une écriture cohérente entre threads.
- Refuser les données qui ne peuvent pas être sérialisées en JSON strict.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
CIRCUIT_BREAKER_LOG = LOG_DIR / "circuit_breaker.jsonl"

# Protège les écritures concurrentes au sein du processus.
_LOG_LOCK = threading.Lock()


def enregistrer_evenement(
    event: str,
    details: dict[str, Any],
    fichier: Path = CIRCUIT_BREAKER_LOG,
) -> None:
    """
    Ajoute un événement dans un fichier JSONL.

    Les erreurs de validation, de sérialisation ou d'écriture
    sont propagées à l'appelant. Elles ne doivent pas être ignorées
    par le composant de sécurité qui utilise ce logger.
    """

    if not isinstance(event, str) or not event.strip():
        raise ValueError("Le nom de l'événement doit être une chaîne non vide.")

    if not isinstance(details, dict):
        raise TypeError("Les détails de l'événement doivent être un dictionnaire.")

    if not isinstance(fichier, (str, Path)):
        raise TypeError("Le chemin du fichier de log doit être une chaîne ou un Path.")

    chemin = Path(fichier)

    evenement = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "details": details,
    }

    # Sérialisation avant ouverture du fichier :
    # une donnée invalide ne doit pas créer une ligne JSONL partielle.
    ligne = json.dumps(
        evenement,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ) + "\n"

    with _LOG_LOCK:
        chemin.parent.mkdir(parents=True, exist_ok=True)

        with chemin.open("a", encoding="utf-8", newline="\n") as log_file:
            log_file.write(ligne)
            log_file.flush()
