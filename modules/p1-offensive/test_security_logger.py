
import json
from datetime import datetime
from pathlib import Path

from security_logger import enregistrer_evenement


def test_enregistrer_evenement(tmp_path):
    # Utiliser un fichier temporaire pour ne pas toucher aux vrais logs
    fichier_test = tmp_path / "logs" / "test.jsonl"

    # Premier événement
    enregistrer_evenement(
        event="circuit_breaker_state_change",
        details={
            "previous_state": "NORMAL",
            "new_state": "DEGRADE",
            "reason": "latency_threshold_exceeded"
        },
        fichier=fichier_test
    )

    # Vérifier que le fichier existe
    assert fichier_test.exists()

    # Lire et vérifier le contenu
    lignes = fichier_test.read_text(encoding="utf-8").splitlines()

    assert len(lignes) == 1

    evenement = json.loads(lignes[0])

    assert evenement["event"] == "circuit_breaker_state_change"
    assert evenement["details"]["new_state"] == "DEGRADE"

    # Vérifier que le timestamp est valide et contient un fuseau horaire
    timestamp = datetime.fromisoformat(evenement["timestamp"])
    assert timestamp.tzinfo is not None

    # Ajouter un deuxième événement
    enregistrer_evenement(
        event="circuit_breaker_incident",
        details={"reason": "server_unreachable"},
        fichier=fichier_test
    )

    # Vérifier que le premier événement n'a pas été écrasé
    lignes = fichier_test.read_text(encoding="utf-8").splitlines()
    assert len(lignes) == 2
