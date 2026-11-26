
#!/usr/bin/env python3
"""
Scan passif de baseline — mesure le comportement réel
d'une cible autorisée avant tout scan actif.

Toutes les validations passent par Target Gate.

Caractéristiques :
- Requêtes GET simples.
- Requêtes espacées.
- Confirmation humaine obligatoire.
- Contrôle du périmètre avant chaque opération.
- Contrôle de chaque redirection HTTP.
- Refus des redirections hors périmètre.
"""

from __future__ import annotations

import json
import time
import urllib.request
import urllib.error

from datetime import datetime, timezone
from pathlib import Path

from core import charger_whitelist
from target_gate import validate_target
from circuit_breaker import etablir_baseline, calibrer_seuils


BASELINE_FILE = (
    Path(__file__).resolve().parent
    / "data"
    / "baseline.json"
)


class TargetRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    Contrôle chaque redirection avec le Target Gate.

    La confirmation humaine initiale est conservée pendant
    toute la chaîne de redirections.
    """

    def __init__(self, whitelist):
        super().__init__()
        self.whitelist = whitelist

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl
    ):

        autorise, raison = validate_target(
            url=newurl,
            user_confirmed=True,
            whitelist=self.whitelist
        )

        if not autorise:
            raise urllib.error.HTTPError(
                req.full_url,
                code,
                f"Redirection refusée par Target Gate : {raison}",
                headers,
                fp
            )

        return super().redirect_request(
            req,
            fp,
            code,
            msg,
            headers,
            newurl
        )

# Compatibilité avec les anciens tests
ScopeRedirectHandler = TargetRedirectHandler
def mesurer_une_requete(
    url: str,
    whitelist,
    timeout_secondes: float = 10.0
) -> float | None:
    """
    Envoie une requête GET légère.

    Les redirections sont contrôlées avant leur suivi.
    Retourne le temps de réponse en millisecondes.
    """

    debut = time.monotonic()

    try:

        requete = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Pentest-P1-BaselineScan"
            }
        )

        opener = urllib.request.build_opener(
            TargetRedirectHandler(whitelist)
        )

        with opener.open(
            requete,
            timeout=timeout_secondes
        ) as reponse:

            reponse.read()

        fin = time.monotonic()

        return (fin - debut) * 1000

    except (
        urllib.error.URLError,
        urllib.error.HTTPError,
        TimeoutError,
        ValueError
    ) as e:

        print(f"    Requête échouée : {e}")

        return None


def scan_baseline(
    url: str,
    nombre_requetes: int = 20,
    delai_secondes: float = 3.0,
    user_confirmed: bool = False
) -> None:

    print("=" * 60)
    print("Scan passif de baseline — Target Gate")
    print("=" * 60)

    # Validation des paramètres.
    if not isinstance(nombre_requetes, int) or nombre_requetes < 2:
        print("\nREFUSÉ : au moins deux requêtes sont nécessaires.")
        return

    if not isinstance(delai_secondes, (int, float)) or delai_secondes < 0:
        print("\nREFUSÉ : délai invalide.")
        return

    # Chargement de la whitelist.
    try:
        whitelist = charger_whitelist()

    except Exception as e:
        print(f"\nREFUSÉ : impossible de charger la whitelist : {e}")
        return

    # Validation centrale obligatoire.
    autorise, raison = validate_target(
        url=url,
        user_confirmed=user_confirmed,
        whitelist=whitelist
    )

    if not autorise:
        print(f"\nREFUSÉ par Target Gate : {raison}")
        print("Aucune requête HTTP n'a été envoyée.")
        return

    print(f"\nCible validée : {raison}")

    print(
        f"\nEnvoi de {nombre_requetes} requêtes légères vers {url}, "
        f"espacées de {delai_secondes}s."
    )

    mesures: list[float] = []

    for i in range(1, nombre_requetes + 1):

        temps_ms = mesurer_une_requete(
            url,
            whitelist
        )

        if temps_ms is not None:

            mesures.append(temps_ms)

            print(
                f"  [{i}/{nombre_requetes}] "
                f"{temps_ms:.0f} ms"
            )

        else:

            print(
                f"  [{i}/{nombre_requetes}] "
                "échec (exclu de la baseline)"
            )

        if i < nombre_requetes:
            time.sleep(delai_secondes)

    # Vérification des mesures.
    if len(mesures) < 2:

        print(
            "\nPas assez de mesures valides "
            "pour établir une baseline fiable."
        )

        return

    # Calibration du Circuit Breaker.
    baseline = etablir_baseline(mesures)

    seuil_degrade_ms, seuil_critique_ms = (
        calibrer_seuils(baseline)
    )

    print("\n" + "=" * 60)
    print("Résultat de la calibration")
    print("=" * 60)

    print(f"Échantillons valides : {baseline.nombre_echantillons}")
    print(f"Moyenne : {baseline.moyenne_ms:.1f} ms")
    print(f"Écart-type : {baseline.ecart_type_ms:.1f} ms")
    print(f"Seuil DÉGRADÉ : {seuil_degrade_ms:.1f} ms")
    print(f"Seuil CRITIQUE : {seuil_critique_ms:.1f} ms")

    # Sauvegarde.
    BASELINE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    donnees = {
        "target": url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "nombre_echantillons": baseline.nombre_echantillons,
        "moyenne_ms": baseline.moyenne_ms,
        "ecart_type_ms": baseline.ecart_type_ms,
        "seuil_degrade_ms": seuil_degrade_ms,
        "seuil_critique_ms": seuil_critique_ms,
    }

    with BASELINE_FILE.open(
        "w",
        encoding="utf-8"
    ) as fichier:

        json.dump(
            donnees,
            fichier,
            indent=2,
            ensure_ascii=False
        )

    print(f"\nBaseline enregistrée dans : {BASELINE_FILE}")


if __name__ == "__main__":

    url = input(
        "URL à mesurer (ex: https://orchidisland.immo/) : "
    ).strip()

    confirmation = input(
        "\nConfirmez-vous disposer d'une autorisation écrite "
        "valide pour mesurer cette cible ? (oui/non) : "
    ).strip().lower()

    user_confirmed = confirmation in ("oui", "o", "yes", "y")

    scan_baseline(
        url=url,
        user_confirmed=user_confirmed
    )
