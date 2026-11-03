#!/usr/bin/env python3
"""
Scan passif de baseline — mesure le comportement RÉEL d'un site autorisé,
avant tout scan actif, pour calibrer le Circuit Breaker sur des données
vraies plutôt que sur des suppositions.

Caractère "passif" de ce scan :
- Requêtes GET simples, comme un visiteur normal (pas de fuzzing, pas
  de payload, pas de scan de ports)
- Requêtes espacées dans le temps (pas de rafale), pour observer le
  comportement naturel du site, pas un comportement sous charge
- Passe quand même par le Scope Manager avant d'envoyer quoi que ce
  soit, par cohérence avec le reste du projet
"""

from __future__ import annotations

import json
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

from core import charger_whitelist
from scope_manager import is_authorized
from circuit_breaker import etablir_baseline, calibrer_seuils

BASELINE_FILE = Path(__file__).resolve().parent / "data" / "baseline.json"


def mesurer_une_requete(url: str, timeout_secondes: float = 10.0) -> float | None:
    """
    Envoie UNE requête GET légère et retourne le temps de réponse en ms.
    Retourne None si la requête échoue (timeout, erreur réseau) — on
    exclut ces cas de la baseline plutôt que de les compter comme "0ms",
    ce qui fausserait complètement la moyenne.
    """
    debut = time.monotonic()
    try:
        requete = urllib.request.Request(url, headers={"User-Agent": "Pentest-P1-BaselineScan"})
        with urllib.request.urlopen(requete, timeout=timeout_secondes) as reponse:
            reponse.read()  # on consomme la réponse, sans l'analyser
        fin = time.monotonic()
        return (fin - debut) * 1000  # conversion en millisecondes
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        print(f"    ⚠️  Requête échouée : {e}")
        return None


def scan_baseline(url: str, nombre_requetes: int = 20, delai_secondes: float = 3.0) -> None:
    print("=" * 60)
    print("Scan passif de baseline")
    print("=" * 60)

    # Garde-fou : même un scan passif passe par le Scope Manager.
    whitelist = charger_whitelist()
    autorise, raison = is_authorized(url, whitelist)
    if not autorise:
        print(f"\n❌ REFUSÉ par le Scope Manager : {raison}")
        print("Aucune requête n'a été envoyée.")
        return

    print(f"\n✅ Autorisé : {raison}")
    print(f"\nEnvoi de {nombre_requetes} requêtes légères vers {url}, "
          f"espacées de {delai_secondes}s (durée totale estimée : "
          f"~{nombre_requetes * delai_secondes / 60:.1f} min)\n")

    mesures: list[float] = []
    for i in range(1, nombre_requetes + 1):
        temps_ms = mesurer_une_requete(url)
        if temps_ms is not None:
            mesures.append(temps_ms)
            print(f"  [{i}/{nombre_requetes}] {temps_ms:.0f} ms")
        else:
            print(f"  [{i}/{nombre_requetes}] échec (exclu de la baseline)")

        if i < nombre_requetes:
            time.sleep(delai_secondes)

    if len(mesures) < 2:
        print("\n❌ Pas assez de mesures valides pour établir une baseline fiable.")
        return

    baseline = etablir_baseline(mesures)
    seuil_degrade_ms, seuil_critique_ms = calibrer_seuils(baseline)

    print("\n" + "=" * 60)
    print("Résultat de la calibration")
    print("=" * 60)
    print(f"Échantillons valides   : {baseline.nombre_echantillons}")
    print(f"Moyenne                : {baseline.moyenne_ms:.1f} ms")
    print(f"Écart-type (variabilité): {baseline.ecart_type_ms:.1f} ms")
    print(f"Seuil DÉGRADÉ           : {seuil_degrade_ms:.1f} ms")
    print(f"Seuil CRITIQUE          : {seuil_critique_ms:.1f} ms")

    # Sauvegarde pour réutilisation par le Circuit Breaker plus tard,
    # sans avoir à refaire ce scan à chaque fois.
    BASELINE_FILE.parent.mkdir(exist_ok=True)
    donnees = {
        "target": url,
        "timestamp": datetime.now().isoformat(),
        "nombre_echantillons": baseline.nombre_echantillons,
        "moyenne_ms": baseline.moyenne_ms,
        "ecart_type_ms": baseline.ecart_type_ms,
        "seuil_degrade_ms": seuil_degrade_ms,
        "seuil_critique_ms": seuil_critique_ms,
    }
    with BASELINE_FILE.open("w", encoding="utf-8") as f:
        json.dump(donnees, f, indent=2, ensure_ascii=False)

    print(f"\n✅ Baseline enregistrée dans {BASELINE_FILE.name}")


if __name__ == "__main__":
    url = input("URL à mesurer (ex: https://orchidisland.immo/) : ").strip()
    scan_baseline(url)