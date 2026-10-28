#!/usr/bin/env python3
"""
Logique partagée entre la CLI (cli.py) et le dashboard web (app.py).

Pourquoi ce fichier existe : pour que la logique "charger la whitelist" et
"journaliser une vérification" n'existe qu'à UN SEUL endroit. Si on avait
laissé ce code dupliqué dans cli.py ET app.py, un correctif appliqué dans
l'un des deux aurait facilement pu être oublié dans l'autre.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path

from scope_manager import ScopeEntry

WHITELIST_FILE = Path(__file__).resolve().parent / "whitelist.json"
LOG_FILE = Path(__file__).resolve().parent / "scope_manager.log"


def charger_whitelist() -> list[ScopeEntry]:
    """Lit whitelist.json et le transforme en objets ScopeEntry."""
    with WHITELIST_FILE.open("r", encoding="utf-8") as f:
        donnees = json.load(f)

    whitelist = []
    for entree in donnees:
        whitelist.append(
            ScopeEntry(
                domain=entree["domain"],
                include_subdomains=entree.get("include_subdomains", False),
                excluded_paths=entree.get("excluded_paths", []),
                excluded_subdomains=entree.get("excluded_subdomains", []),
                authorized_from=date.fromisoformat(entree["authorized_from"])
                if entree.get("authorized_from") else None,
                authorized_until=date.fromisoformat(entree["authorized_until"])
                if entree.get("authorized_until") else None,
                authorized_by=entree.get("authorized_by", ""),
                notes=entree.get("notes", ""),
            )
        )
    return whitelist


def journaliser(url: str, confirme_par_utilisateur: bool, autorise: bool, raison: str, source: str = "cli") -> None:
    """
    Ajoute une ligne au fichier de log, sans jamais écraser l'historique.

    Le champ `source` dit si la vérification vient du terminal ou du
    dashboard web — utile pour la traçabilité.
    """
    ligne = (
        f"{datetime.now().isoformat()} | "
        f"source={source} | "
        f"url={url} | "
        f"confirmation_utilisateur={confirme_par_utilisateur} | "
        f"resultat={'AUTORISE' if autorise else 'REFUSE'} | "
        f"raison={raison}\n"
    )
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(ligne)


# ---------------------------------------------------------------------------
# Lecture des résultats (sous-étape 1.8)
# ---------------------------------------------------------------------------
#
# Ces deux fonctions lisent des fichiers encore vides aujourd'hui ([] dans
# data/scan_results.json et data/hypotheses.json). Elles existent dès
# maintenant pour que le dashboard ait quelque chose à appeler, et pour
# que les futurs Modules 6 (Normalizer) et 7 (hypothèses LLM) sachent
# exactement où écrire leurs résultats.

SCAN_RESULTS_FILE = Path(__file__).resolve().parent / "data" / "scan_results.json"
HYPOTHESES_FILE = Path(__file__).resolve().parent / "data" / "hypotheses.json"


def lire_scan_results() -> list[dict]:
    """Lit data/scan_results.json (format : section 8 de la spec)."""
    with SCAN_RESULTS_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)


def lire_hypotheses() -> list[dict]:
    """Lit data/hypotheses.json (format : section 7 de la spec)."""
    with HYPOTHESES_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)