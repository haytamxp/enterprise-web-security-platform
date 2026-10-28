#!/usr/bin/env python3
"""
CLI du Scope Manager — sous-étape 1.6, mise à jour en 1.7.

Ce fichier est maintenant volontairement court : toute la logique de
chargement de whitelist et de journalisation vit dans core.py, pour être
partagée avec le dashboard web (app.py) sans duplication.
"""

from __future__ import annotations

from core import charger_whitelist, journaliser
from scope_manager import is_authorized


def main() -> None:
    print("=" * 60)
    print("Scope Manager — vérification de périmètre (CLI)")
    print("=" * 60)

    whitelist = charger_whitelist()

    url = input("\nQuelle URL voulez-vous tester ? ").strip()

    reponse = input(
        "Confirmez-vous disposer d'une autorisation écrite valide "
        "pour tester cette cible ? (oui/non) : "
    ).strip().lower()
    confirme_par_utilisateur = reponse in ("oui", "o", "yes", "y")

    if not confirme_par_utilisateur:
        print("\n❌ REFUSÉ — Aucune confirmation d'autorisation fournie.")
        journaliser(url, confirme_par_utilisateur, False, "Pas de confirmation humaine", source="cli")
        return

    autorise, raison = is_authorized(url, whitelist)
    journaliser(url, confirme_par_utilisateur, autorise, raison, source="cli")

    print()
    if autorise:
        print(f"✅ AUTORISÉ — {raison}")
    else:
        print(f"❌ REFUSÉ — {raison}")

    print("\n(Cette vérification a été enregistrée dans scope_manager.log)")


if __name__ == "__main__":
    main()