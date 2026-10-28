#!/usr/bin/env python3
"""
Tests du Scope Manager — un cas de test par piège identifié en 1.3.

Chaque test affiche OK / ECHEC, avec la raison retournée par le code,
pour qu'on puisse vérifier que le Scope Manager se comporte vraiment
comme prévu, pas juste "qu'il ne plante pas".
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from datetime import date

from scope_manager import ScopeEntry, is_authorized


WHITELIST_TOTALE = [
    ScopeEntry(
        domain="orchidisland.immo",
        include_subdomains=False,
        excluded_paths=[],
        excluded_subdomains=[],
        authorized_from=date(2026, 1, 1),
        authorized_until=date(2026, 12, 31),
        authorized_by="Responsable Sécurité",
    )
]

WHITELIST_AVEC_OPTIONS = [
    ScopeEntry(
        domain="orchidisland.immo",
        include_subdomains=True,
        excluded_paths=["/paiement"],
        excluded_subdomains=["chat-widget.orchidisland.immo"],
        authorized_from=date(2026, 1, 1),
        authorized_until=date(2026, 12, 31),
        authorized_by="Responsable Sécurité",
    )
]


def check(description: str, url: str, whitelist, expected: bool, today=None) -> bool:
    authorized, reason = is_authorized(url, whitelist, today=today)
    status = "OK" if authorized == expected else "ECHEC"
    print(f"[{status}] {description}")
    print(f"        URL testée : {url}")
    print(f"        Attendu    : {'autorisé' if expected else 'refusé'}")
    print(f"        Obtenu     : {'autorisé' if authorized else 'refusé'} — {reason}")
    print()
    return authorized == expected


def main() -> None:
    resultats = []

    resultats.append(check(
        "Cas de base — domaine légitime",
        "https://orchidisland.immo/contact",
        WHITELIST_TOTALE,
        expected=True,
    ))

    resultats.append(check(
        "Piège 1 — domaine légitime en sous-dossier d'un site pirate",
        "https://orchidisland.immo.site-pirate.com/",
        WHITELIST_TOTALE,
        expected=False,
    ))
    resultats.append(check(
        "Piège 1 — domaine légitime caché dans un paramètre d'URL",
        "https://evil.com/redirect?to=orchidisland.immo",
        WHITELIST_TOTALE,
        expected=False,
    ))

    resultats.append(check(
        "Piège 2 — majuscules",
        "https://ORCHIDISLAND.IMMO/contact",
        WHITELIST_TOTALE,
        expected=True,
    ))

    resultats.append(check(
        "Piège 3a — sous-domaine REFUSÉ quand include_subdomains=False",
        "https://admin.orchidisland.immo/",
        WHITELIST_TOTALE,
        expected=False,
    ))
    resultats.append(check(
        "Piège 3b — sous-domaine AUTORISÉ quand include_subdomains=True",
        "https://admin.orchidisland.immo/",
        WHITELIST_AVEC_OPTIONS,
        expected=True,
    ))
    resultats.append(check(
        "Piège 3c — faux sous-domaine qui ressemble mais n'en est pas un",
        "https://orchidislandimmo.com/",
        WHITELIST_AVEC_OPTIONS,
        expected=False,
    ))

    resultats.append(check(
        "Piège 4 — présence d'un port, ne doit pas perturber la comparaison",
        "https://orchidisland.immo:8443/admin",
        WHITELIST_TOTALE,
        expected=True,
    ))

    resultats.append(check(
        "Piège 5 — adresse IP brute, doit être refusée (fail-closed)",
        "https://185.12.34.56/",
        WHITELIST_TOTALE,
        expected=False,
    ))

    resultats.append(check(
        "Piège 6a — chemin exclu exact",
        "https://orchidisland.immo/paiement",
        WHITELIST_AVEC_OPTIONS,
        expected=False,
    ))
    resultats.append(check(
        "Piège 6b — sous-chemin d'un chemin exclu (doit AUSSI être refusé)",
        "https://orchidisland.immo/paiement/confirmation",
        WHITELIST_AVEC_OPTIONS,
        expected=False,
    ))
    resultats.append(check(
        "Piège 6c — chemin voisin non exclu, doit rester autorisé",
        "https://orchidisland.immo/contact",
        WHITELIST_AVEC_OPTIONS,
        expected=True,
    ))

    resultats.append(check(
        "Date — hors fenêtre d'autorisation (dans le futur)",
        "https://orchidisland.immo/",
        WHITELIST_TOTALE,
        expected=False,
        today=date(2027, 1, 1),
    ))

    resultats.append(check(
        "Robustesse — URL complètement invalide",
        "pas-une-url-du-tout",
        WHITELIST_TOTALE,
        expected=False,
    ))

    total = len(resultats)
    reussis = sum(resultats)
    print("=" * 60)
    print(f"Résultat global : {reussis}/{total} tests réussis")
    if reussis == total:
        print("✅ Le Scope Manager se comporte comme prévu sur tous les pièges.")
    else:
        print("❌ Au moins un comportement ne correspond pas à ce qui était prévu.")


if __name__ == "__main__":
    main()