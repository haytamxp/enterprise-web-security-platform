#!/usr/bin/env python3
"""
Tests du Scope Manager — un cas de test par piège identifié en 1.3.

Deux façons de lancer les MÊMES cas (une seule source de vérité : la liste CAS) :

    python -m pytest tests               -> intégré à la suite complète (CI, etc.)
    python tests\\test_scope_manager.py   -> affichage détaillé OK / ECHEC avec
                                            la raison retournée par le code

Mise à jour 2.x : le fichier était un script autonome que pytest ne voyait
pas ("collected 0 items"). Les 14 cas d'origine sont conservés à l'identique
(mêmes URLs, mêmes whitelists, mêmes résultats attendus).

Date de référence : les cas passent désormais une date FIXE (DATE_FIXE) au
lieu de la date du jour. Sinon les fenêtres d'autorisation de test
(jusqu'au 31/12/2026) auraient fait échouer ces tests dès le 1er janvier 2027,
sans aucun bug dans le Scope Manager.
"""

import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scope_manager import ScopeEntry, is_authorized  # noqa: E402

# Date "aujourd'hui" simulée, au milieu de la fenêtre d'autorisation de test.
DATE_FIXE = date(2026, 6, 1)


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


@dataclass(frozen=True)
class Cas:
    id: str            # identifiant court (ASCII) affiché par pytest
    description: str   # description complète affichée en mode script
    url: str
    whitelist: list
    attendu: bool      # True = doit être autorisé, False = doit être refusé
    today: date = DATE_FIXE


CAS = [
    Cas(
        "cas_de_base",
        "Cas de base — domaine légitime",
        "https://orchidisland.immo/contact",
        WHITELIST_TOTALE,
        attendu=True,
    ),
    Cas(
        "piege1_sous_dossier_site_pirate",
        "Piège 1 — domaine légitime en sous-dossier d'un site pirate",
        "https://orchidisland.immo.site-pirate.com/",
        WHITELIST_TOTALE,
        attendu=False,
    ),
    Cas(
        "piege1_domaine_dans_parametre_url",
        "Piège 1 — domaine légitime caché dans un paramètre d'URL",
        "https://evil.com/redirect?to=orchidisland.immo",
        WHITELIST_TOTALE,
        attendu=False,
    ),
    Cas(
        "piege2_majuscules",
        "Piège 2 — majuscules",
        "https://ORCHIDISLAND.IMMO/contact",
        WHITELIST_TOTALE,
        attendu=True,
    ),
    Cas(
        "piege3a_sous_domaine_refuse",
        "Piège 3a — sous-domaine REFUSÉ quand include_subdomains=False",
        "https://admin.orchidisland.immo/",
        WHITELIST_TOTALE,
        attendu=False,
    ),
    Cas(
        "piege3b_sous_domaine_autorise",
        "Piège 3b — sous-domaine AUTORISÉ quand include_subdomains=True",
        "https://admin.orchidisland.immo/",
        WHITELIST_AVEC_OPTIONS,
        attendu=True,
    ),
    Cas(
        "piege3c_faux_sous_domaine",
        "Piège 3c — faux sous-domaine qui ressemble mais n'en est pas un",
        "https://orchidislandimmo.com/",
        WHITELIST_AVEC_OPTIONS,
        attendu=False,
    ),
    Cas(
        "piege4_port",
        "Piège 4 — présence d'un port, ne doit pas perturber la comparaison",
        "https://orchidisland.immo:8443/admin",
        WHITELIST_TOTALE,
        attendu=True,
    ),
    Cas(
        "piege5_ip_brute",
        "Piège 5 — adresse IP brute, doit être refusée (fail-closed)",
        "https://185.12.34.56/",
        WHITELIST_TOTALE,
        attendu=False,
    ),
    Cas(
        "piege6a_chemin_exclu_exact",
        "Piège 6a — chemin exclu exact",
        "https://orchidisland.immo/paiement",
        WHITELIST_AVEC_OPTIONS,
        attendu=False,
    ),
    Cas(
        "piege6b_sous_chemin_exclu",
        "Piège 6b — sous-chemin d'un chemin exclu (doit AUSSI être refusé)",
        "https://orchidisland.immo/paiement/confirmation",
        WHITELIST_AVEC_OPTIONS,
        attendu=False,
    ),
    Cas(
        "piege6c_chemin_voisin",
        "Piège 6c — chemin voisin non exclu, doit rester autorisé",
        "https://orchidisland.immo/contact",
        WHITELIST_AVEC_OPTIONS,
        attendu=True,
    ),
    Cas(
        "date_hors_fenetre",
        "Date — hors fenêtre d'autorisation (dans le futur)",
        "https://orchidisland.immo/",
        WHITELIST_TOTALE,
        attendu=False,
        today=date(2027, 1, 1),
    ),
    Cas(
        "robustesse_url_invalide",
        "Robustesse — URL complètement invalide",
        "pas-une-url-du-tout",
        WHITELIST_TOTALE,
        attendu=False,
    ),
]


# ---------------------------------------------------------------------------
# Mode pytest : un test par cas
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("cas", CAS, ids=[c.id for c in CAS])
def test_scope_manager(cas: Cas) -> None:
    autorise, raison = is_authorized(cas.url, cas.whitelist, today=cas.today)
    assert autorise == cas.attendu, (
        f"{cas.description} | URL : {cas.url} | "
        f"attendu : {'autorisé' if cas.attendu else 'refusé'} | "
        f"obtenu : {'autorisé' if autorise else 'refusé'} — {raison}"
    )


# --- Ajout : comportement quand AUCUNE date n'est passée (date du jour réelle)
# Les 14 cas ci-dessus fixent la date ; ces 2 tests vérifient que, sans
# paramètre `today`, le Scope Manager utilise bien la date du jour. Les
# fenêtres sont très larges / très anciennes pour ne jamais expirer.
def _entree_avec_fenetre(debut: date, fin: date) -> list:
    return [
        ScopeEntry(
            domain="orchidisland.immo",
            include_subdomains=False,
            excluded_paths=[],
            excluded_subdomains=[],
            authorized_from=debut,
            authorized_until=fin,
            authorized_by="Test",
        )
    ]


def test_date_du_jour_par_defaut_fenetre_en_cours():
    whitelist = _entree_avec_fenetre(date(2000, 1, 1), date(2999, 12, 31))
    autorise, raison = is_authorized("https://orchidisland.immo/", whitelist)
    assert autorise, raison


def test_date_du_jour_par_defaut_fenetre_expiree():
    whitelist = _entree_avec_fenetre(date(2000, 1, 1), date(2001, 1, 1))
    autorise, raison = is_authorized("https://orchidisland.immo/", whitelist)
    assert not autorise, raison


# ---------------------------------------------------------------------------
# Mode script : affichage détaillé, identique à l'ancien
# ---------------------------------------------------------------------------
def check(cas: Cas) -> bool:
    authorized, reason = is_authorized(cas.url, cas.whitelist, today=cas.today)
    status = "OK" if authorized == cas.attendu else "ECHEC"
    print(f"[{status}] {cas.description}")
    print(f"        URL testée : {cas.url}")
    print(f"        Attendu    : {'autorisé' if cas.attendu else 'refusé'}")
    print(f"        Obtenu     : {'autorisé' if authorized else 'refusé'} — {reason}")
    print()
    return authorized == cas.attendu


def main() -> None:
    resultats = [check(cas) for cas in CAS]

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