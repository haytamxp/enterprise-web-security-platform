"""
Garde-fou de la page d'accueil (Module 1) — ajouté en 2.7.

Pourquoi : en 2.7 on a réécrit app.py et modifié le menu des templates. Ces
tests vérifient que la fonctionnalité d'origine (formulaire de vérification
de périmètre -> Scope Manager -> journalisation) fonctionne toujours, et que
le formulaire n'a pas disparu de index.html par accident.

Aucun fichier réel n'est touché : le journal et la whitelist sont remplacés
par des versions temporaires.
"""

import sys
from datetime import date
from pathlib import Path

import pytest

pytest.importorskip("flask")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as app_module  # noqa: E402
import core  # noqa: E402
from scope_manager import ScopeEntry  # noqa: E402

# Fenêtre très large : ces tests ne doivent jamais expirer.
WHITELIST_TEST = [
    ScopeEntry(
        domain="orchidisland.immo",
        include_subdomains=False,
        excluded_paths=[],
        excluded_subdomains=[],
        authorized_from=date(2000, 1, 1),
        authorized_until=date(2999, 12, 31),
        authorized_by="Test",
    )
]


@pytest.fixture
def accueil(monkeypatch, tmp_path):
    journal = tmp_path / "scope_manager.log"
    monkeypatch.setattr(core, "LOG_FILE", journal)
    monkeypatch.setattr(app_module, "charger_whitelist", lambda: WHITELIST_TEST)
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client(), journal


def test_accueil_contient_le_formulaire_de_verification(accueil):
    client, _ = accueil
    html = client.get("/").get_data(as_text=True)
    assert "<form" in html, "index.html n'a plus de formulaire"
    assert 'name="url"' in html, "index.html : champ 'url' manquant"
    assert 'name="autorisation"' in html, "index.html : case 'autorisation' manquante"


def test_sans_confirmation_refus_et_journal(accueil):
    client, journal = accueil
    reponse = client.post("/", data={"url": "https://orchidisland.immo/"})
    assert reponse.status_code == 200
    ligne = journal.read_text(encoding="utf-8")
    assert "source=web" in ligne and "resultat=REFUSE" in ligne


def test_avec_confirmation_url_dans_le_perimetre_autorisee(accueil):
    client, journal = accueil
    reponse = client.post("/", data={"url": "https://orchidisland.immo/contact", "autorisation": "on"})
    assert reponse.status_code == 200
    assert "resultat=AUTORISE" in journal.read_text(encoding="utf-8")


def test_avec_confirmation_url_hors_perimetre_refusee(accueil):
    client, journal = accueil
    reponse = client.post("/", data={"url": "https://evil.com/", "autorisation": "on"})
    assert reponse.status_code == 200
    assert "resultat=REFUSE" in journal.read_text(encoding="utf-8")