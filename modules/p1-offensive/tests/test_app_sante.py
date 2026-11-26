"""
Tests des routes /sante du dashboard (sous-étape 2.7), via le client de test
de Flask : aucun serveur à démarrer, aucun réseau.
"""

import sys
from pathlib import Path

import pytest

pytest.importorskip("flask")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as app_module  # noqa: E402
from circuit_breaker import Baseline  # noqa: E402
from simulation_live import GestionnaireSimulation  # noqa: E402

BASELINE_REELLE = Baseline(moyenne_ms=661.4, ecart_type_ms=458.8, nombre_echantillons=20)
TEMPLATES = Path(__file__).resolve().parent.parent / "templates"


@pytest.fixture
def client(monkeypatch):
    """Client de test + gestionnaire rapide, sans pause, avec baseline figée."""
    g = GestionnaireSimulation(delai_affichage_s=0, charger_baseline_fn=lambda: BASELINE_REELLE)
    monkeypatch.setattr(app_module, "gestionnaire", g)
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


def gestionnaire_courant():
    return app_module.gestionnaire


# --- Pages ------------------------------------------------------------------------
def test_page_sante_s_affiche_avec_les_scenarios(client):
    reponse = client.get("/sante")
    assert reponse.status_code == 200
    html = reponse.get_data(as_text=True)
    assert "surcharge" in html and "panne_longue" in html
    assert "aucune requête réelle" in html.lower()


@pytest.mark.parametrize("nom", ["index.html", "scan_results.html", "hypotheses.html", "sante.html"])
def test_chaque_page_a_le_lien_de_menu_sante(nom):
    contenu = (TEMPLATES / nom).read_text(encoding="utf-8")
    assert 'href="/sante"' in contenu, f"templates/{nom} : il manque le lien du menu vers /sante"


def test_pages_existantes_toujours_accessibles(client):
    for chemin in ("/", "/scan-results", "/hypotheses"):
        assert client.get(chemin).status_code == 200


# --- Etat / lancement / arrêt -------------------------------------------------------
def test_etat_initial_en_json(client):
    donnees = client.get("/sante/etat").get_json()
    assert donnees["statut"] == "inactif"
    assert donnees["evenements"] == []


def test_lancer_puis_lire_l_etat(client):
    reponse = client.post("/sante/lancer", data={"scenario": "surcharge", "requetes": "40"})
    assert reponse.status_code == 200
    gestionnaire_courant().attendre_fin()

    donnees = client.get("/sante/etat").get_json()
    assert donnees["statut"] == "termine"
    assert donnees["scenario"] == "surcharge"
    assert donnees["sondes_envoyees"] > 0
    assert donnees["etat"] == "normal"


def test_double_lancement_renvoie_409(monkeypatch):
    g = GestionnaireSimulation(delai_affichage_s=0.05, charger_baseline_fn=lambda: BASELINE_REELLE)
    monkeypatch.setattr(app_module, "gestionnaire", g)
    app_module.app.config["TESTING"] = True
    client = app_module.app.test_client()

    assert client.post("/sante/lancer", data={"scenario": "normal", "requetes": "40"}).status_code == 200
    deuxieme = client.post("/sante/lancer", data={"scenario": "normal", "requetes": "40"})
    assert deuxieme.status_code == 409
    assert "déjà en cours" in deuxieme.get_json()["erreur"]

    assert client.post("/sante/arreter").get_json() == {"arrete": True}
    g.attendre_fin()
    assert client.get("/sante/etat").get_json()["statut"] == "arrete"


@pytest.mark.parametrize(
    "donnees",
    [
        {"scenario": "inconnu", "requetes": "10"},
        {"scenario": "normal", "requetes": "0"},
        {"scenario": "normal", "requetes": "99999"},
        {"scenario": "normal", "requetes": "abc"},
        {},
    ],
)
def test_lancement_avec_parametres_invalides_renvoie_400(client, donnees):
    reponse = client.post("/sante/lancer", data=donnees)
    assert reponse.status_code == 400
    assert "erreur" in reponse.get_json()
    assert client.get("/sante/etat").get_json()["statut"] == "inactif"


def test_arreter_sans_simulation(client):
    assert client.post("/sante/arreter").get_json() == {"arrete": False}


def test_baseline_absente_renvoie_500_et_message_clair(monkeypatch):
    def absente():
        raise FileNotFoundError("lance d'abord baseline_scan.py")

    g = GestionnaireSimulation(delai_affichage_s=0, charger_baseline_fn=absente)
    monkeypatch.setattr(app_module, "gestionnaire", g)
    app_module.app.config["TESTING"] = True
    reponse = app_module.app.test_client().post("/sante/lancer", data={"scenario": "normal", "requetes": "10"})
    assert reponse.status_code == 500
    assert "baseline_scan.py" in reponse.get_json()["erreur"]


def test_les_routes_de_lancement_refusent_get(client):
    assert client.get("/sante/lancer").status_code == 405
    assert client.get("/sante/arreter").status_code == 405