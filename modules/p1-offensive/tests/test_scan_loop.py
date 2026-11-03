"""
Tests de la boucle de scan (sous-étape 2.6).

Aucun réseau : la cible est simulée (simulation.py), les pauses sont
virtuelles. Baseline FIGÉE (valeurs réelles d'orchidisland.immo) pour que
les tests ne dépendent pas de data/baseline.json.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import core  # noqa: E402
from circuit_breaker import Baseline, CircuitBreaker, Etat, ResultatRequete  # noqa: E402
from scan_loop import DELAI_BASE_S, DELAI_SONDE_S, MAX_SONDES, executer_scan  # noqa: E402
from simulation import SCENARIOS, creer_cible  # noqa: E402

BASELINE_REELLE = Baseline(moyenne_ms=661.4, ecart_type_ms=458.8, nombre_echantillons=20)


def lancer(scenario: str, nb: int = 40, **kwargs):
    breaker = CircuitBreaker.depuis_baseline(BASELINE_REELLE)
    cible = creer_cible(scenario, BASELINE_REELLE)
    resume = executer_scan(cible.envoyer, breaker, nb, **kwargs)
    return resume, breaker


def etats(resume):
    return {e.etat for e in resume.evenements}


# --- Les scénarios, un par un ------------------------------------------------
def test_site_normal_aucune_alerte():
    resume, _ = lancer("normal")
    assert etats(resume) == {Etat.NORMAL}
    assert resume.requetes_envoyees == 40
    assert resume.sondes_envoyees == 0
    assert not resume.abandonne


def test_site_normal_rythme_de_base_partout():
    resume, _ = lancer("normal")
    # 39 pauses de 3 s (pas de pause après la dernière requête)
    assert resume.temps_virtuel_s == pytest.approx(39 * DELAI_BASE_S)


def test_pic_isole_ignore():
    resume, _ = lancer("pic_isole")
    assert etats(resume) == {Etat.NORMAL}
    assert resume.sondes_envoyees == 0


def test_ralentissement_double_le_delai():
    resume, _ = lancer("ralentissement")
    assert Etat.DEGRADE in etats(resume)
    assert Etat.CRITIQUE not in etats(resume)
    degrades = [e for e in resume.evenements if e.etat == Etat.DEGRADE and e.numero < len(resume.evenements)]
    assert degrades
    assert all(e.delai_avant_suivante_s == pytest.approx(2 * DELAI_BASE_S) for e in degrades)
    assert resume.evenements[-1].etat == Etat.NORMAL  # le site s'est rétabli


def test_erreurs_5xx_declenchent_degrade_sans_arret():
    resume, _ = lancer("erreurs")
    assert Etat.DEGRADE in etats(resume)
    assert Etat.CRITIQUE not in etats(resume)
    assert resume.sondes_envoyees == 0


def test_surcharge_critique_puis_sondes_puis_reprise():
    resume, breaker = lancer("surcharge")
    assert Etat.CRITIQUE in etats(resume)
    assert resume.sondes_envoyees > 0
    assert not resume.abandonne
    assert resume.requetes_envoyees == 40  # le scan est allé jusqu'au bout
    assert breaker.etat() == Etat.NORMAL


def test_panne_breve_quarantaine_puis_reprise():
    resume, breaker = lancer("panne")
    assert resume.sondes_envoyees >= 3  # il faut 3 succès consécutifs
    assert not resume.abandonne
    assert resume.requetes_envoyees == 40
    assert breaker.etat() == Etat.NORMAL


def test_panne_longue_abandon_fail_closed():
    resume, _ = lancer("panne_longue")
    assert resume.abandonne
    assert resume.sondes_envoyees == MAX_SONDES
    assert resume.requetes_envoyees < 40  # le scan n'est PAS allé au bout
    assert resume.evenements[-1].genre == "abandon"
    assert "abandonné" in resume.raison_arret


def test_site_qui_clignote_compteur_remis_a_zero():
    resume, _ = lancer("clignotant")
    # 3 succès consécutifs impossibles tout de suite : au moins 5 sondes
    assert resume.sondes_envoyees >= 5
    assert not resume.abandonne


# --- Règles de la boucle -------------------------------------------------------
def test_en_critique_seules_des_sondes_sont_envoyees():
    resume, _ = lancer("panne")
    premier_critique = next(i for i, e in enumerate(resume.evenements) if e.etat == Etat.CRITIQUE)
    # Tant que le breaker reste CRITIQUE, les événements suivants sont des sondes
    for e in resume.evenements[premier_critique + 1:]:
        if e.genre == "requete":
            break
        assert e.genre == "sonde"


def test_delai_entre_sondes():
    resume, _ = lancer("panne")
    sondes_critiques = [e for e in resume.evenements if e.genre == "sonde" and e.etat == Etat.CRITIQUE]
    assert sondes_critiques
    assert all(e.delai_avant_suivante_s == DELAI_SONDE_S for e in sondes_critiques)


def test_callback_appele_pour_chaque_evenement():
    recus = []
    resume, _ = lancer("surcharge", sur_evenement=recus.append)
    assert recus == resume.evenements


def test_simulation_reproductible():
    r1, _ = lancer("ralentissement")
    r2, _ = lancer("ralentissement")
    mesures1 = [(e.genre, e.resultat.temps_reponse_ms, e.etat) for e in r1.evenements]
    mesures2 = [(e.genre, e.resultat.temps_reponse_ms, e.etat) for e in r2.evenements]
    assert mesures1 == mesures2


def test_tous_les_scenarios_connus_se_terminent():
    for nom in SCENARIOS:
        resume, _ = lancer(nom)
        assert resume.evenements  # aucun scénario ne reste bloqué


# --- Validation (fail-closed) ----------------------------------------------------
def test_parametres_absurdes_refuses():
    breaker = CircuitBreaker.depuis_baseline(BASELINE_REELLE)
    envoyer = lambda est_sonde: ResultatRequete(temps_reponse_ms=600.0)  # noqa: E731
    with pytest.raises(ValueError):
        executer_scan(envoyer, breaker, 0)
    with pytest.raises(ValueError):
        executer_scan(envoyer, breaker, 10, max_sondes=0)
    with pytest.raises(ValueError):
        executer_scan(envoyer, breaker, 10, delai_base_s=-1)


def test_scenario_inconnu_refuse():
    with pytest.raises(ValueError):
        creer_cible("n_importe_quoi", BASELINE_REELLE)


# --- Chargement de la baseline (core.py) ----------------------------------------
def test_charger_baseline_lit_le_fichier(tmp_path, monkeypatch):
    fichier = tmp_path / "baseline.json"
    fichier.write_text(
        json.dumps({"moyenne_ms": 661.4, "ecart_type_ms": 458.8, "nombre_echantillons": 20}),
        encoding="utf-8",
    )
    monkeypatch.setattr(core, "BASELINE_FILE", fichier)
    baseline = core.charger_baseline()
    assert baseline.moyenne_ms == pytest.approx(661.4)
    assert baseline.ecart_type_ms == pytest.approx(458.8)
    assert baseline.nombre_echantillons == 20


def test_charger_baseline_fichier_absent_echoue_clairement(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "BASELINE_FILE", tmp_path / "inexistant.json")
    with pytest.raises(FileNotFoundError, match="baseline_scan.py"):
        core.charger_baseline()


def test_charger_baseline_champ_manquant_echoue(tmp_path, monkeypatch):
    fichier = tmp_path / "baseline.json"
    fichier.write_text(json.dumps({"moyenne_ms": 661.4}), encoding="utf-8")
    monkeypatch.setattr(core, "BASELINE_FILE", fichier)
    with pytest.raises(ValueError, match="ecart_type_ms"):
        core.charger_baseline()