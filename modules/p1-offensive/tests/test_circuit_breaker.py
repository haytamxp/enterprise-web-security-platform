"""
Tests du Circuit Breaker (sous-étape 2.5).

Aucun vrai réseau ici : on injecte des ResultatRequete simulés.
Les valeurs de baseline sont FIGÉES (copiées de data/baseline.json au
moment du scan réel sur orchidisland.immo) pour que les tests ne cassent
pas si on refait un scan de baseline plus tard.
"""

import random
import sys
from pathlib import Path

import pytest

# Permet d'importer circuit_breaker.py (dossier parent) quel que soit
# l'endroit d'où pytest est lancé.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from circuit_breaker import (  # noqa: E402
    Baseline,
    CircuitBreaker,
    Etat,
    ResultatRequete,
    calibrer_seuils,
    etablir_baseline,
)

# --- Baseline réelle d'orchidisland.immo (20 requêtes), figée -------------
BASELINE_REELLE = Baseline(moyenne_ms=661.4, ecart_type_ms=458.8, nombre_echantillons=20)
SEUIL_DEGRADE = 2037.9   # ms (à ~0.1 ms près, voir pytest.approx)
SEUIL_CRITIQUE = 3414.4  # ms

ORDRE = {Etat.NORMAL: 0, Etat.DEGRADE: 1, Etat.CRITIQUE: 2}


# --- Aides ----------------------------------------------------------------
def nouveau_cb() -> CircuitBreaker:
    return CircuitBreaker.depuis_baseline(BASELINE_REELLE)


def ok(ms: float = 660.0) -> ResultatRequete:
    return ResultatRequete(temps_reponse_ms=ms)


def erreur_5xx(ms: float = 660.0) -> ResultatRequete:
    return ResultatRequete(temps_reponse_ms=ms, erreur_5xx=True)


def injoignable() -> ResultatRequete:
    return ResultatRequete(temps_reponse_ms=0.0, injoignable=True)


def cb_avec_fenetre_saine() -> CircuitBreaker:
    """Un breaker dont la fenêtre de 10 requêtes est pleine et saine."""
    cb = nouveau_cb()
    for _ in range(10):
        cb.enregistrer_resultat(ok())
    assert cb.etat() == Etat.NORMAL
    return cb


# --- Calibration ----------------------------------------------------------
def test_calibration_donne_les_seuils_de_la_baseline_reelle():
    degrade, critique = calibrer_seuils(BASELINE_REELLE)
    assert degrade == pytest.approx(SEUIL_DEGRADE, abs=0.5)
    assert critique == pytest.approx(SEUIL_CRITIQUE, abs=0.5)


def test_calibration_plancher_pour_un_site_tres_stable():
    # Écart-type quasi nul : sans plancher, le seuil serait collé à la moyenne.
    stable = Baseline(moyenne_ms=500.0, ecart_type_ms=1.0, nombre_echantillons=20)
    degrade, critique = calibrer_seuils(stable)
    # plancher = 10% de 500 = 50 ms  ->  500 + 3*50 et 500 + 6*50
    assert degrade == pytest.approx(650.0)
    assert critique == pytest.approx(800.0)


def test_baseline_refuse_moins_de_2_mesures():
    with pytest.raises(ValueError):
        etablir_baseline([650.0])


# --- Scénario 1 : site stable ---------------------------------------------
def test_site_stable_reste_normal():
    # Temps de réponse tirés au hasard autour de la vraie variabilité du
    # site (graine fixe = test reproductible).
    alea = random.Random(42)
    cb = nouveau_cb()
    for _ in range(300):
        ms = max(100.0, alea.gauss(661.4, 458.8))
        assert cb.enregistrer_resultat(ok(ms)) == Etat.NORMAL
    assert cb.facteur_ralentissement() == 1.0


# --- Scénario 2 : ralentissement progressif --------------------------------
def test_ralentissement_progressif_normal_puis_degrade_sans_jamais_reculer():
    cb = cb_avec_fenetre_saine()
    etats = []
    for _ in range(10):  # le site passe à 2500 ms (entre les deux seuils)
        etats.append(cb.enregistrer_resultat(ok(2500.0)))

    assert etats[0] == Etat.NORMAL          # un seul lent ne suffit pas
    assert etats[-1] == Etat.DEGRADE        # fenêtre pleine de 2500 ms
    assert Etat.CRITIQUE not in etats       # 2500 < seuil critique
    niveaux = [ORDRE[e] for e in etats]
    assert niveaux == sorted(niveaux)       # jamais de retour en arrière
    assert cb.facteur_ralentissement() == 2.0


# --- Scénario 3 : ralentissement sévère ------------------------------------
def test_ralentissement_severe_declenche_critique_et_arret():
    cb = cb_avec_fenetre_saine()
    for _ in range(10):
        cb.enregistrer_resultat(ok(5000.0))
    assert cb.etat() == Etat.CRITIQUE
    assert cb.facteur_ralentissement() == float("inf")


# --- Scénario 4 : erreurs 5xx ----------------------------------------------
def test_taux_eleve_d_erreurs_5xx_declenche_critique():
    cb = cb_avec_fenetre_saine()
    for _ in range(4):  # temps de réponse parfaits, mais 4 erreurs sur 10
        cb.enregistrer_resultat(erreur_5xx(660.0))
    assert cb.etat() == Etat.CRITIQUE
    assert "5xx" in cb.raison()


def test_une_seule_erreur_5xx_isolee_ne_declenche_rien():
    # 2.5bis (correction 2) : 1 erreur sur 10 = bruit normal d'un site sain.
    cb = cb_avec_fenetre_saine()
    assert cb.enregistrer_resultat(erreur_5xx()) == Etat.NORMAL


def test_deux_erreurs_5xx_sur_dix_ralentissent():
    cb = cb_avec_fenetre_saine()
    cb.enregistrer_resultat(erreur_5xx())
    assert cb.enregistrer_resultat(erreur_5xx()) == Etat.DEGRADE
    assert cb.facteur_ralentissement() == 2.0


def test_trois_erreurs_5xx_sur_dix_restent_degrade():
    cb = cb_avec_fenetre_saine()
    for _ in range(3):
        cb.enregistrer_resultat(erreur_5xx())
    assert cb.etat() == Etat.DEGRADE


# --- Scénario 5 : pic isolé ------------------------------------------------
def test_pic_isole_de_temps_de_reponse_ne_declenche_rien():
    cb = cb_avec_fenetre_saine()
    # Une requête à 6000 ms parmi 9 normales : moyenne ~1194 ms < 2038 ms
    assert cb.enregistrer_resultat(ok(6000.0)) == Etat.NORMAL
    assert cb.facteur_ralentissement() == 1.0


# --- Scénario 6 : injoignable ----------------------------------------------
def test_injoignable_declenche_critique_immediatement():
    cb = cb_avec_fenetre_saine()  # historique parfaitement sain...
    assert cb.enregistrer_resultat(injoignable()) == Etat.CRITIQUE  # ...ça ne change rien
    assert "injoignable" in cb.raison().lower()
    assert cb.facteur_ralentissement() == float("inf")


# --- Scénario 7 : retour à la normale --------------------------------------
def test_retour_a_la_normale_apres_critique():
    cb = cb_avec_fenetre_saine()
    for _ in range(10):
        cb.enregistrer_resultat(ok(5000.0))
    assert cb.etat() == Etat.CRITIQUE

    for _ in range(10):  # le site se rétablit
        cb.enregistrer_resultat(ok(660.0))
    assert cb.etat() == Etat.NORMAL
    assert cb.facteur_ralentissement() == 1.0


def test_redescente_progressive_critique_degrade_normal():
    cb = cb_avec_fenetre_saine()
    for _ in range(10):
        cb.enregistrer_resultat(ok(5000.0))
    assert cb.etat() == Etat.CRITIQUE

    vus = {cb.enregistrer_resultat(ok(660.0)) for _ in range(10)}
    assert Etat.DEGRADE in vus  # on passe bien par l'étage intermédiaire


# --- Fenêtre glissante -----------------------------------------------------
def test_la_fenetre_oublie_les_vieilles_requetes():
    cb = nouveau_cb()
    for _ in range(50):
        cb.enregistrer_resultat(ok())
    assert len(cb._fenetre) == 10


# --- 2.5bis, correction 1 : période de chauffe -----------------------------
def test_chauffe_premiere_requete_lente_ne_declenche_rien():
    cb = nouveau_cb()
    assert cb.enregistrer_resultat(ok(6000.0)) == Etat.NORMAL
    assert "chauffe" in cb.raison().lower()


def test_chauffe_se_termine_a_la_cinquieme_requete():
    cb = nouveau_cb()
    for _ in range(4):  # 4 requêtes très lentes : toujours pas de jugement
        assert cb.enregistrer_resultat(ok(6000.0)) == Etat.NORMAL
    # 5e requête : la chauffe est finie, la moyenne (6000 ms) est jugée
    assert cb.enregistrer_resultat(ok(6000.0)) == Etat.CRITIQUE


def test_chauffe_ne_retarde_jamais_injoignable():
    cb = nouveau_cb()  # aucune requête observée, en pleine chauffe
    assert cb.enregistrer_resultat(injoignable()) == Etat.CRITIQUE


def test_configuration_absurde_refusee():
    # Si le minimum dépassait la fenêtre, le breaker ne jugerait jamais rien.
    with pytest.raises(ValueError):
        CircuitBreaker.depuis_baseline(BASELINE_REELLE, taille_fenetre=10, nb_min_avant_jugement=11)
    with pytest.raises(ValueError):
        CircuitBreaker.depuis_baseline(BASELINE_REELLE, succes_requis_apres_panne=0)


# --- 2.5bis, correction 3 : quarantaine après injoignable ------------------
def test_quarantaine_trois_succes_consecutifs_pour_reprendre():
    cb = cb_avec_fenetre_saine()
    cb.enregistrer_resultat(injoignable())

    assert cb.enregistrer_resultat(ok()) == Etat.CRITIQUE  # 1/3
    assert "1/3" in cb.raison()
    assert cb.enregistrer_resultat(ok()) == Etat.CRITIQUE  # 2/3
    assert cb.facteur_ralentissement() == float("inf")
    assert cb.enregistrer_resultat(ok()) == Etat.NORMAL    # 3/3 : confiance rétablie
    assert cb.facteur_ralentissement() == 1.0


def test_quarantaine_site_qui_clignote_est_remis_a_zero():
    cb = cb_avec_fenetre_saine()
    cb.enregistrer_resultat(injoignable())
    cb.enregistrer_resultat(ok())
    cb.enregistrer_resultat(ok())
    cb.enregistrer_resultat(injoignable())  # retombe avant le 3e succès

    assert cb.enregistrer_resultat(ok()) == Etat.CRITIQUE  # on recompte depuis 0
    assert cb.enregistrer_resultat(ok()) == Etat.CRITIQUE
    assert cb.enregistrer_resultat(ok()) == Etat.NORMAL


def test_quarantaine_une_erreur_5xx_remet_le_compteur_a_zero():
    cb = cb_avec_fenetre_saine()
    cb.enregistrer_resultat(injoignable())
    cb.enregistrer_resultat(ok())
    cb.enregistrer_resultat(ok())
    cb.enregistrer_resultat(erreur_5xx())  # pas saine : retour à 0/3

    assert cb.enregistrer_resultat(ok()) == Etat.CRITIQUE
    assert cb.enregistrer_resultat(ok()) == Etat.CRITIQUE
    assert cb.enregistrer_resultat(ok()) == Etat.NORMAL


def test_quarantaine_une_reponse_lente_n_est_pas_saine():
    cb = cb_avec_fenetre_saine()
    cb.enregistrer_resultat(injoignable())
    cb.enregistrer_resultat(ok())
    cb.enregistrer_resultat(ok())
    cb.enregistrer_resultat(ok(2500.0))  # au-dessus du seuil dégradé : pas saine

    assert cb.etat() == Etat.CRITIQUE
    assert cb.enregistrer_resultat(ok()) == Etat.CRITIQUE  # 1/3 seulement


# --- Choix assumé : une réponse à 30 s est un quasi-timeout ----------------
def test_une_reponse_a_30_secondes_declenche_critique_par_choix():
    # (9 x 660 + 30000) / 10 = 3594 ms >= seuil critique (~3414 ms).
    # Ce n'est pas un accident : 30 s de réponse = presque une panne.
    cb = cb_avec_fenetre_saine()
    assert cb.enregistrer_resultat(ok(30000.0)) == Etat.CRITIQUE