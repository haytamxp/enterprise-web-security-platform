#!/usr/bin/env python3
"""
Cibles SIMULÉES pour tester la boucle de scan (sous-étape 2.6).

Aucun réseau ici : une `CibleSimulee` fabrique des ResultatRequete selon un
scénario. Le "bruit normal" est tiré autour de la VRAIE baseline du site
(moyenne et écart-type), avec une graine fixe : le hasard est donc
réaliste ET reproductible.

Le scénario raisonne sur le numéro d'appel (0, 1, 2, ...). Les sondes de
santé comptent comme des appels : le site "vit" au rythme des requêtes
envoyées, qu'elles soient de scan ou de sonde.
"""

from __future__ import annotations

import random
from typing import Callable

from circuit_breaker import Baseline, ResultatRequete


class CibleSimulee:
    def __init__(self, scenario: Callable[[int, "CibleSimulee"], ResultatRequete], baseline: Baseline, graine: int = 42):
        self._scenario = scenario
        self._baseline = baseline
        self._alea = random.Random(graine)
        self._appels = 0

    def envoyer(self, est_sonde: bool = False) -> ResultatRequete:
        # `est_sonde` est ignoré par la cible simulée : une vraie sonde sera
        # plus légère, mais le site simulé réagit de la même façon.
        i = self._appels
        self._appels += 1
        return self._scenario(i, self)

    # --- Briques pour écrire les scénarios ---------------------------------
    def normal(self) -> ResultatRequete:
        ms = self._alea.gauss(self._baseline.moyenne_ms, self._baseline.ecart_type_ms)
        return ResultatRequete(temps_reponse_ms=max(100.0, ms))

    def lent(self, centre_ms: float, dispersion_ms: float = 300.0) -> ResultatRequete:
        ms = self._alea.gauss(centre_ms, dispersion_ms)
        return ResultatRequete(temps_reponse_ms=max(100.0, ms))

    def erreur_5xx(self) -> ResultatRequete:
        resultat = self.normal()
        resultat.erreur_5xx = True
        return resultat

    @staticmethod
    def injoignable() -> ResultatRequete:
        return ResultatRequete(temps_reponse_ms=0.0, injoignable=True)


# --- Scénarios ---------------------------------------------------------------
def _normal(i, c):
    return c.normal()


def _pic_isole(i, c):
    return ResultatRequete(temps_reponse_ms=6000.0) if i == 12 else c.normal()


def _ralentissement(i, c):
    return c.lent(2500.0) if 15 <= i < 30 else c.normal()


def _surcharge(i, c):
    return c.lent(5000.0, 400.0) if 15 <= i < 25 else c.normal()


def _erreurs(i, c):
    return c.erreur_5xx() if 12 <= i < 26 and i % 4 == 0 else c.normal()


def _panne(i, c):
    return c.injoignable() if 10 <= i < 12 else c.normal()


def _panne_longue(i, c):
    return c.injoignable() if i >= 10 else c.normal()


def _clignotant(i, c):
    return c.injoignable() if i in (10, 13) else c.normal()


SCENARIOS: dict[str, tuple[str, Callable]] = {
    "normal": ("Site stable : rien ne doit se déclencher", _normal),
    "pic_isole": ("Une seule réponse à 6000 ms : doit être ignorée", _pic_isole),
    "ralentissement": ("Le site ralentit (~2500 ms) puis se rétablit : DEGRADE", _ralentissement),
    "surcharge": ("Surcharge sévère (~5000 ms) : CRITIQUE, sondes, reprise", _surcharge),
    "erreurs": ("Rafale d'erreurs 5xx : DEGRADE", _erreurs),
    "panne": ("Site injoignable brièvement : quarantaine puis reprise", _panne),
    "panne_longue": ("Site injoignable pour de bon : abandon (fail-closed)", _panne_longue),
    "clignotant": ("Site qui tombe, revient, retombe : compteur remis à zéro", _clignotant),
}


def creer_cible(nom: str, baseline: Baseline, graine: int = 42) -> CibleSimulee:
    if nom not in SCENARIOS:
        raise ValueError(f"Scénario inconnu : {nom!r}. Choix possibles : {', '.join(sorted(SCENARIOS))}")
    return CibleSimulee(SCENARIOS[nom][1], baseline, graine)