#!/usr/bin/env python3
"""
Boucle de scan pilotée par le Circuit Breaker — sous-étape 2.6.

Pourquoi ce fichier existe : le Circuit Breaker (circuit_breaker.py) sait
JUGER la santé de la cible, mais il n'agit pas. Ici on construit la boucle
qui lui OBÉIT : envoyer une requête, la lui montrer, lire sa décision,
puis agir en conséquence.

    NORMAL   -> on continue au rythme de base
    DEGRADE  -> on double le délai entre les requêtes
    CRITIQUE -> on arrête le scan et on passe en "mode sondes" : de petites
                requêtes de santé espacées, uniquement pour savoir si le
                site se rétablit. Si la cible ne se rétablit pas après
                `max_sondes` sondes, on ABANDONNE (fail-closed).

Choix de conception :
- La boucle ne sait PAS si les requêtes sont réelles ou simulées : elle
  reçoit une fonction `envoyer(est_sonde) -> ResultatRequete`. Plus tard, on
  lui donnera la vraie fonction HTTP (qui devra passer par le Scope Manager
  avant la moindre requête) sans toucher à cette boucle.
- Les pauses sont VIRTUELLES : on les additionne dans `temps_virtuel_s`
  sans vraiment attendre, pour pouvoir simuler 40 requêtes en une seconde.
- La boucle renvoie un journal d'événements, réutilisable par le dashboard
  (2.7) et la journalisation des incidents (2.8).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from circuit_breaker import CircuitBreaker, Etat, ResultatRequete

DELAI_BASE_S = 3.0     # pause normale entre deux requêtes (comme baseline_scan.py)
DELAI_SONDE_S = 30.0   # pause entre deux sondes de santé en état CRITIQUE
MAX_SONDES = 10        # sondes max par crise avant d'abandonner


@dataclass
class EvenementScan:
    """Une ligne du journal : ce qui s'est passé, et ce que le breaker en a conclu."""

    numero: int                          # ordre dans le journal (1, 2, 3...)
    genre: str                           # "requete" | "sonde" | "abandon"
    resultat: ResultatRequete | None     # None pour "abandon"
    etat: Etat                           # état du breaker APRÈS cet événement
    raison: str                          # explication fournie par le breaker
    delai_avant_suivante_s: float        # pause appliquée avant l'action suivante
    temps_virtuel_s: float               # moment (virtuel) où l'événement a eu lieu


@dataclass
class ResumeScan:
    evenements: list[EvenementScan] = field(default_factory=list)
    requetes_envoyees: int = 0
    sondes_envoyees: int = 0
    abandonne: bool = False
    raison_arret: str = ""
    temps_virtuel_s: float = 0.0


def executer_scan(
    envoyer: Callable[[bool], ResultatRequete],
    breaker: CircuitBreaker,
    nb_requetes: int,
    delai_base_s: float = DELAI_BASE_S,
    delai_sonde_s: float = DELAI_SONDE_S,
    max_sondes: int = MAX_SONDES,
    sur_evenement: Callable[[EvenementScan], None] | None = None,
) -> ResumeScan:
    """
    Exécute `nb_requetes` requêtes de scan en obéissant au Circuit Breaker.

    `envoyer(est_sonde)` envoie UNE requête (de scan si False, de sonde de
    santé si True) et renvoie son ResultatRequete.
    `sur_evenement` (optionnel) est appelé à chaque événement, au moment où
    il se produit : utile pour afficher en direct.
    """
    # Fail-closed : une configuration absurde échoue bruyamment.
    if nb_requetes < 1:
        raise ValueError("nb_requetes doit être au moins 1")
    if max_sondes < 1:
        raise ValueError("max_sondes doit être au moins 1")
    if delai_base_s < 0 or delai_sonde_s < 0:
        raise ValueError("les délais ne peuvent pas être négatifs")

    resume = ResumeScan()

    def noter(genre: str, resultat: ResultatRequete | None, etat: Etat, raison: str, delai: float) -> None:
        evenement = EvenementScan(
            numero=len(resume.evenements) + 1,
            genre=genre,
            resultat=resultat,
            etat=etat,
            raison=raison,
            delai_avant_suivante_s=delai,
            temps_virtuel_s=resume.temps_virtuel_s,
        )
        resume.evenements.append(evenement)
        resume.temps_virtuel_s += delai  # pause "virtuelle" : on la compte sans attendre
        if sur_evenement is not None:
            sur_evenement(evenement)

    for i in range(1, nb_requetes + 1):
        derniere = i == nb_requetes

        resultat = envoyer(False)
        etat = breaker.enregistrer_resultat(resultat)
        resume.requetes_envoyees += 1

        if derniere:
            delai = 0.0
        elif etat == Etat.CRITIQUE:
            delai = delai_sonde_s  # la prochaine action sera une sonde
        else:
            delai = delai_base_s * breaker.facteur_ralentissement()

        noter("requete", resultat, etat, breaker.raison(), delai)

        if etat != Etat.CRITIQUE or derniere:
            continue

        # --- Mode sondes : le scan est arrêté, on surveille la reprise ----
        sondes_crise = 0
        while breaker.etat() == Etat.CRITIQUE:
            if sondes_crise >= max_sondes:
                resume.abandonne = True
                resume.raison_arret = (
                    f"Cible toujours en état critique après {max_sondes} sondes de santé : "
                    f"scan abandonné (fail-closed)"
                )
                noter("abandon", None, Etat.CRITIQUE, resume.raison_arret, 0.0)
                return resume

            sondes_crise += 1
            resultat = envoyer(True)
            etat = breaker.enregistrer_resultat(resultat)
            resume.sondes_envoyees += 1

            if etat == Etat.CRITIQUE:
                delai = delai_sonde_s
            else:
                # La cible se rétablit : prochaine action = requête de scan,
                # avec le délai correspondant à l'état actuel (DEGRADE = x2).
                delai = delai_base_s * breaker.facteur_ralentissement()

            noter("sonde", resultat, etat, breaker.raison(), delai)

    return resume