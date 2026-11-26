
#!/usr/bin/env python3
"""
Boucle de scan contrôlée par le Circuit Breaker.

NORMAL   : rythme normal.
DEGRADE  : délai multiplié par deux.
CRITIQUE : arrêt du scan normal et passage en mode sondes.
"""

from __future__ import annotations

import math
import time

from dataclasses import dataclass, field
from typing import Callable

from circuit_breaker import (
    CircuitBreaker,
    Etat,
    ResultatRequete,
)


DELAI_BASE_S = 3.0
DELAI_SONDE_S = 30.0
MAX_SONDES = 10


@dataclass
class EvenementScan:
    numero: int
    genre: str
    resultat: ResultatRequete | None
    etat: Etat
    raison: str
    delai_avant_suivante_s: float
    temps_virtuel_s: float


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
    attendre_reellement: bool = False,
) -> ResumeScan:

    if (
        isinstance(nb_requetes, bool)
        or not isinstance(nb_requetes, int)
        or nb_requetes < 1
    ):
        raise ValueError("nb_requetes doit être un entier positif")

    if (
        isinstance(max_sondes, bool)
        or not isinstance(max_sondes, int)
        or max_sondes < 1
    ):
        raise ValueError("max_sondes doit être un entier positif")

    if (
        not math.isfinite(delai_base_s)
        or not math.isfinite(delai_sonde_s)
        or delai_base_s < 0
        or delai_sonde_s < 0
    ):
        raise ValueError("Les délais doivent être finis et positifs")

    resume = ResumeScan()

    def noter(
        genre: str,
        resultat: ResultatRequete | None,
        etat: Etat,
        raison: str,
        delai: float,
    ) -> None:

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

        if sur_evenement is not None:
            sur_evenement(evenement)

        resume.temps_virtuel_s += delai

        if attendre_reellement and delai > 0:
            time.sleep(delai)

    for i in range(1, nb_requetes + 1):

        derniere = i == nb_requetes

        # Une requête normale ne doit jamais contourner
        # un Circuit Breaker critique.
        if breaker.etat() == Etat.CRITIQUE:
            resume.abandonne = True
            resume.raison_arret = (
                "Requête normale bloquée : état critique."
            )
            noter(
                "abandon",
                None,
                Etat.CRITIQUE,
                resume.raison_arret,
                0.0,
            )
            return resume

        resultat = envoyer(False)

        if not isinstance(resultat, ResultatRequete):
            raise TypeError(
                "La fonction envoyer doit retourner ResultatRequete"
            )

        etat = breaker.enregistrer_resultat(resultat)
        resume.requetes_envoyees += 1

        if derniere:
            delai = 0.0
        elif etat == Etat.CRITIQUE:
            delai = delai_sonde_s
        else:
            delai = (
                delai_base_s * breaker.facteur_ralentissement()
            )

        noter(
            "requete",
            resultat,
            etat,
            breaker.raison(),
            delai,
        )

        if etat != Etat.CRITIQUE or derniere:
            continue

        sondes_crise = 0

        while breaker.etat() == Etat.CRITIQUE:

            if sondes_crise >= max_sondes:
                resume.abandonne = True
                resume.raison_arret = (
                f"Cible toujours critique après "
                f"{max_sondes} sondes : scan abandonné (fail-closed)."
            )

                noter(
                    "abandon",
                    None,
                    Etat.CRITIQUE,
                    resume.raison_arret,
                    0.0,
                )
                return resume

            sondes_crise += 1

            resultat = envoyer(True)

            if not isinstance(resultat, ResultatRequete):
                raise TypeError(
                    "La fonction envoyer doit retourner ResultatRequete"
                )

            etat = breaker.enregistrer_resultat(resultat)
            resume.sondes_envoyees += 1

            if etat == Etat.CRITIQUE:
                delai = delai_sonde_s
            else:
                delai = (
                    delai_base_s * breaker.facteur_ralentissement()
                )

            noter(
                "sonde",
                resultat,
                etat,
                breaker.raison(),
                delai,
            )

    return resume
