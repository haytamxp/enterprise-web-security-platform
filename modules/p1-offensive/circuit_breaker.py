#!/usr/bin/env python3
"""
Circuit Breaker — surveillance de la santé de la cible pendant un scan actif.

Principe (voir sous-étape 2.1) :
Au lieu de fixer un débit fixe à l'avance, on observe en continu comment
la cible réagit (temps de réponse, erreurs, disponibilité) et on adapte
le débit en conséquence.

Mise à jour 2.3bis : les seuils de déclenchement ne sont plus des
multiplicateurs fixes choisis arbitrairement (x3, x6). Ils sont calculés
à partir du comportement RÉEL observé du site pendant la baseline :
moyenne + un nombre d'écarts-types, avec un plancher minimum pour éviter
qu'un site parfaitement stable ne déclenche des alertes au moindre
micro-écart.

Mise à jour 2.5bis (corrections découvertes par les tests de 2.5) :
  1. Période de chauffe : pas de jugement tant qu'on n'a pas assez de
     requêtes observées (une "moyenne" d'une seule valeur n'en est pas une).
  2. Seuils 5xx réalistes pour une fenêtre de 10 : 1 erreur isolée est
     tolérée, 2 erreurs ralentissent, 4 erreurs arrêtent.
  3. Quarantaine après "injoignable" : il faut plusieurs requêtes saines
     CONSÉCUTIVES avant de refaire confiance (anti-site-qui-clignote).
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field
from enum import Enum


class Etat(str, Enum):
    NORMAL = "normal"
    DEGRADE = "degrade"
    CRITIQUE = "critique"


@dataclass
class ResultatRequete:
    """Ce qu'on observe après chaque requête envoyée à la cible."""

    temps_reponse_ms: float
    erreur_5xx: bool = False
    injoignable: bool = False  # timeout / connexion refusée


@dataclass
class Baseline:
    """
    Résultat de la calibration (sous-étape 2.3bis) : pas juste une
    moyenne, mais aussi l'écart-type, pour connaître la variabilité
    NORMALE de ce site précis avant de fixer des seuils d'alerte.
    """

    moyenne_ms: float
    ecart_type_ms: float
    nombre_echantillons: int


def etablir_baseline(temps_reponse_observes_ms: list[float]) -> Baseline:
    """
    Calcule la moyenne ET l'écart-type d'une série de mesures prises
    AVANT le scan actif. L'écart-type dit à quel point ce site varie
    naturellement — c'est lui qui va déterminer des seuils adaptés à
    CE site précis, plutôt que des seuils génériques.

    Recommandation : mesurer plus que quelques requêtes rapprochées
    (idéalement étalées dans le temps) pour capturer la vraie
    variabilité du site, pas juste un instantané.
    """
    if len(temps_reponse_observes_ms) < 2:
        raise ValueError(
            "Au moins 2 mesures sont nécessaires pour calculer un écart-type "
            "(fail-closed : pas de baseline fiable avec trop peu de données)"
        )

    moyenne = sum(temps_reponse_observes_ms) / len(temps_reponse_observes_ms)
    variance = sum((x - moyenne) ** 2 for x in temps_reponse_observes_ms) / len(temps_reponse_observes_ms)
    ecart_type = math.sqrt(variance)

    return Baseline(
        moyenne_ms=moyenne,
        ecart_type_ms=ecart_type,
        nombre_echantillons=len(temps_reponse_observes_ms),
    )


def calibrer_seuils(
    baseline: Baseline,
    k_degrade: float = 3.0,
    k_critique: float = 6.0,
    plancher_variabilite_pct: float = 0.10,
) -> tuple[float, float]:
    """
    Transforme une Baseline en seuils ABSOLUS (en millisecondes), adaptés
    à la variabilité réelle du site.

    Le plancher (plancher_variabilite_pct) évite qu'un site anormalement
    stable (écart-type proche de 0) ne déclenche des alertes au moindre
    micro-écart : on considère toujours au moins 10% de la moyenne comme
    marge de variabilité normale.
    """
    variabilite = max(baseline.ecart_type_ms, baseline.moyenne_ms * plancher_variabilite_pct)

    seuil_degrade_ms = baseline.moyenne_ms + k_degrade * variabilite
    seuil_critique_ms = baseline.moyenne_ms + k_critique * variabilite

    return seuil_degrade_ms, seuil_critique_ms


@dataclass
class CircuitBreaker:
    """
    Surveille une fenêtre glissante des dernières requêtes. Les seuils de
    temps de réponse sont des valeurs ABSOLUES en ms, calculées par
    calibrer_seuils() à partir du vrai comportement du site.
    """

    seuil_degrade_ms: float
    seuil_critique_ms: float
    taille_fenetre: int = 10
    # 2.5bis (correction 2) : sur une fenêtre de 10, une erreur = 10 %.
    # Des seuils de 2 % / 5 % n'avaient donc aucun sens (1 erreur isolée
    # déclenchait CRITIQUE). Nouveaux seuils : 2 erreurs sur 10 = ralentir,
    # 4 erreurs sur 10 = arrêter.
    seuil_5xx_degrade: float = 0.20
    seuil_5xx_critique: float = 0.40
    # 2.5bis (correction 1) : nombre minimum de requêtes observées avant
    # de juger la santé (hors cas "injoignable", jamais retardé).
    nb_min_avant_jugement: int = 5
    # 2.5bis (correction 3) : requêtes saines CONSÉCUTIVES exigées après
    # un "injoignable" avant de refaire confiance à la cible.
    succes_requis_apres_panne: int = 3

    _fenetre: deque[ResultatRequete] = field(default_factory=deque, init=False)
    _etat_actuel: Etat = field(default=Etat.NORMAL, init=False)
    _derniere_raison: str = field(default="Aucune requête observée pour l'instant", init=False)
    _succes_restants: int = field(default=0, init=False)  # > 0 = quarantaine en cours

    def __post_init__(self) -> None:
        # Fail-closed : une configuration absurde doit échouer bruyamment.
        # Si nb_min_avant_jugement > taille_fenetre, la fenêtre n'atteindrait
        # jamais le minimum et le breaker ne jugerait JAMAIS rien.
        if self.nb_min_avant_jugement > self.taille_fenetre:
            raise ValueError(
                "nb_min_avant_jugement ne peut pas dépasser taille_fenetre "
                "(le breaker ne jugerait jamais rien)"
            )
        if self.nb_min_avant_jugement < 1:
            raise ValueError("nb_min_avant_jugement doit être au moins 1")
        if self.succes_requis_apres_panne < 1:
            raise ValueError("succes_requis_apres_panne doit être au moins 1")
        self._fenetre = deque(maxlen=self.taille_fenetre)

    @classmethod
    def depuis_baseline(
        cls,
        baseline: Baseline,
        taille_fenetre: int = 10,
        seuil_5xx_degrade: float = 0.20,
        seuil_5xx_critique: float = 0.40,
        nb_min_avant_jugement: int = 5,
        succes_requis_apres_panne: int = 3,
    ) -> "CircuitBreaker":
        """Raccourci pratique : baseline -> seuils calibrés -> CircuitBreaker prêt à l'emploi."""
        seuil_degrade_ms, seuil_critique_ms = calibrer_seuils(baseline)
        return cls(
            seuil_degrade_ms=seuil_degrade_ms,
            seuil_critique_ms=seuil_critique_ms,
            taille_fenetre=taille_fenetre,
            seuil_5xx_degrade=seuil_5xx_degrade,
            seuil_5xx_critique=seuil_5xx_critique,
            nb_min_avant_jugement=nb_min_avant_jugement,
            succes_requis_apres_panne=succes_requis_apres_panne,
        )

    def enregistrer_resultat(self, resultat: ResultatRequete) -> Etat:
        # Piège 3 (voir 2.3) : "injoignable" est traité AVANT toute moyenne,
        # en réaction immédiate. Il (re)lance aussi la quarantaine.
        if resultat.injoignable:
            self._succes_restants = self.succes_requis_apres_panne
            self._etat_actuel = Etat.CRITIQUE
            self._derniere_raison = "Cible injoignable (timeout ou connexion refusée) — arrêt immédiat"
            return self._etat_actuel

        self._fenetre.append(resultat)

        # Quarantaine : tant qu'on n'a pas vu assez de requêtes saines
        # CONSÉCUTIVES, on reste en CRITIQUE. Une requête non saine remet
        # le compteur à zéro.
        if self._succes_restants > 0:
            if self._est_saine(resultat):
                self._succes_restants -= 1
            else:
                self._succes_restants = self.succes_requis_apres_panne

            if self._succes_restants > 0:
                fait = self.succes_requis_apres_panne - self._succes_restants
                self._etat_actuel = Etat.CRITIQUE
                self._derniere_raison = (
                    f"Quarantaine après panne : {fait}/{self.succes_requis_apres_panne} "
                    f"requêtes saines consécutives"
                )
                return self._etat_actuel
            # compteur tombé à 0 : la quarantaine est levée, on réévalue normalement

        self._reevaluer()
        return self._etat_actuel

    def _est_saine(self, resultat: ResultatRequete) -> bool:
        """Une requête est 'saine' si pas d'erreur 5xx et temps sous le seuil dégradé."""
        return (not resultat.erreur_5xx) and resultat.temps_reponse_ms < self.seuil_degrade_ms

    def _reevaluer(self) -> None:
        if not self._fenetre:
            return

        # Chauffe : pas assez de requêtes pour calculer une moyenne qui
        # veuille dire quelque chose -> on ne juge pas encore.
        if len(self._fenetre) < self.nb_min_avant_jugement:
            self._etat_actuel = Etat.NORMAL
            self._derniere_raison = (
                f"Chauffe : {len(self._fenetre)}/{self.nb_min_avant_jugement} "
                f"requêtes observées avant de juger"
            )
            return

        temps_moyen = sum(r.temps_reponse_ms for r in self._fenetre) / len(self._fenetre)
        taux_5xx = sum(1 for r in self._fenetre if r.erreur_5xx) / len(self._fenetre)

        if temps_moyen >= self.seuil_critique_ms or taux_5xx >= self.seuil_5xx_critique:
            self._etat_actuel = Etat.CRITIQUE
            self._derniere_raison = (
                f"Critique : temps moyen {temps_moyen:.0f}ms (seuil {self.seuil_critique_ms:.0f}ms), "
                f"taux 5xx {taux_5xx:.0%}"
            )
        elif temps_moyen >= self.seuil_degrade_ms or taux_5xx >= self.seuil_5xx_degrade:
            self._etat_actuel = Etat.DEGRADE
            self._derniere_raison = (
                f"Dégradé : temps moyen {temps_moyen:.0f}ms (seuil {self.seuil_degrade_ms:.0f}ms), "
                f"taux 5xx {taux_5xx:.0%}"
            )
        else:
            # Piège 4 : on redescend bien à NORMAL si la fenêtre récente
            # est redevenue saine.
            self._etat_actuel = Etat.NORMAL
            self._derniere_raison = (
                f"Normal : temps moyen {temps_moyen:.0f}ms (seuil dégradé {self.seuil_degrade_ms:.0f}ms), "
                f"taux 5xx {taux_5xx:.0%}"
            )

    def etat(self) -> Etat:
        return self._etat_actuel

    def raison(self) -> str:
        return self._derniere_raison

    def facteur_ralentissement(self) -> float:
        """
        Multiplicateur à appliquer au délai entre requêtes.
        1.0 = rythme normal, 2.0 = deux fois plus lent, etc.
        """
        if self._etat_actuel == Etat.CRITIQUE:
            return float("inf")  # arrêt complet, pas juste un ralentissement
        if self._etat_actuel == Etat.DEGRADE:
            return 2.0
        return 1.0