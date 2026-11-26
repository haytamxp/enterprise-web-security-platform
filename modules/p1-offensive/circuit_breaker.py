
#!/usr/bin/env python3
"""
Circuit Breaker — surveillance de la santé de la cible pendant un scan actif.

Fonctionnalités :
- Calibration à partir d'une baseline réelle.
- Chargement d'une baseline JSON.
- Surveillance des temps de réponse et des erreurs 5xx.
- Arrêt immédiat si la cible devient inaccessible.
- Quarantaine après une panne.
- Journalisation des changements d'état et des incidents.
"""

from __future__ import annotations

import json
import math
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from security_logger import enregistrer_evenement


class Etat(str, Enum):
    NORMAL = "normal"
    DEGRADE = "degrade"
    CRITIQUE = "critique"


@dataclass
class ResultatRequete:
    """Résultat observé après une requête."""

    temps_reponse_ms: float
    erreur_5xx: bool = False
    injoignable: bool = False


@dataclass
class Baseline:
    """Mesures de référence du comportement normal de la cible."""

    moyenne_ms: float
    ecart_type_ms: float
    nombre_echantillons: int


def etablir_baseline(temps_reponse_observes_ms: list[float]) -> Baseline:
    """Calcule la moyenne et l'écart-type des mesures."""

    if len(temps_reponse_observes_ms) < 2:
        raise ValueError(
            "Au moins 2 mesures sont nécessaires pour calculer un écart-type"
        )

    if any(not math.isfinite(x) or x < 0 for x in temps_reponse_observes_ms):
        raise ValueError("Les temps de réponse doivent être finis et positifs")

    moyenne = sum(temps_reponse_observes_ms) / len(temps_reponse_observes_ms)

    variance = sum(
        (x - moyenne) ** 2 for x in temps_reponse_observes_ms
    ) / len(temps_reponse_observes_ms)

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
    """Calcule les seuils à partir de la variabilité de la baseline."""

    variabilite = max(
        baseline.ecart_type_ms,
        baseline.moyenne_ms * plancher_variabilite_pct
    )

    seuil_degrade_ms = baseline.moyenne_ms + k_degrade * variabilite
    seuil_critique_ms = baseline.moyenne_ms + k_critique * variabilite

    return seuil_degrade_ms, seuil_critique_ms


@dataclass
class CircuitBreaker:
    """Surveille la santé de la cible pendant le scan."""

    seuil_degrade_ms: float
    seuil_critique_ms: float

    taille_fenetre: int = 10
    seuil_5xx_degrade: float = 0.20
    seuil_5xx_critique: float = 0.40

    nb_min_avant_jugement: int = 5
    succes_requis_apres_panne: int = 3

    _fenetre: deque[ResultatRequete] = field(
        default_factory=deque,
        init=False
    )

    _etat_actuel: Etat = field(
        default=Etat.NORMAL,
        init=False
    )

    _derniere_raison: str = field(
        default="Aucune requête observée pour l'instant",
        init=False
    )

    _succes_restants: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        """Vérifie la configuration."""

        if not (
            math.isfinite(self.seuil_degrade_ms)
            and math.isfinite(self.seuil_critique_ms)
            and 0 < self.seuil_degrade_ms < self.seuil_critique_ms
        ):
            raise ValueError("Les seuils de réponse sont invalides")

        if self.taille_fenetre < 1:
            raise ValueError("taille_fenetre doit être au moins 1")

        if not 1 <= self.nb_min_avant_jugement <= self.taille_fenetre:
            raise ValueError(
                "nb_min_avant_jugement doit être compris entre 1 "
                "et taille_fenetre"
            )

        if self.succes_requis_apres_panne < 1:
            raise ValueError("succes_requis_apres_panne doit être au moins 1")

        if not (
            0 <= self.seuil_5xx_degrade < self.seuil_5xx_critique <= 1
        ):
            raise ValueError("Les seuils 5xx sont invalides")

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
        """Construit un Circuit Breaker à partir d'une baseline."""

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

    @classmethod
    def depuis_fichier(
        cls,
        chemin: str | Path,
        taille_fenetre: int = 10,
        seuil_5xx_degrade: float = 0.20,
        seuil_5xx_critique: float = 0.40,
        nb_min_avant_jugement: int = 5,
        succes_requis_apres_panne: int = 3,
    ) -> "CircuitBreaker":
        """
        Charge les seuils calibrés depuis un fichier JSON.

        Le fichier doit contenir :
        - moyenne_ms
        - ecart_type_ms
        - nombre_echantillons
        - seuil_degrade_ms
        - seuil_critique_ms
        """

        chemin = Path(chemin)

        with chemin.open("r", encoding="utf-8") as fichier:
            donnees = json.load(fichier)

        champs_requis = (
            "moyenne_ms",
            "ecart_type_ms",
            "nombre_echantillons",
            "seuil_degrade_ms",
            "seuil_critique_ms",
        )

        for champ in champs_requis:
            if champ not in donnees:
                raise ValueError(
                    f"Champ manquant dans la baseline : {champ}"
                )

        valeurs = [
            donnees["moyenne_ms"],
            donnees["ecart_type_ms"],
            donnees["seuil_degrade_ms"],
            donnees["seuil_critique_ms"],
        ]

        if any(
            isinstance(valeur, bool)
            or not isinstance(valeur, (int, float))
            or not math.isfinite(valeur)
            for valeur in valeurs
        ):
            raise ValueError("La baseline contient des valeurs numériques invalides")

        nombre = donnees["nombre_echantillons"]

        if (
            isinstance(nombre, bool)
            or not isinstance(nombre, int)
            or nombre < 2
        ):
            raise ValueError("Nombre d'échantillons invalide")

        baseline = Baseline(
            moyenne_ms=float(donnees["moyenne_ms"]),
            ecart_type_ms=float(donnees["ecart_type_ms"]),
            nombre_echantillons=nombre,
        )

        if baseline.moyenne_ms <= 0 or baseline.ecart_type_ms < 0:
            raise ValueError("Les mesures de baseline sont invalides")

        # Vérifier que les seuils enregistrés correspondent
        # aux mesures et à la calibration standard.
        seuils_calcules = calibrer_seuils(baseline)

        seuils_fichier = (
            float(donnees["seuil_degrade_ms"]),
            float(donnees["seuil_critique_ms"]),
        )

        if not all(
            math.isclose(a, b, rel_tol=1e-6, abs_tol=1e-6)
            for a, b in zip(seuils_calcules, seuils_fichier)
        ):
            raise ValueError(
                "Les seuils du fichier ne correspondent pas à la baseline"
            )

        return cls(
            seuil_degrade_ms=seuils_fichier[0],
            seuil_critique_ms=seuils_fichier[1],
            taille_fenetre=taille_fenetre,
            seuil_5xx_degrade=seuil_5xx_degrade,
            seuil_5xx_critique=seuil_5xx_critique,
            nb_min_avant_jugement=nb_min_avant_jugement,
            succes_requis_apres_panne=succes_requis_apres_panne,
        )

    def _changer_etat(self, nouvel_etat: Etat, raison: str) -> None:
        """Change l'état et journalise uniquement les transitions."""

        ancien_etat = self._etat_actuel

        if ancien_etat != nouvel_etat:
            # Journaliser avant de modifier l'état.
            # Si l'écriture échoue, la transition n'est pas appliquée.
            enregistrer_evenement(
                event="circuit_breaker_state_change",
                details={
                    "previous_state": ancien_etat.value,
                    "new_state": nouvel_etat.value,
                    "reason": raison,
                    "seuil_degrade_ms": self.seuil_degrade_ms,
                    "seuil_critique_ms": self.seuil_critique_ms,
                }
            )

        self._etat_actuel = nouvel_etat
        self._derniere_raison = raison

    def enregistrer_resultat(self, resultat: ResultatRequete) -> Etat:
        """Enregistre une observation et réévalue la santé."""

        if (
            not math.isfinite(resultat.temps_reponse_ms)
            or resultat.temps_reponse_ms < 0
        ):
            raise ValueError("Temps de réponse invalide")

        if resultat.injoignable:
            self._succes_restants = self.succes_requis_apres_panne

            raison = (
                "Cible injoignable "
                "(timeout ou connexion refusée) — arrêt immédiat"
            )

            enregistrer_evenement(
                event="circuit_breaker_incident",
                details={
                    "reason": raison,
                    "trigger": "target_unreachable",
                    "action": "immediate_stop",
                }
            )

            self._changer_etat(Etat.CRITIQUE, raison)

            return self._etat_actuel

        self._fenetre.append(resultat)

        # Quarantaine après une panne.
        if self._succes_restants > 0:

            if self._est_saine(resultat):
                self._succes_restants -= 1
            else:
                self._succes_restants = self.succes_requis_apres_panne

            if self._succes_restants > 0:
                fait = (
                    self.succes_requis_apres_panne
                    - self._succes_restants
                )

                raison = (
                    f"Quarantaine après panne : {fait}/"
                    f"{self.succes_requis_apres_panne} "
                    "requêtes saines consécutives"
                )

                self._changer_etat(Etat.CRITIQUE, raison)

                return self._etat_actuel

            # La quarantaine est levée : réévaluation normale.

        self._reevaluer()

        return self._etat_actuel

    def _est_saine(self, resultat: ResultatRequete) -> bool:
        """Vérifie si une requête est saine."""

        return (
            not resultat.erreur_5xx
            and resultat.temps_reponse_ms < self.seuil_degrade_ms
        )

    def _reevaluer(self) -> None:
        """Évalue la santé de la cible avec la fenêtre glissante."""

        if not self._fenetre:
            return

        if len(self._fenetre) < self.nb_min_avant_jugement:
            raison = (
                f"Chauffe : {len(self._fenetre)}/"
                f"{self.nb_min_avant_jugement} "
                "requêtes observées avant de juger"
            )

            self._changer_etat(Etat.NORMAL, raison)
            return

        temps_moyen = (
            sum(r.temps_reponse_ms for r in self._fenetre)
            / len(self._fenetre)
        )

        taux_5xx = (
            sum(1 for r in self._fenetre if r.erreur_5xx)
            / len(self._fenetre)
        )

        if (
            temps_moyen >= self.seuil_critique_ms
            or taux_5xx >= self.seuil_5xx_critique
        ):
            nouvel_etat = Etat.CRITIQUE

            raison = (
                f"Critique : temps moyen {temps_moyen:.0f}ms "
                f"(seuil {self.seuil_critique_ms:.0f}ms), "
                f"taux 5xx {taux_5xx:.0%}"
            )

        elif (
            temps_moyen >= self.seuil_degrade_ms
            or taux_5xx >= self.seuil_5xx_degrade
        ):
            nouvel_etat = Etat.DEGRADE

            raison = (
                f"Dégradé : temps moyen {temps_moyen:.0f}ms "
                f"(seuil {self.seuil_degrade_ms:.0f}ms), "
                f"taux 5xx {taux_5xx:.0%}"
            )

        else:
            nouvel_etat = Etat.NORMAL

            raison = (
                f"Normal : temps moyen {temps_moyen:.0f}ms "
                f"(seuil dégradé {self.seuil_degrade_ms:.0f}ms), "
                f"taux 5xx {taux_5xx:.0%}"
            )

        self._changer_etat(nouvel_etat, raison)

    def etat(self) -> Etat:
        """Retourne l'état actuel."""

        return self._etat_actuel

    def raison(self) -> str:
        """Retourne la dernière raison enregistrée."""

        return self._derniere_raison

    def facteur_ralentissement(self) -> float:
        """
        1.0 = rythme normal
        2.0 = rythme deux fois plus lent
        infini = arrêt complet
        """

        if self._etat_actuel == Etat.CRITIQUE:
            return float("inf")

        if self._etat_actuel == Etat.DEGRADE:
            return 2.0

        return 1.0
