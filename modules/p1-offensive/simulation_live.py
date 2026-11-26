#!/usr/bin/env python3
"""
Simulation de scan "en direct" pour le dashboard — sous-étape 2.7.

Pourquoi ce fichier existe : le dashboard doit pouvoir LANCER une simulation
(scan_loop.py + simulation.py) et la laisser tourner PENDANT que le serveur
Flask continue de répondre aux navigateurs. On la fait donc tourner dans un
thread d'arrière-plan ; ce fichier garde l'état courant à un endroit unique,
protégé par un verrou, que app.py se contente de lire.

Règles de sécurité :
- UNE SEULE simulation à la fois (double clic, deux onglets : le 2e lancement
  est refusé côté serveur, pas seulement en grisant un bouton).
- Un bouton d'arrêt : un humain peut toujours couper la boucle.
- Si le thread plante, l'état passe à "erreur" au lieu de rester bloqué sur
  "en cours" (sinon on ne pourrait plus jamais relancer).
- SIMULÉ uniquement : aucune requête réelle ne part d'ici.
"""

from __future__ import annotations

import threading
from typing import Callable

from circuit_breaker import Baseline, CircuitBreaker
from core import charger_baseline
from scan_loop import EvenementScan, executer_scan
from simulation import SCENARIOS, creer_cible

NB_REQUETES_MAX = 200


class SimulationDejaEnCours(RuntimeError):
    """Une simulation tourne déjà : on refuse d'en lancer une deuxième."""


class ParametresInvalides(ValueError):
    """Scénario inconnu ou nombre de requêtes hors limites."""


class _ArretDemande(Exception):
    """Lancée depuis le callback pour interrompre la boucle quand l'humain clique sur Arrêter."""


class GestionnaireSimulation:
    def __init__(
        self,
        delai_affichage_s: float = 0.5,
        charger_baseline_fn: Callable[[], Baseline] = charger_baseline,
    ):
        # Pause RÉELLE entre deux événements, uniquement pour que l'humain
        # puisse suivre à l'écran (les pauses de la boucle, elles, restent virtuelles).
        self._delai_affichage_s = delai_affichage_s
        self._charger_baseline = charger_baseline_fn
        self._verrou = threading.Lock()
        self._arret = threading.Event()
        self._thread: threading.Thread | None = None
        self._remettre_a_zero()

    # ------------------------------------------------------------------
    def _remettre_a_zero(self) -> None:
        self._statut = "inactif"  # inactif | en_cours | termine | abandonne | arrete | erreur
        self._scenario: str | None = None
        self._nb_requetes = 0
        self._etat: str | None = None
        self._raison = ""
        self._requetes = 0
        self._sondes = 0
        self._temps_virtuel_s = 0.0
        self._evenements: list[dict] = []
        self._message_erreur = ""

    # ------------------------------------------------------------------
    def demarrer(self, scenario: str, nb_requetes: int) -> None:
        if scenario not in SCENARIOS:
            raise ParametresInvalides(f"Scénario inconnu : {scenario!r}")
        if not 1 <= nb_requetes <= NB_REQUETES_MAX:
            raise ParametresInvalides(f"Le nombre de requêtes doit être entre 1 et {NB_REQUETES_MAX}")

        with self._verrou:
            if self._statut == "en_cours":
                raise SimulationDejaEnCours("Une simulation est déjà en cours : arrête-la ou attends sa fin.")

            # Si la baseline manque ou est invalide, ça échoue ICI, avant
            # tout changement d'état : on ne reste pas coincé sur "en cours".
            baseline = self._charger_baseline()
            breaker = CircuitBreaker.depuis_baseline(baseline)
            cible = creer_cible(scenario, baseline)

            self._remettre_a_zero()
            self._statut = "en_cours"
            self._scenario = scenario
            self._nb_requetes = nb_requetes
            self._arret.clear()

            self._thread = threading.Thread(
                target=self._executer, args=(cible, breaker, nb_requetes), daemon=True
            )
            self._thread.start()

    def arreter(self) -> bool:
        """Demande l'arrêt. Renvoie False s'il n'y avait rien à arrêter."""
        with self._verrou:
            if self._statut != "en_cours":
                return False
            self._arret.set()
            return True

    def attendre_fin(self, timeout: float = 10.0) -> None:
        """Bloque jusqu'à la fin du thread (utile pour les tests)."""
        thread = self._thread
        if thread is not None:
            thread.join(timeout)

    # ------------------------------------------------------------------
    def _executer(self, cible, breaker, nb_requetes: int) -> None:
        try:
            resume = executer_scan(cible.envoyer, breaker, nb_requetes, sur_evenement=self._sur_evenement)
            with self._verrou:
                self._temps_virtuel_s = resume.temps_virtuel_s
                self._statut = "abandonne" if resume.abandonne else "termine"
        except _ArretDemande:
            with self._verrou:
                self._statut = "arrete"
        except Exception as e:  # noqa: BLE001 - on ne veut JAMAIS rester bloqué sur "en cours"
            with self._verrou:
                self._statut = "erreur"
                self._message_erreur = f"{type(e).__name__} : {e}"

    def _sur_evenement(self, ev: EvenementScan) -> None:
        with self._verrou:
            self._evenements.append(
                {
                    "numero": ev.numero,
                    "genre": ev.genre,
                    "temps_reponse_ms": None if ev.resultat is None else ev.resultat.temps_reponse_ms,
                    "erreur_5xx": False if ev.resultat is None else ev.resultat.erreur_5xx,
                    "injoignable": False if ev.resultat is None else ev.resultat.injoignable,
                    "etat": ev.etat.value,
                    "raison": ev.raison,
                    "delai_avant_suivante_s": ev.delai_avant_suivante_s,
                    "temps_virtuel_s": ev.temps_virtuel_s,
                }
            )
            self._etat = ev.etat.value
            self._raison = ev.raison
            self._temps_virtuel_s = ev.temps_virtuel_s
            if ev.genre == "requete":
                self._requetes += 1
            elif ev.genre == "sonde":
                self._sondes += 1

        # Pause d'affichage ET point de contrôle de l'arrêt : wait() rend la
        # main tout de suite si l'humain a cliqué sur Arrêter.
        if self._arret.wait(self._delai_affichage_s):
            raise _ArretDemande()

    # ------------------------------------------------------------------
    def instantane(self) -> dict:
        """Photo de l'état courant, prête à être envoyée en JSON au navigateur."""
        with self._verrou:
            return {
                "statut": self._statut,
                "scenario": self._scenario,
                "nb_requetes": self._nb_requetes,
                "etat": self._etat,
                "raison": self._raison,
                "requetes_envoyees": self._requetes,
                "sondes_envoyees": self._sondes,
                "temps_virtuel_s": self._temps_virtuel_s,
                "message_erreur": self._message_erreur,
                "evenements": list(self._evenements),
            }