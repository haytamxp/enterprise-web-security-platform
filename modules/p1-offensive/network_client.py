
#!/usr/bin/env python3
"""
Client réseau sécurisé pour le module P1.

Responsabilités :
- Valider chaque opération avec le Target Gate.
- Effectuer uniquement des requêtes HTTP GET.
- Ne jamais suivre automatiquement les redirections.
- Mesurer le temps de réponse.
- Transmettre les résultats au Circuit Breaker.
- Refuser les opérations hors périmètre.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request

from circuit_breaker import (
    CircuitBreaker,
    Etat,
    ResultatRequete,
)
from target_gate import TargetGate


class OperationReseauRefusee(Exception):
    """Une opération réseau a été refusée par les contrôles de sécurité."""


class RedirectHandler(urllib.request.HTTPRedirectHandler):
    """Empêche tout suivi automatique des redirections."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class NetworkClient:
    """Client HTTP contrôlé par le Target Gate et le Circuit Breaker."""

    def __init__(
        self,
        url: str,
        target_gate: TargetGate,
        breaker: CircuitBreaker,
        user_confirmed: bool,
        timeout: float = 5.0,
    ):
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("Le timeout doit être strictement positif")

        self.url = url
        self.target_gate = target_gate
        self.breaker = breaker
        self.user_confirmed = user_confirmed
        self.timeout = float(timeout)

        self.opener = urllib.request.build_opener(
            RedirectHandler()
        )

    def envoyer(self, est_sonde: bool = False) -> ResultatRequete:
        """
        Envoie une requête GET contrôlée.

        Une sonde est autorisée pendant l'état CRITIQUE.
        Une requête de scan normale ne l'est jamais.
        """

        # 1. Empêcher toute opération normale en état critique.
        if self.breaker.etat() == Etat.CRITIQUE and not est_sonde:
            raise OperationReseauRefusee(
                "Opération refusée : Circuit Breaker en état critique."
            )

        # 2. Vérifier à nouveau le périmètre avant chaque requête.
        decision = self.target_gate.validate(
            self.url,
            self.user_confirmed,
        )

        if not decision.authorized:
            raise OperationReseauRefusee(
                f"Opération refusée par le Target Gate : {decision.reason}"
            )

        # 3. Préparer une requête légère.
        requete = urllib.request.Request(
            self.url,
            method="GET",
            headers={
                "User-Agent": "P1-Security-Scanner/1.0",
                "Range": "bytes=0-0",
                "Accept": "*/*",
                "Connection": "close",
            },
        )

        debut = time.perf_counter()

        try:
            with self.opener.open(
                requete,
                timeout=self.timeout,
            ) as reponse:
                statut = reponse.status

            duree_ms = (time.perf_counter() - debut) * 1000

            return ResultatRequete(
                temps_reponse_ms=duree_ms,
                erreur_5xx=500 <= statut <= 599,
                injoignable=False,
            )

        except urllib.error.HTTPError as erreur:
            duree_ms = (time.perf_counter() - debut) * 1000

            # Les réponses HTTP 3xx ne sont pas suivies.
            return ResultatRequete(
                temps_reponse_ms=duree_ms,
                erreur_5xx=500 <= erreur.code <= 599,
                injoignable=False,
            )

        except (
            urllib.error.URLError,
            TimeoutError,
            ConnectionError,
            OSError,
        ):
            duree_ms = (time.perf_counter() - debut) * 1000

            return ResultatRequete(
                temps_reponse_ms=duree_ms,
                erreur_5xx=False,
                injoignable=True,
            )
