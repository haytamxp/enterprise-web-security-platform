
#!/usr/bin/env python3
"""
Target Gate — Barrière centrale de sécurité du module P1.

Responsabilités :
- Exiger une confirmation humaine explicite.
- Valider le format et la structure de la cible.
- Vérifier la présence et l'intégrité de la whitelist.
- Déléguer la validation du périmètre au Scope Manager.
- Centraliser la décision AUTORISÉ / REFUSÉ.
- Garantir un comportement FAIL-CLOSED.
- Fournir une décision structurée et traçable.

Sécurité :
- Aucun appel réseau.
- Aucun appel au LLM.
- Aucune modification de la whitelist.
- Aucun élargissement du périmètre.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from scope_manager import ScopeEntry, is_authorized


@dataclass(frozen=True)
class TargetDecision:
    """Résultat structuré d'une validation de cible."""

    authorized: bool
    target: str
    reason: str
    timestamp: str
    checks: dict[str, bool]

    def to_dict(self) -> dict:
        """Convertit la décision en dictionnaire JSON-compatible."""
        return {
            "authorized": self.authorized,
            "target": self.target,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "checks": dict(self.checks),
        }


class TargetGate:
    """
    Barrière centrale obligatoire avant toute opération P1.

    Le Target Gate ne remplace pas le Scope Manager.
    Il centralise les contrôles et applique une décision finale.
    """

    def __init__(
        self,
        whitelist: list[ScopeEntry],
    ):
        self.whitelist = whitelist

    @staticmethod
    def _decision(
        authorized: bool,
        target: str,
        reason: str,
        checks: dict[str, bool],
    ) -> TargetDecision:
        return TargetDecision(
            authorized=authorized,
            target=target,
            reason=reason,
            timestamp=datetime.now(timezone.utc).isoformat(),
            checks=checks,
        )

    def validate(
        self,
        url: str,
        user_confirmed: bool,
    ) -> TargetDecision:
        """
        Effectue tous les contrôles avant d'autoriser une opération.

        Toute anomalie entraîne un refus.
        """

        checks = {
            "human_confirmation": False,
            "target_format": False,
            "whitelist_integrity": False,
            "scope_validation": False,
        }

        # 1. Confirmation humaine explicite
        if user_confirmed is not True:
            return self._decision(
                False,
                url if isinstance(url, str) else "",
                "REFUSÉ : confirmation humaine explicite absente.",
                checks,
            )

        checks["human_confirmation"] = True

        # 2. Validation de la cible
        if not isinstance(url, str) or not url.strip():
            return self._decision(
                False,
                "",
                "REFUSÉ : URL absente ou invalide.",
                checks,
            )

        target = url.strip()

        if any(ord(char) < 32 or ord(char) == 127 for char in target):
            return self._decision(
                False,
                target,
                "REFUSÉ : caractères de contrôle interdits dans l'URL.",
                checks,
            )

        checks["target_format"] = True

        # 3. Intégrité de la whitelist
        if not isinstance(self.whitelist, list) or not self.whitelist:
            return self._decision(
                False,
                target,
                "REFUSÉ : whitelist absente ou invalide.",
                checks,
            )

        if not all(
            isinstance(entry, ScopeEntry)
            for entry in self.whitelist
        ):
            return self._decision(
                False,
                target,
                "REFUSÉ : format de whitelist invalide.",
                checks,
            )

        checks["whitelist_integrity"] = True

        # 4. Validation par le Scope Manager
        try:
            authorized, reason = is_authorized(
                target,
                self.whitelist,
            )

            if not isinstance(authorized, bool):
                raise TypeError("Réponse invalide du Scope Manager")

            if not isinstance(reason, str):
                raise TypeError("Motif de validation invalide")

        except Exception:
            return self._decision(
                False,
                target,
                "REFUSÉ : erreur interne pendant la vérification du périmètre.",
                checks,
            )

        checks["scope_validation"] = True

        # 5. Décision finale
        if not authorized:
            return self._decision(
                False,
                target,
                f"REFUSÉ par le Scope Manager : {reason}",
                checks,
            )

        return self._decision(
            True,
            target,
            f"TARGET VALIDÉ : {reason}",
            checks,
        )


def validate_target(
    url: str,
    user_confirmed: bool,
    whitelist: list[ScopeEntry],
) -> tuple[bool, str]:
    """
    Interface de compatibilité avec les 11 tests existants.

    Les anciens composants peuvent continuer à utiliser :
        authorized, reason = validate_target(...)
    """

    try:
        gate = TargetGate(whitelist)
        decision = gate.validate(url, user_confirmed)

        return decision.authorized, decision.reason

    except Exception:
        return (
            False,
            "REFUSÉ : erreur interne du Target Gate.",
        )
