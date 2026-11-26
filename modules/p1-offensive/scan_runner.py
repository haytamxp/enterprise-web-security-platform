
#!/usr/bin/env python3
"""
Scan Runner — orchestrateur central du scan actif P1.

Responsabilités :
- Charger la whitelist et la baseline.
- Vérifier la cible avec le Target Gate.
- Initialiser le Circuit Breaker.
- Construire le Network Client.
- Exécuter la boucle de scan.
- Retourner un résumé structuré.

Sécurité :
- Aucune confirmation humaine n'est définie en dur.
- Chaque requête est validée par le Target Gate.
- Les requêtes sont exclusivement des GET.
- Le Circuit Breaker contrôle chaque résultat.
- Le mode réel doit être explicitement activé.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from core import charger_baseline, charger_whitelist
from circuit_breaker import CircuitBreaker
from network_client import NetworkClient, OperationReseauRefusee
from scan_loop import executer_scan, ResumeScan
from target_gate import TargetGate


@dataclass
class ScanRunnerResult:
    """Résultat global de l'exécution."""

    success: bool
    message: str
    resume: Optional[ResumeScan] = None


def lancer_scan(
    url: str,
    user_confirmed: bool,
    nb_requetes: int = 5,
    attendre_reellement: bool = False,
) -> ScanRunnerResult:
    """
    Prépare et lance un scan contrôlé.

    Paramètres :
        url:
            URL cible.

        user_confirmed:
            Confirmation explicite provenant de l'utilisateur.

        nb_requetes:
            Nombre maximal de requêtes normales.

        attendre_reellement:
            False : pauses virtuelles, sans attente réelle.
            True  : applique les délais réels entre les requêtes.

    Retour :
        ScanRunnerResult contenant le statut et le résumé.
    """

    # 1. Vérifier la confirmation humaine.
    if user_confirmed is not True:
        return ScanRunnerResult(
            success=False,
            message="Scan refusé : confirmation humaine absente."
        )

    # 2. Charger la whitelist.
    try:
        whitelist = charger_whitelist()
    except Exception as erreur:
        return ScanRunnerResult(
            success=False,
            message=f"Impossible de charger la whitelist : {erreur}"
        )

    # 3. Initialiser le Target Gate.
    try:
        target_gate = TargetGate(whitelist)
    except Exception as erreur:
        return ScanRunnerResult(
            success=False,
            message=f"Initialisation du Target Gate impossible : {erreur}"
        )

    # 4. Valider la cible avant toute initialisation du scan.
    try:
        decision = target_gate.validate(url, user_confirmed)
    except Exception as erreur:
        return ScanRunnerResult(
            success=False,
            message=f"Erreur lors de la validation de la cible : {erreur}"
        )

    if not decision.authorized:
        return ScanRunnerResult(
            success=False,
            message=f"Cible refusée par le Target Gate : {decision.reason}"
        )

    # 5. Charger la baseline.
    try:
        baseline = charger_baseline()
    except Exception as erreur:
        return ScanRunnerResult(
            success=False,
            message=f"Baseline indisponible ou invalide : {erreur}"
        )

    # 6. Initialiser le Circuit Breaker.
    try:
        breaker = CircuitBreaker.depuis_baseline(baseline)
    except Exception as erreur:
        return ScanRunnerResult(
            success=False,
            message=f"Initialisation du Circuit Breaker impossible : {erreur}"
        )

    # 7. Initialiser le client réseau.
    try:
        client = NetworkClient(
            url=url,
            target_gate=target_gate,
            breaker=breaker,
            user_confirmed=user_confirmed,
        )
    except Exception as erreur:
        return ScanRunnerResult(
            success=False,
            message=f"Initialisation du client réseau impossible : {erreur}"
        )

    # 8. Exécuter la boucle de scan.
    try:
        resume = executer_scan(
            envoyer=client.envoyer,
            breaker=breaker,
            nb_requetes=nb_requetes,
            attendre_reellement=attendre_reellement,
        )

    except OperationReseauRefusee as erreur:
        return ScanRunnerResult(
            success=False,
            message=f"Opération réseau refusée : {erreur}"
        )

    except Exception as erreur:
        return ScanRunnerResult(
            success=False,
            message=f"Échec du scan : {erreur}"
        )

    # 9. Retourner le résultat.
    return ScanRunnerResult(
        success=True,
        message="Exécution du scan terminée.",
        resume=resume,
    )
