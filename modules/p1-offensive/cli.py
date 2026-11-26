
#!/usr/bin/env python3
"""
CLI du module P1 — vérification centralisée par Target Gate.

Deux usages :
  python cli.py
  python cli.py simuler <scenario>

La simulation reste indépendante du Target Gate :
elle n'envoie aucune requête réelle.
"""

from __future__ import annotations

import argparse
import time

from circuit_breaker import CircuitBreaker, Etat
from core import charger_baseline, charger_whitelist, journaliser
from scan_loop import EvenementScan, ResumeScan, executer_scan
from target_gate import validate_target
from simulation import SCENARIOS, creer_cible


ICONES = {
    Etat.NORMAL: "🟢",
    Etat.DEGRADE: "🟠",
    Etat.CRITIQUE: "🔴"
}

LIBELLES = {
    "requete": "requête",
    "sonde": "sonde",
    "abandon": "ABANDON"
}


def verifier_perimetre() -> None:

    print("=" * 60)
    print("Target Gate — vérification de cible (CLI)")
    print("=" * 60)

    whitelist = charger_whitelist()

    url = input("\nQuelle URL voulez-vous tester ? ").strip()

    reponse = input(
        "Confirmez-vous disposer d'une autorisation écrite valide "
        "pour tester cette cible ? (oui/non) : "
    ).strip().lower()

    confirme = reponse in ("oui", "o", "yes", "y")

    autorise, raison = validate_target(
        url=url,
        user_confirmed=confirme,
        whitelist=whitelist
    )

    journaliser(
        url,
        confirme,
        autorise,
        raison,
        source="cli"
    )

    print()

    if autorise:
        print(f"✅ AUTORISÉ — {raison}")
    else:
        print(f"❌ REFUSÉ — {raison}")

    print("\nVérification enregistrée dans scope_manager.log.")


def formater_evenement(ev: EvenementScan) -> str:

    if ev.resultat is None:
        mesure = "—"

    elif ev.resultat.injoignable:
        mesure = "INJOIGNABLE"

    else:
        mesure = f"{ev.resultat.temps_reponse_ms:.0f} ms"

        if ev.resultat.erreur_5xx:
            mesure += " +5xx"

    return (
        f"#{ev.numero:02d} {LIBELLES[ev.genre]:<8} "
        f"{mesure:>14}  "
        f"{ICONES[ev.etat]} {ev.etat.value.upper():<8} | "
        f"{ev.raison}"
    )


def afficher_resume(resume: ResumeScan, etat_final: Etat) -> None:

    print("\n" + "-" * 60)
    print("Résumé de la simulation")
    print("-" * 60)

    print(f"Requêtes de scan envoyées : {resume.requetes_envoyees}")
    print(f"Sondes de santé envoyées  : {resume.sondes_envoyees}")
    print(f"État final                : {ICONES[etat_final]} {etat_final.value.upper()}")
    print(f"Durée simulée             : {resume.temps_virtuel_s / 60:.1f} min")

    if resume.abandonne:
        print(f"\n⛔ SCAN ABANDONNÉ — {resume.raison_arret}")
    else:
        print("\n✅ Simulation terminée sans abandon.")


def simuler(scenario: str, nb_requetes: int, lent: bool) -> None:

    baseline = charger_baseline()
    breaker = CircuitBreaker.depuis_baseline(baseline)
    cible = creer_cible(scenario, baseline)

    print("=" * 60)
    print(f"SIMULATION — scénario « {scenario} »")
    print(SCENARIOS[scenario][0])
    print("⚠️ Aucune requête réelle n'est envoyée.")
    print("=" * 60)

    print(
        f"Baseline : moyenne {baseline.moyenne_ms:.0f} ms, "
        f"écart-type {baseline.ecart_type_ms:.0f} ms | "
        f"seuil dégradé {breaker.seuil_degrade_ms:.0f} ms, "
        f"seuil critique {breaker.seuil_critique_ms:.0f} ms\n"
    )

    def afficher(ev: EvenementScan) -> None:
        print(formater_evenement(ev))

        if lent:
            time.sleep(0.2)

    resume = executer_scan(
        cible.envoyer,
        breaker,
        nb_requetes,
        sur_evenement=afficher
    )

    afficher_resume(resume, breaker.etat())


def construire_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        description="CLI du module P1 — Target Gate et simulation."
    )

    sous_commandes = parser.add_subparsers(dest="commande")

    liste = "\n".join(
        f"  {nom:<15} {desc}"
        for nom, (desc, _) in sorted(SCENARIOS.items())
    )

    sim = sous_commandes.add_parser(
        "simuler",
        help="Simuler un scan sans requêtes réelles",
        description="Simulation pilotée par le Circuit Breaker.",
        epilog="Scénarios disponibles :\n" + liste,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    sim.add_argument(
        "scenario",
        choices=sorted(SCENARIOS)
    )

    sim.add_argument(
        "--requetes",
        type=int,
        default=40
    )

    sim.add_argument(
        "--lent",
        action="store_true"
    )

    return parser


def main() -> None:

    args = construire_parser().parse_args()

    if args.commande == "simuler":
        simuler(
            args.scenario,
            args.requetes,
            args.lent
        )

    else:
        verifier_perimetre()


if __name__ == "__main__":
    main()
