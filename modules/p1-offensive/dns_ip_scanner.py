
#!/usr/bin/env python3
"""
DNS/IP Scanner — Reconnaissance DNS passive.

La validation de toute cible passe obligatoirement par Target Gate.

Responsabilités :
- Exiger une confirmation humaine.
- Vérifier le périmètre autorisé.
- Résoudre les enregistrements DNS.
- Identifier IPv4 et IPv6.
- Récupérer CNAME, NS, MX et TXT.
- Détecter les nameservers Cloudflare.
- Enregistrer les résultats en JSON.

Aucune connexion directe aux IP découvertes.
Aucun scan de ports.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import dns.resolver
import dns.exception

from core import charger_whitelist
from target_gate import validate_target


RESULT_FILE = (
    Path(__file__).resolve().parent
    / "data"
    / "dns_ip_results.json"
)

DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "NS", "MX", "TXT"]


class DNSIPScanner:

    def __init__(self, timeout: float = 3.0, lifetime: float = 5.0):
        self.timeout = timeout
        self.lifetime = lifetime

        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = lifetime

        self.whitelist = charger_whitelist()

    def verifier_scope(
        self,
        domain: str,
        user_confirmed: bool = False
    ) -> tuple[bool, str]:
        """
        Vérification centralisée par le Target Gate.
        """

        if not isinstance(domain, str) or not domain.strip():
            return False, "REFUSÉ : domaine absent ou invalide."

        url = f"https://{domain.strip()}/"

        return validate_target(
            url=url,
            user_confirmed=user_confirmed,
            whitelist=self.whitelist
        )

    def resoudre_enregistrement(
        self,
        domain: str,
        record_type: str
    ) -> dict:

        resultat = {
            "type": record_type,
            "records": [],
            "status": "success",
            "error": None,
        }

        try:
            answers = self.resolver.resolve(
                domain,
                record_type,
                raise_on_no_answer=False
            )

            if answers.rrset is None:
                resultat["status"] = "no_answer"
                return resultat

            resultat["records"] = [
                str(record).strip() for record in answers
            ]

        except dns.resolver.NXDOMAIN:
            resultat["status"] = "nxdomain"
            resultat["error"] = "Domaine inexistant"

        except dns.resolver.NoNameservers:
            resultat["status"] = "no_nameservers"
            resultat["error"] = "Aucun serveur DNS disponible"

        except dns.resolver.LifetimeTimeout:
            resultat["status"] = "timeout"
            resultat["error"] = "Délai DNS dépassé"

        except dns.exception.DNSException as e:
            resultat["status"] = "error"
            resultat["error"] = str(e)

        return resultat

    def analyser_domaine(
        self,
        domain: str,
        user_confirmed: bool = False
    ) -> dict:

        print("\n" + "=" * 60)
        print(f"Reconnaissance DNS/IP : {domain}")
        print("=" * 60)

        # Étape obligatoire : Target Gate.
        autorise, raison = self.verifier_scope(
            domain,
            user_confirmed
        )

        if not autorise:
            print(f"\nREFUSÉ : {raison}")

            return {
                "domain": domain,
                "authorized": False,
                "reason": raison,
                "records": [],
            }

        print(f"\nAutorisé : {raison}")

        resultats = []

        for record_type in DNS_RECORD_TYPES:

            print(f"\n--- {record_type} ---")

            resultat = self.resoudre_enregistrement(
                domain,
                record_type
            )

            resultats.append(resultat)

            if resultat["records"]:
                for record in resultat["records"]:
                    print(f"  {record}")

            elif resultat["error"]:
                print(f"  Erreur : {resultat['error']}")

            else:
                print("  Aucun enregistrement")

        ips = {
            "ipv4": [],
            "ipv6": [],
        }

        for resultat in resultats:
            if resultat["type"] == "A":
                ips["ipv4"] = resultat["records"]

            elif resultat["type"] == "AAAA":
                ips["ipv6"] = resultat["records"]

        ns_records = next(
            (
                resultat["records"]
                for resultat in resultats
                if resultat["type"] == "NS"
            ),
            []
        )

        cloudflare_detecte = any(
            "cloudflare.com" in ns.lower()
            for ns in ns_records
        )

        donnees = {
            "domain": domain,
            "authorized": True,
            "authorization_reason": raison,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "infrastructure": {
                "cloudflare_nameservers_detected": cloudflare_detecte,
                "ipv4": ips["ipv4"],
                "ipv6": ips["ipv6"],
            },
            "records": resultats,
        }

        return donnees

    def sauvegarder(self, donnees: dict) -> None:

        if donnees.get("authorized") is not True:
            raise PermissionError(
                "Sauvegarde refusée : cible non autorisée."
            )

        RESULT_FILE.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with RESULT_FILE.open("w", encoding="utf-8") as fichier:
            json.dump(
                donnees,
                fichier,
                indent=4,
                ensure_ascii=False
            )

        print(f"\nRésultats enregistrés : {RESULT_FILE}")


if __name__ == "__main__":

    scanner = DNSIPScanner()

    domaine = input("Domaine à analyser : ").strip()

    confirmation = input(
        "\nConfirmez-vous disposer d'une autorisation écrite "
        "valide pour analyser ce domaine ? (oui/non) : "
    ).strip().lower()

    user_confirmed = confirmation in ("oui", "o", "yes", "y")

    resultats = scanner.analyser_domaine(
        domaine,
        user_confirmed=user_confirmed
    )

    if resultats.get("authorized") is True:
        scanner.sauvegarder(resultats)
