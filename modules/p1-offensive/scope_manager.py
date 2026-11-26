
#!/usr/bin/env python3
"""
Scope Manager — contrôle strict du périmètre autorisé.

Responsabilités :
- Normaliser les noms d'hôtes.
- Extraire et valider les URL HTTP/HTTPS.
- Vérifier les domaines autorisés.
- Gérer les sous-domaines.
- Appliquer les exclusions de sous-domaines et de chemins.
- Vérifier les dates d'autorisation.
- Refuser les URL malformées.
- Garantir un comportement FAIL-CLOSED.

Aucun appel au LLM : les décisions de sécurité restent déterministes.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import date
from urllib.parse import urlsplit


@dataclass
class ScopeEntry:
    """Représente une entrée du périmètre autorisé."""

    domain: str
    include_subdomains: bool = False
    excluded_paths: list[str] = field(default_factory=list)
    excluded_subdomains: list[str] = field(default_factory=list)
    authorized_from: date | None = None
    authorized_until: date | None = None
    authorized_by: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        self.domain = _normalize_hostname(self.domain)

        self.excluded_subdomains = [
            _normalize_hostname(d)
            for d in self.excluded_subdomains
        ]

        # Conversion automatique des dates depuis le JSON.
        if isinstance(self.authorized_from, str):
            self.authorized_from = date.fromisoformat(
                self.authorized_from
            )

        if isinstance(self.authorized_until, str):
            self.authorized_until = date.fromisoformat(
                self.authorized_until
            )


def _normalize_hostname(hostname: str) -> str:
    """Normalise un nom d'hôte."""

    if not isinstance(hostname, str):
        raise ValueError("Hostname invalide")

    return hostname.strip().lower().rstrip(".")


def _extract_hostname_and_path(
    url: str,
) -> tuple[str | None, str]:

    if not isinstance(url, str) or not url:
        return None, ""

    try:
        parsed = urlsplit(url)

        if parsed.scheme.lower() not in ("http", "https"):
            return None, ""

        if not parsed.netloc or not parsed.hostname:
            return None, ""

        # Refuser les identifiants intégrés.
        if parsed.username is not None or parsed.password is not None:
            return None, ""

        # Valider le port.
        port = parsed.port

        if port is not None and not (1 <= port <= 65535):
            return None, ""

        hostname = _normalize_hostname(parsed.hostname)

        if not hostname:
            return None, ""

        # Vérifier la syntaxe IP.
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass

        if any(char.isspace() for char in hostname):
            return None, ""

        if "/" in hostname or "\\" in hostname:
            return None, ""

        return hostname, parsed.path or "/"

    except (ValueError, TypeError, AttributeError):
        return None, ""


def _hostname_matches_entry(
    hostname: str,
    entry: ScopeEntry,
) -> bool:

    if hostname == entry.domain:
        return True

    if entry.include_subdomains:
        return hostname.endswith("." + entry.domain)

    return False


def _path_is_excluded(
    path: str,
    excluded_paths: list[str],
) -> str | None:

    for excluded in excluded_paths:

        excluded = excluded.rstrip("/") or "/"

        if path == excluded or path.startswith(excluded + "/"):
            return excluded

    return None


def is_authorized(
    url: str,
    whitelist: list[ScopeEntry],
    today: date | None = None,
) -> tuple[bool, str]:
    """
    Vérifie si une URL appartient au périmètre autorisé.

    Principe FAIL-CLOSED :
    Toute URL invalide, exclue ou non explicitement autorisée
    est refusée.
    """

    if today is None:
        today = date.today()

    hostname, path = _extract_hostname_and_path(url)

    if hostname is None:
        return False, (
            "URL invalide ou impossible à parser (fail-closed)"
        )

    # Refuser les adresses IP brutes.
    try:
        ipaddress.ip_address(hostname)
        return False, f"Adresse IP brute refusée : {hostname}"
    except ValueError:
        pass

    matching_entries = [
        entry
        for entry in whitelist
        if _hostname_matches_entry(hostname, entry)
    ]

    if not matching_entries:
        return False, (
            "Aucune entrée de whitelist ne correspond (fail-closed)"
        )

    # Les exclusions sont prioritaires.
    for entry in matching_entries:

        if hostname in entry.excluded_subdomains:
            return False, (
                f"Sous-domaine explicitement exclu : {hostname}"
            )

        excluded_path = _path_is_excluded(
            path,
            entry.excluded_paths,
        )

        if excluded_path is not None:
            return False, (
                f"Chemin explicitement exclu : {excluded_path}"
            )

    # Vérifier les dates d'autorisation.
    for entry in matching_entries:

        if (
            entry.authorized_from is not None
            and today < entry.authorized_from
        ):
            continue

        if (
            entry.authorized_until is not None
            and today > entry.authorized_until
        ):
            continue

        return True, (
            f"Autorisé via l'entrée whitelist pour {entry.domain}"
        )

    return False, (
        "Hors fenêtre d'autorisation "
        "(pas encore commencée ou expirée)"
    )
