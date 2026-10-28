#!/usr/bin/env python3
"""
Scope Manager — vérification déterministe du périmètre autorisé.

Principe fondamental (voir sous-étape 1.1) :
Ce module ne contient AUCUN appel au LLM. C'est volontaire : la décision
"ai-je le droit de scanner cette cible ?" doit être 100% prévisible et ne
jamais pouvoir être influencée par du texte trouvé pendant un scan
(instruction cachée dans une page, un header, un commentaire JS, etc.).

Principe "fail-closed" (voir sous-étape 1.1) :
En cas de doute, d'URL malformée, ou d'absence de correspondance claire
dans la whitelist, la réponse est TOUJOURS "refusé". Jamais "autorisé"
par défaut.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from urllib.parse import urlparse


@dataclass
class ScopeEntry:
    """Une entrée de la whitelist = un site autorisé, avec ses conditions."""

    domain: str
    include_subdomains: bool = False
    excluded_paths: list[str] = field(default_factory=list)
    excluded_subdomains: list[str] = field(default_factory=list)
    authorized_from: date = None
    authorized_until: date = None
    authorized_by: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        self.domain = _normalize_hostname(self.domain)
        self.excluded_subdomains = [
            _normalize_hostname(d) for d in self.excluded_subdomains
        ]


def _normalize_hostname(hostname: str) -> str:
    """Minuscules + suppression du point final éventuel."""
    hostname = hostname.strip().lower()
    if hostname.endswith("."):
        hostname = hostname[:-1]
    return hostname


def _extract_hostname_and_path(url: str) -> tuple[str | None, str]:
    try:
        parsed = urlparse(url)
    except ValueError:
        return None, ""

    if parsed.scheme not in ("http", "https"):
        return None, ""

    hostname = parsed.hostname
    if not hostname:
        return None, ""

    return _normalize_hostname(hostname), (parsed.path or "/")


def _hostname_matches_entry(hostname: str, entry: ScopeEntry) -> bool:
    if hostname == entry.domain:
        return True
    if entry.include_subdomains and hostname.endswith("." + entry.domain):
        return True
    return False


def is_authorized(
    url: str,
    whitelist: list[ScopeEntry],
    today: date | None = None,
) -> tuple[bool, str]:
    if today is None:
        today = date.today()

    hostname, path = _extract_hostname_and_path(url)
    if hostname is None:
        return False, "URL invalide ou impossible à parser (fail-closed)"

    for entry in whitelist:
        if not _hostname_matches_entry(hostname, entry):
            continue

        if hostname in entry.excluded_subdomains:
            return False, f"Sous-domaine explicitement exclu : {hostname}"

        if entry.authorized_from and today < entry.authorized_from:
            return False, "Hors fenêtre d'autorisation (pas encore commencée)"
        if entry.authorized_until and today > entry.authorized_until:
            return False, "Hors fenêtre d'autorisation (expirée)"

        for excluded in entry.excluded_paths:
            if path.startswith(excluded):
                return False, f"Chemin explicitement exclu : {excluded}"

        return True, f"Autorisé via l'entrée whitelist pour {entry.domain}"

    return False, "Aucune entrée de whitelist ne correspond (fail-closed)"