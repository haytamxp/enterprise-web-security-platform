
from types import SimpleNamespace

import pytest
import dns.resolver

import dns_ip_scanner
from dns_ip_scanner import DNSIPScanner
from scope_manager import ScopeEntry


@pytest.fixture
def scanner():
    """Scanner configuré avec un périmètre de test indépendant."""
    instance = DNSIPScanner()

    instance.whitelist = [
        ScopeEntry(
            domain="orchidisland.immo",
            include_subdomains=False,
            excluded_paths=[],
            excluded_subdomains=[],
            authorized_from="2026-01-01",
            authorized_until="2026-12-31",
            authorized_by="Test",
            notes="Test automatisé",
        )
    ]

    return instance


class FakeAnswer:
    """Simule une réponse DNS dnspython."""

    def __init__(self, records):
        self.records = records
        self.rrset = records if records else None

    def __iter__(self):
        return iter(self.records)


class FakeResolver:
    """Résolveur DNS simulé : aucune requête réseau."""

    def __init__(self, responses=None, errors=None):
        self.responses = responses or {}
        self.errors = errors or {}

    def resolve(self, domain, record_type, raise_on_no_answer=False):
        if record_type in self.errors:
            raise self.errors[record_type]

        records = self.responses.get(record_type, [])
        return FakeAnswer(records)


def test_domaine_autorise(scanner):
    authorized, reason = scanner.verifier_scope(
        "orchidisland.immo",
        user_confirmed=True
    )

    assert authorized is True


def test_sous_domaine_mail_refuse(scanner):
    authorized, reason = scanner.verifier_scope(
        "mail.orchidisland.immo",
        user_confirmed=True
    )

    assert authorized is False


def test_domaine_externe_refuse(scanner):
    authorized, reason = scanner.verifier_scope(
        "example.com",
        user_confirmed=True
    )

    assert authorized is False


def test_analyse_enregistrements_dns(scanner):
    scanner.resolver = FakeResolver(
        responses={
            "A": ["104.21.71.172"],
            "AAAA": ["2606:4700:3030::ac43:ab14"],
            "CNAME": [],
            "NS": ["vern.ns.cloudflare.com."],
            "MX": ["0 mail.orchidisland.immo."],
            "TXT": ['"v=spf1 include:example.net ~all"'],
        }
    )

    result = scanner.analyser_domaine(
        "orchidisland.immo",
        user_confirmed=True
    )

    assert result["authorized"] is True
    assert result["infrastructure"]["ipv4"] == ["104.21.71.172"]
    assert result["infrastructure"]["ipv6"] == [
        "2606:4700:3030::ac43:ab14"
    ]
    assert result["infrastructure"]["cloudflare_nameservers_detected"] is True

    record_types = [record["type"] for record in result["records"]]

    assert record_types == ["A", "AAAA", "CNAME", "NS", "MX", "TXT"]


def test_analyse_domaine_non_autorise_ne_lance_pas_dns(scanner):
    scanner.resolver = FakeResolver()

    result = scanner.analyser_domaine(
        "example.com",
        user_confirmed=True
    )

    assert result["authorized"] is False
    assert result["records"] == []


def test_reponse_dns_sans_enregistrement(scanner):
    scanner.resolver = FakeResolver(
        responses={"A": []}
    )

    result = scanner.resoudre_enregistrement("orchidisland.immo", "A")

    assert result["status"] == "no_answer"
    assert result["records"] == []


def test_erreur_nxdomain(scanner):
    scanner.resolver = FakeResolver(
        errors={"A": dns.resolver.NXDOMAIN()}
    )

    result = scanner.resoudre_enregistrement("orchidisland.immo", "A")

    assert result["status"] == "nxdomain"
    assert result["error"] == "Domaine inexistant"


def test_erreur_no_nameservers(scanner):
    scanner.resolver = FakeResolver(
        errors={"A": dns.resolver.NoNameservers()}
    )

    result = scanner.resoudre_enregistrement("orchidisland.immo", "A")

    assert result["status"] == "no_nameservers"


def test_erreur_timeout(scanner):
    scanner.resolver = FakeResolver(
        errors={
            "A": dns.resolver.LifetimeTimeout(timeout=1, errors=[])
        }
    )

    result = scanner.resoudre_enregistrement("orchidisland.immo", "A")

    assert result["status"] == "timeout"


def test_sauvegarde_json(scanner, tmp_path, monkeypatch):
    destination = tmp_path / "dns_ip_results.json"

    monkeypatch.setattr(
        dns_ip_scanner,
        "RESULT_FILE",
        destination
    )

    donnees = {
        "domain": "orchidisland.immo",
        "authorized": True,
        "records": [],
    }

    scanner.sauvegarder(donnees)

    assert destination.exists()

    contenu = destination.read_text(encoding="utf-8")

    assert '"domain": "orchidisland.immo"' in contenu
