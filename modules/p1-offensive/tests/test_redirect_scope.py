
import threading
from datetime import date
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.error import HTTPError
from urllib.request import build_opener

import pytest

from scope_manager import ScopeEntry
from baseline_scan import ScopeRedirectHandler


class RedirectTestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        routes = {
            "/interne": (
                302,
                "/destination"
            ),
            "/destination": (
                200,
                None
            ),
            "/externe": (
                302,
                "https://evil.com/"
            ),
            "/paiement": (
                302,
                "/paiement"
            ),
            "/chaine": (
                302,
                "/externe"
            ),
            "/boucle1": (
                302,
                "/boucle2"
            ),
            "/boucle2": (
                302,
                "/boucle1"
            ),
            "/sous-domaine": (
                302,
                "https://sub.orchidisland.immo/"
            ),
            "/port-invalide": (
                302,
                "http://localhost:99999/"
            ),
            "/ip": (
                302,
                "https://185.12.34.56/"
            ),
            "/identifiants": (
                302,
                "https://user:pass@orchidisland.immo/"
            ),
        }

        if self.path not in routes:
            self.send_response(404)
            self.end_headers()
            return

        status, destination = routes[self.path]

        self.send_response(status)

        if destination:
            if destination.startswith("/"):
                destination = (
                    f"http://localhost:{self.server.server_port}"
                    f"{destination}"
                )

            self.send_header("Location", destination)

        self.end_headers()

        if status == 200:
            self.wfile.write(b"OK")

    def log_message(self, format, *args):
        pass


@pytest.fixture
def serveur_local():
    server = HTTPServer(
        ("127.0.0.1", 0),
        RedirectTestHandler
    )

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True
    )
    thread.start()

    yield (
        f"http://localhost:{server.server_port}"
    )

    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


@pytest.fixture
def whitelist():
    return [
        ScopeEntry(
            domain="localhost",
            include_subdomains=False,
            excluded_paths=["/paiement"],
            authorized_from=date(2026, 1, 1),
            authorized_until=date(2026, 12, 31),
        ),
        ScopeEntry(
            domain="orchidisland.immo",
            include_subdomains=False,
            excluded_paths=["/paiement"],
            authorized_from=date(2026, 1, 1),
            authorized_until=date(2026, 12, 31),
        ),
    ]


def ouvrir_avec_controle(url, whitelist):
    opener = build_opener(
        ScopeRedirectHandler(whitelist)
    )

    return opener.open(url, timeout=3)


def test_redirection_interne_autorisee(
    serveur_local,
    whitelist
):
    with ouvrir_avec_controle(
        serveur_local + "/interne",
        whitelist
    ) as reponse:

        assert reponse.status == 200
        assert reponse.read() == b"OK"


def test_redirection_externe_refusee(
    serveur_local,
    whitelist
):
    with pytest.raises(HTTPError):
        ouvrir_avec_controle(
            serveur_local + "/externe",
            whitelist
        )


def test_redirection_vers_chemin_exclu_refusee(
    serveur_local,
    whitelist
):
    with pytest.raises(HTTPError):
        ouvrir_avec_controle(
            serveur_local + "/paiement",
            whitelist
        )


def test_chaine_redirections_externe_refusee(
    serveur_local,
    whitelist
):
    with pytest.raises(HTTPError):
        ouvrir_avec_controle(
            serveur_local + "/chaine",
            whitelist
        )


def test_boucle_redirection_bloquee(
    serveur_local,
    whitelist
):
    with pytest.raises(HTTPError):
        ouvrir_avec_controle(
            serveur_local + "/boucle1",
            whitelist
        )


def test_redirection_vers_sous_domaine_non_autorise(
    serveur_local,
    whitelist
):
    with pytest.raises(HTTPError):
        ouvrir_avec_controle(
            serveur_local + "/sous-domaine",
            whitelist
        )


def test_redirection_vers_port_invalide_refusee(
    serveur_local,
    whitelist
):
    with pytest.raises(HTTPError):
        ouvrir_avec_controle(
            serveur_local + "/port-invalide",
            whitelist
        )


def test_redirection_vers_ip_non_autorisee_refusee(
    serveur_local,
    whitelist
):
    with pytest.raises(HTTPError):
        ouvrir_avec_controle(
            serveur_local + "/ip",
            whitelist
        )


def test_redirection_vers_identifiants_url_refusee(
    serveur_local,
    whitelist
):
    with pytest.raises(HTTPError):
        ouvrir_avec_controle(
            serveur_local + "/identifiants",
            whitelist
        )
