
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from circuit_breaker import CircuitBreaker, Baseline, Etat
from network_client import NetworkClient
from scan_loop import executer_scan


class FakeTargetGate:
    """Autorise uniquement les requêtes du serveur local de test."""

    def __init__(self):
        self.calls = []

    def validate(self, url, user_confirmed):
        self.calls.append((url, user_confirmed))
        return SimpleNamespace(
            authorized=(user_confirmed is True),
            reason="Cible locale autorisée pour le test.",
        )


class LocalHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.request_count += 1
        self.server.request_paths.append(self.path)

        if self.path == "/ok":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")

        elif self.path == "/error":
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Internal Server Error")

        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/destination")
            self.end_headers()

        elif self.path == "/destination":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"REDIRECT FOLLOWED")

        elif self.path == "/slow":
            time.sleep(0.3)
            try:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"SLOW")
            except (BrokenPipeError, ConnectionResetError):
                pass

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


@pytest.fixture
def local_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalHandler)
    server.request_count = 0
    server.request_paths = []

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    host, port = server.server_address
    base_url = f"http://{host}:{port}"

    yield server, base_url

    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def create_breaker():
    baseline = Baseline(
        moyenne_ms=100,
        ecart_type_ms=1,
        nombre_echantillons=10,
    )

    return CircuitBreaker.depuis_baseline(
        baseline,
        taille_fenetre=5,
        seuil_5xx_degrade=0.20,
        seuil_5xx_critique=0.40,
        nb_min_avant_jugement=1,
        succes_requis_apres_panne=3,
    )


def create_client(url, breaker, gate=None, timeout=1.0):
    return NetworkClient(
        url=url,
        target_gate=gate or FakeTargetGate(),
        breaker=breaker,
        user_confirmed=True,
        timeout=timeout,
    )


def test_requetes_http_reussies(local_server):
    server, base_url = local_server
    breaker = create_breaker()
    gate = FakeTargetGate()

    client = create_client(
        f"{base_url}/ok",
        breaker,
        gate,
    )

    resume = executer_scan(
        envoyer=client.envoyer,
        breaker=breaker,
        nb_requetes=3,
        attendre_reellement=False,
    )

    assert server.request_count == 3
    assert server.request_paths == ["/ok", "/ok", "/ok"]
    assert len(gate.calls) == 3
    assert all(confirmed is True for _, confirmed in gate.calls)
    assert breaker.etat() == Etat.NORMAL


def test_erreurs_500_declenchent_le_circuit_breaker(local_server):
    server, base_url = local_server
    breaker = create_breaker()
    client = create_client(f"{base_url}/error", breaker)

    resume = executer_scan(
        envoyer=client.envoyer,
        breaker=breaker,
        nb_requetes=5,
        max_sondes=2,
        attendre_reellement=False,
    )

    # Une requête normale, puis deux sondes maximum.
    assert server.request_count == 3
    assert breaker.etat() == Etat.CRITIQUE


def test_redirection_http_non_suivie(local_server):
    server, base_url = local_server
    breaker = create_breaker()
    client = create_client(f"{base_url}/redirect", breaker)

    resultat = client.envoyer()

    assert server.request_count == 1
    assert server.request_paths == ["/redirect"]
    assert "/destination" not in server.request_paths
    assert resultat.injoignable is False
    assert resultat.erreur_5xx is False


def test_timeout_detecte_comme_cible_injoignable(local_server):
    server, base_url = local_server
    breaker = create_breaker()
    client = create_client(
        f"{base_url}/slow",
        breaker,
        timeout=0.05,
    )

    resultat = client.envoyer()

    assert resultat.injoignable is True
    assert server.request_count == 1


def test_refus_connexion_detecte_comme_cible_injoignable():
    # Réserve un port local puis le libère avant la tentative.
    temporary_server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        LocalHandler,
    )
    port = temporary_server.server_address[1]
    temporary_server.server_close()

    breaker = create_breaker()
    client = create_client(
        f"http://127.0.0.1:{port}/ok",
        breaker,
        timeout=0.5,
    )

    resultat = client.envoyer()

    assert resultat.injoignable is True


def test_target_gate_est_verifie_avant_chaque_requete(local_server):
    server, base_url = local_server
    breaker = create_breaker()
    gate = FakeTargetGate()

    client = create_client(
        f"{base_url}/ok",
        breaker,
        gate,
    )

    executer_scan(
        envoyer=client.envoyer,
        breaker=breaker,
        nb_requetes=4,
        attendre_reellement=False,
    )

    assert len(gate.calls) == 4
    assert server.request_count == 4


def test_client_refuse_une_requete_si_circuit_critique(local_server):
    server, base_url = local_server
    breaker = create_breaker()

    # On force l'état critique à travers un résultat réseau.
    from circuit_breaker import ResultatRequete

    breaker.enregistrer_resultat(
        ResultatRequete(
            temps_reponse_ms=100,
            erreur_5xx=True,
            injoignable=False,
        )
    )

    assert breaker.etat() == Etat.CRITIQUE

    client = create_client(f"{base_url}/ok", breaker)

    from network_client import OperationReseauRefusee

    with pytest.raises(OperationReseauRefusee):
        client.envoyer(est_sonde=False)

    assert server.request_count == 0
