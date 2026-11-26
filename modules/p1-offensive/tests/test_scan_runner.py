
from unittest.mock import MagicMock, patch

import pytest

from circuit_breaker import Etat
from network_client import OperationReseauRefusee
from scan_runner import lancer_scan


URL_AUTORISEE = "https://orchidisland.immo/"
URL_REFUSEE = "https://example.com/"


def preparer_composants():
    """Prépare les composants simulés communs aux tests."""

    whitelist = [MagicMock()]

    decision = MagicMock()
    decision.authorized = True
    decision.reason = "Cible autorisée"

    breaker = MagicMock()
    breaker.etat.return_value = Etat.NORMAL

    client = MagicMock()
    resume = MagicMock()

    return whitelist, decision, breaker, client, resume


def test_refus_sans_confirmation_humaine():
    with patch("scan_runner.charger_whitelist") as mock_whitelist:
        resultat = lancer_scan(
            URL_AUTORISEE,
            user_confirmed=False,
        )

    assert resultat.success is False
    assert "confirmation humaine absente" in resultat.message.lower()
    assert resultat.resume is None
    mock_whitelist.assert_not_called()


def test_refus_cible_hors_whitelist():
    whitelist, decision, _, _, _ = preparer_composants()
    decision.authorized = False
    decision.reason = "Domaine absent de la whitelist"

    with patch(
        "scan_runner.charger_whitelist",
        return_value=whitelist,
    ), patch("scan_runner.TargetGate") as gate, patch(
        "scan_runner.charger_baseline"
    ) as baseline, patch(
        "scan_runner.NetworkClient"
    ) as client:

        gate.return_value.validate.return_value = decision

        resultat = lancer_scan(URL_REFUSEE, True)

    assert resultat.success is False
    assert "Domaine absent de la whitelist" in resultat.message
    baseline.assert_not_called()
    client.assert_not_called()


def test_refus_si_baseline_indisponible():
    whitelist, decision, _, _, _ = preparer_composants()

    with patch(
        "scan_runner.charger_whitelist",
        return_value=whitelist,
    ), patch("scan_runner.TargetGate") as gate, patch(
        "scan_runner.charger_baseline",
        side_effect=FileNotFoundError("Baseline introuvable"),
    ), patch("scan_runner.NetworkClient") as client:

        gate.return_value.validate.return_value = decision

        resultat = lancer_scan(URL_AUTORISEE, True)

    assert resultat.success is False
    assert "Baseline indisponible ou invalide" in resultat.message
    client.assert_not_called()


def test_initialisation_et_execution_scan_simule():
    whitelist, decision, breaker, client, resume = preparer_composants()
    baseline = MagicMock()

    with patch(
        "scan_runner.charger_whitelist",
        return_value=whitelist,
    ), patch("scan_runner.TargetGate") as gate, patch(
        "scan_runner.charger_baseline",
        return_value=baseline,
    ), patch(
        "scan_runner.CircuitBreaker.depuis_baseline",
        return_value=breaker,
    ) as mock_breaker, patch(
        "scan_runner.NetworkClient",
        return_value=client,
    ) as mock_client, patch(
        "scan_runner.executer_scan",
        return_value=resume,
    ) as mock_scan:

        gate.return_value.validate.return_value = decision

        resultat = lancer_scan(
            URL_AUTORISEE,
            True,
            nb_requetes=5,
        )

    assert resultat.success is True
    assert resultat.resume is resume

    mock_breaker.assert_called_once_with(baseline)

    mock_client.assert_called_once_with(
        url=URL_AUTORISEE,
        target_gate=gate.return_value,
        breaker=breaker,
        user_confirmed=True,
    )

    mock_scan.assert_called_once()
    assert mock_scan.call_args.kwargs["envoyer"] == client.envoyer
    assert mock_scan.call_args.kwargs["breaker"] == breaker
    assert mock_scan.call_args.kwargs["nb_requetes"] == 5
    assert mock_scan.call_args.kwargs["attendre_reellement"] is False


def test_interception_operation_reseau_refusee():
    whitelist, decision, breaker, client, _ = preparer_composants()

    with patch(
        "scan_runner.charger_whitelist",
        return_value=whitelist,
    ), patch("scan_runner.TargetGate") as gate, patch(
        "scan_runner.charger_baseline",
        return_value=MagicMock(),
    ), patch(
        "scan_runner.CircuitBreaker.depuis_baseline",
        return_value=breaker,
    ), patch(
        "scan_runner.NetworkClient",
        return_value=client,
    ), patch(
        "scan_runner.executer_scan",
        side_effect=OperationReseauRefusee("Circuit Breaker critique"),
    ):

        gate.return_value.validate.return_value = decision

        resultat = lancer_scan(URL_AUTORISEE, True)

    assert resultat.success is False
    assert "Opération réseau refusée" in resultat.message
    assert "Circuit Breaker critique" in resultat.message
    assert resultat.resume is None


@pytest.mark.parametrize(
    "erreur",
    [
        RuntimeError("Erreur interne"),
        ValueError("Configuration invalide"),
    ],
)
def test_interception_erreurs_generales(erreur):
    whitelist, decision, breaker, client, _ = preparer_composants()

    with patch(
        "scan_runner.charger_whitelist",
        return_value=whitelist,
    ), patch("scan_runner.TargetGate") as gate, patch(
        "scan_runner.charger_baseline",
        return_value=MagicMock(),
    ), patch(
        "scan_runner.CircuitBreaker.depuis_baseline",
        return_value=breaker,
    ), patch(
        "scan_runner.NetworkClient",
        return_value=client,
    ), patch(
        "scan_runner.executer_scan",
        side_effect=erreur,
    ):

        gate.return_value.validate.return_value = decision

        resultat = lancer_scan(URL_AUTORISEE, True)

    assert resultat.success is False
    assert "Échec du scan" in resultat.message
    assert resultat.resume is None


def test_validation_target_gate_effectuee_avant_baseline():
    whitelist, decision, _, _, _ = preparer_composants()

    with patch(
        "scan_runner.charger_whitelist",
        return_value=whitelist,
    ), patch("scan_runner.TargetGate") as gate, patch(
        "scan_runner.charger_baseline",
        return_value=MagicMock(),
    ) as baseline, patch(
        "scan_runner.CircuitBreaker.depuis_baseline",
        return_value=MagicMock(),
    ), patch(
        "scan_runner.NetworkClient",
        return_value=MagicMock(),
    ), patch(
        "scan_runner.executer_scan",
        return_value=MagicMock(),
    ):

        gate.return_value.validate.return_value = decision

        resultat = lancer_scan(URL_AUTORISEE, True)

    assert resultat.success is True
    gate.return_value.validate.assert_called_once_with(URL_AUTORISEE, True)
    baseline.assert_called_once()


def test_confirmation_non_booleenne_refusee():
    with patch("scan_runner.charger_whitelist") as mock_whitelist:
        resultat = lancer_scan(
            URL_AUTORISEE,
            user_confirmed=1,
        )

    assert resultat.success is False
    mock_whitelist.assert_not_called()


def test_parametres_scan_invalides():
    whitelist, decision, breaker, client, _ = preparer_composants()

    with patch(
        "scan_runner.charger_whitelist",
        return_value=whitelist,
    ), patch("scan_runner.TargetGate") as gate, patch(
        "scan_runner.charger_baseline",
        return_value=MagicMock(),
    ), patch(
        "scan_runner.CircuitBreaker.depuis_baseline",
        return_value=breaker,
    ), patch(
        "scan_runner.NetworkClient",
        return_value=client,
    ), patch(
        "scan_runner.executer_scan",
        side_effect=ValueError("nb_requetes doit être un entier positif"),
    ):

        gate.return_value.validate.return_value = decision

        resultat = lancer_scan(
            URL_AUTORISEE,
            True,
            nb_requetes=0,
        )

    assert resultat.success is False
    assert "Échec du scan" in resultat.message
