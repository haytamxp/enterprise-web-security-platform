
from datetime import date
from unittest.mock import patch

import pytest

from target_gate import validate_target
from scope_manager import ScopeEntry


@pytest.fixture
def whitelist():
    return [
        ScopeEntry(
            domain="orchidisland.immo",
            include_subdomains=False,
            excluded_paths=[],
            excluded_subdomains=[],
            authorized_from=date(2026, 1, 1),
            authorized_until=date(2026, 12, 31),
            authorized_by="Responsable Pentest",
            notes="Autorisation de test"
        )
    ]


# ---------------------------------------------------------
# 1. Cible autorisée avec confirmation humaine
# ---------------------------------------------------------

def test_cible_autorisee_avec_confirmation(whitelist):
    autorise, raison = validate_target(
        "https://orchidisland.immo/",
        True,
        whitelist
    )

    assert autorise is True
    assert "TARGET VALIDÉ" in raison


# ---------------------------------------------------------
# 2. Absence de confirmation humaine
# ---------------------------------------------------------

def test_absence_confirmation_humaine(whitelist):
    autorise, raison = validate_target(
        "https://orchidisland.immo/",
        False,
        whitelist
    )

    assert autorise is False
    assert raison == "REFUSÉ : confirmation humaine explicite absente."


# ---------------------------------------------------------
# 3. Domaine externe
# ---------------------------------------------------------

def test_domaine_externe_refuse(whitelist):
    autorise, raison = validate_target(
        "https://example.com/",
        True,
        whitelist
    )

    assert autorise is False
    assert "Scope Manager" in raison


# ---------------------------------------------------------
# 4. URL vide
# ---------------------------------------------------------

def test_url_vide_refuse(whitelist):
    autorise, raison = validate_target(
        "",
        True,
        whitelist
    )

    assert autorise is False
    assert raison == "REFUSÉ : URL absente ou invalide."


# ---------------------------------------------------------
# 5. URL contenant uniquement des espaces
# ---------------------------------------------------------

def test_url_espaces_refuse(whitelist):
    autorise, raison = validate_target(
        "   ",
        True,
        whitelist
    )

    assert autorise is False


# ---------------------------------------------------------
# 6. Whitelist vide
# ---------------------------------------------------------

def test_whitelist_vide_refuse():
    autorise, raison = validate_target(
        "https://orchidisland.immo/",
        True,
        []
    )

    assert autorise is False
    assert raison == "REFUSÉ : whitelist absente ou invalide."


# ---------------------------------------------------------
# 7. Whitelist avec mauvais type
# ---------------------------------------------------------

def test_whitelist_invalide_refuse():
    autorise, raison = validate_target(
        "https://orchidisland.immo/",
        True,
        ["orchidisland.immo"]
    )

    assert autorise is False
    assert raison == "REFUSÉ : format de whitelist invalide."


# ---------------------------------------------------------
# 8. URL None
# ---------------------------------------------------------

def test_url_none_refuse(whitelist):
    autorise, raison = validate_target(
        None,
        True,
        whitelist
    )

    assert autorise is False


# ---------------------------------------------------------
# 9. Erreur interne du Scope Manager
# ---------------------------------------------------------

def test_erreur_interne_refuse_fail_closed(whitelist):
    with patch(
        "target_gate.is_authorized",
        side_effect=RuntimeError("Erreur simulée")
    ):
        autorise, raison = validate_target(
            "https://orchidisland.immo/",
            True,
            whitelist
        )

    assert autorise is False
    assert raison == (
        "REFUSÉ : erreur interne pendant la vérification du périmètre."
    )


# ---------------------------------------------------------
# 10. Vérification de la délégation au Scope Manager
# ---------------------------------------------------------

def test_scope_manager_est_appele(whitelist):
    with patch(
        "target_gate.is_authorized",
        return_value=(True, "Autorisé")
    ) as mock_scope:

        autorise, raison = validate_target(
            "https://orchidisland.immo/",
            True,
            whitelist
        )

    assert autorise is True
    mock_scope.assert_called_once()


# ---------------------------------------------------------
# 11. Confirmation humaine obligatoire même pour une URL valide
# ---------------------------------------------------------

def test_confirmation_absente_ne_declenche_pas_scope(whitelist):
    with patch("target_gate.is_authorized") as mock_scope:

        autorise, raison = validate_target(
            "https://orchidisland.immo/",
            False,
            whitelist
        )

    assert autorise is False
    mock_scope.assert_not_called()
