
#!/usr/bin/env python3
"""
Dashboard web — module P1 Offensive Security.

La validation des cibles passe par Target Gate.
Le Scope Manager reste responsable de la validation de la whitelist.

Les simulations restent simulées et indépendantes.
"""

from __future__ import annotations

from flask import Flask, jsonify, render_template, request

from core import (
    charger_whitelist,
    journaliser,
    lire_scan_results,
    lire_hypotheses,
)

from target_gate import validate_target

from simulation import SCENARIOS

from simulation_live import (
    NB_REQUETES_MAX,
    GestionnaireSimulation,
    ParametresInvalides,
    SimulationDejaEnCours,
)


app = Flask(__name__)

gestionnaire = GestionnaireSimulation()


@app.route("/", methods=["GET", "POST"])
def index():

    resultat = None

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        confirme = request.form.get("autorisation") == "on"

        try:
            whitelist = charger_whitelist()

            autorise, raison = validate_target(
                url=url,
                user_confirmed=confirme,
                whitelist=whitelist
            )

        except Exception:
            autorise = False
            raison = (
                "REFUSÉ : erreur interne pendant "
                "le chargement ou la validation de la whitelist."
            )

        resultat = {
            "autorise": autorise,
            "raison": raison,
            "url": url,
        }

        journaliser(
            url,
            confirme,
            autorise,
            raison,
            source="web"
        )

    return render_template(
        "index.html",
        resultat=resultat
    )


@app.route("/scan-results")
def scan_results():

    resultats = lire_scan_results()

    return render_template(
        "scan_results.html",
        resultats=resultats
    )


@app.route("/hypotheses")
def hypotheses():

    liste = lire_hypotheses()

    return render_template(
        "hypotheses.html",
        hypotheses=liste
    )


# --------------------------------------------------
# Santé de la cible — simulation uniquement
# --------------------------------------------------

@app.route("/sante")
def sante():

    scenarios = [
        {
            "nom": nom,
            "description": desc
        }
        for nom, (desc, _) in sorted(SCENARIOS.items())
    ]

    return render_template(
        "sante.html",
        scenarios=scenarios,
        nb_requetes_max=NB_REQUETES_MAX
    )


@app.route("/sante/etat")
def sante_etat():

    return jsonify(gestionnaire.instantane())


@app.route("/sante/lancer", methods=["POST"])
def sante_lancer():

    scenario = request.form.get("scenario", "")

    try:
        nb_requetes = int(
            request.form.get("requetes", "40")
        )

    except ValueError:
        return jsonify(
            erreur="Le nombre de requêtes doit être un entier."
        ), 400

    try:
        gestionnaire.demarrer(
            scenario,
            nb_requetes
        )

    except SimulationDejaEnCours as e:
        return jsonify(erreur=str(e)), 409

    except ParametresInvalides as e:
        return jsonify(erreur=str(e)), 400

    except (FileNotFoundError, ValueError) as e:
        return jsonify(erreur=str(e)), 500

    return jsonify(ok=True)


@app.route("/sante/arreter", methods=["POST"])
def sante_arreter():

    return jsonify(
        arrete=gestionnaire.arreter()
    )


if __name__ == "__main__":

    app.run(
        debug=True,
        port=5000
    )
