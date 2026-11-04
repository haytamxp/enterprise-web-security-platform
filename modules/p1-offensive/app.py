#!/usr/bin/env python3
"""
Dashboard web — sous-étape 1.7, enrichi en 1.8.

Même logique que cli.py (saisie URL, confirmation d'autorisation, appel
au Scope Manager, journalisation), mais sous forme de page web au lieu
du terminal. Toute la logique métier vient de core.py et scope_manager.py
— ce fichier ne fait QUE gérer l'affichage et les routes.
"""

from __future__ import annotations

from flask import Flask, render_template, request

from core import charger_whitelist, journaliser, lire_scan_results, lire_hypotheses
from scope_manager import is_authorized

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    resultat = None  # rien à afficher tant que le formulaire n'est pas soumis

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        confirme_par_utilisateur = request.form.get("autorisation") == "on"

        if not confirme_par_utilisateur:
            resultat = {
                "autorise": False,
                "raison": "Aucune confirmation d'autorisation fournie.",
                "url": url,
            }
            journaliser(url, confirme_par_utilisateur, False, resultat["raison"], source="web")
        else:
            whitelist = charger_whitelist()
            autorise, raison = is_authorized(url, whitelist)
            resultat = {"autorise": autorise, "raison": raison, "url": url}
            journaliser(url, confirme_par_utilisateur, autorise, raison, source="web")

    return render_template("index.html", resultat=resultat)


@app.route("/scan-results")
def scan_results():
    """
    Vue en LECTURE SEULE des résultats de scan bruts (section 8).
    Aucune action possible ici volontairement — ce n'est que du factuel,
    produit par le Normalizer (Module 6, pas encore construit).
    """
    resultats = lire_scan_results()
    return render_template("scan_results.html", resultats=resultats)


@app.route("/hypotheses")
def hypotheses():
    """
    Vue INTERACTIVE des hypothèses à trier (section 7).
    C'est ici que la personne de triage travaillera une fois le module
    de génération d'hypothèses (Module 7) construit. Pour l'instant,
    lecture seule aussi — le tri/l'édition viendra plus tard.
    """
    liste = lire_hypotheses()
    return render_template("hypotheses.html", hypotheses=liste)


if __name__ == "__main__":
    app.run(debug=True, port=5000)