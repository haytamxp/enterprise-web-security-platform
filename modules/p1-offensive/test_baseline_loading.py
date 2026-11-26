
from pathlib import Path

from circuit_breaker import CircuitBreaker

# Emplacement du fichier contenant les mesures réelles.
chemin = Path(__file__).resolve().parent / "data" / "baseline.json"

# Création du Circuit Breaker à partir de cette baseline.
breaker = CircuitBreaker.depuis_fichier(chemin)

# Affichage des seuils réellement chargés.
print("Seuil dégradé :", round(breaker.seuil_degrade_ms, 1), "ms")
print("Seuil critique :", round(breaker.seuil_critique_ms, 1), "ms")
print("État initial :", breaker.etat().value)
