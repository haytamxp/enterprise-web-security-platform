FROM python:3.10-slim

WORKDIR /app

# Installation des dépendances système pour sentence-transformers
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# 1. On installe PyTorch en version CPU uniquement AVANT le reste
# On force une version spécifique (2.4.0) qui évite le bug de flit_core
# Et on ajoute --only-binary=:all: pour empêcher pip de tenter de compiler depuis les sources
RUN pip install --no-cache-dir torch==2.4.0+cpu --index-url https://download.pytorch.org/whl/cpu --only-binary=:all:


# 2. On copie les requirements et on installe le reste
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# On copie tout le code
COPY . .

# On lance le pipeline principal
CMD ["python", "pipeline.py"]