FROM python:3.10-slim

WORKDIR /app

# Installation des dépendances système
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# ⚠️ LA CORRECTION EST ICI : mettre à jour pip AVANT tout le reste
# Les vieilles versions de pip rejettent les fichiers typing_extensions de l'index PyTorch
RUN pip install --upgrade pip

# 1. Installer typing-extensions depuis PyPI officiel (nom correct)
RUN pip install --no-cache-dir --only-binary=:all: typing-extensions==4.12.2

# 2. Installer PyTorch CPU (pip est maintenant à jour, il acceptera les fichiers)
RUN pip install --no-cache-dir --only-binary=:all: torch==2.4.0+cpu --index-url https://download.pytorch.org/whl/cpu

# 3. Installer le reste des dépendances
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code
COPY . .

CMD ["python", "pipeline.py"]