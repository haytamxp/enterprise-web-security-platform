import pandas as pd
import numpy as np
import joblib

from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, f1_score


# Chemins des datasets UNSW-NB15
DATA_DIR = "data/CSV Files/Training and Testing Sets"

TRAIN_PATH = f"{DATA_DIR}/UNSW_NB15_training-set.csv"
TEST_PATH = f"{DATA_DIR}/UNSW_NB15_testing-set.csv"

# Dossier de sauvegarde du modèle
MODEL_DIR = "models"

# Chargement des datasets
print("Chargement du dataset UNSW-NB15...")

train_df = pd.read_csv(TRAIN_PATH)
test_df = pd.read_csv(TEST_PATH)

print("Dataset d'entraînement :", train_df.shape)
print("Dataset de test :", test_df.shape)

print("\nRépartition des classes dans le dataset d'entraînement :")
print(train_df["attack_cat"].value_counts())

# Préparation des variables
TARGET = "attack_cat"

DROP_COLUMNS = ["id", "label", TARGET]

X_train = train_df.drop(columns=DROP_COLUMNS)
y_train = train_df[TARGET]

X_test = test_df.drop(columns=DROP_COLUMNS)
y_test = test_df[TARGET]

# Identification des colonnes catégorielles et numériques
CATEGORICAL_FEATURES = ["proto", "service", "state"]

NUMERICAL_FEATURES = [
    col for col in X_train.columns
    if col not in CATEGORICAL_FEATURES
]

print("\nPréparation des données terminée.")
print("Variables d'entraînement :", X_train.shape)
print("Variables de test :", X_test.shape)
print("Nombre de variables catégorielles :", len(CATEGORICAL_FEATURES))
print("Nombre de variables numériques :", len(NUMERICAL_FEATURES))

# Prétraitement des caractéristiques
preprocessor = ColumnTransformer(
    transformers=[
        (
            "categorical",
            OneHotEncoder(handle_unknown="ignore"),
            CATEGORICAL_FEATURES
        ),
        (
            "numerical",
            "passthrough",
            NUMERICAL_FEATURES
        )
    ]
)

print("\nPréprocesseur configuré avec succès.")

# Configuration du modèle Random Forest
model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced_subsample"
)

# Création du pipeline complet
pipeline = Pipeline(
    steps=[
        ("preprocessor", preprocessor),
        ("classifier", model)
    ]
)

print("\nModèle Random Forest configuré avec succès.")

# Entraînement du modèle
print("\nDébut de l'entraînement du modèle...")

pipeline.fit(X_train, y_train)

print("Entraînement terminé avec succès !")

# Évaluation du modèle sur le dataset de test
print("\nDébut de l'évaluation du modèle...")

y_pred = pipeline.predict(X_test)

print("Prédictions terminées avec succès !")


# Évaluation des performances
print("\nRapport de classification :")
print(classification_report(y_test, y_pred, zero_division=0))

accuracy = accuracy_score(y_test, y_pred)
f1_macro = f1_score(y_test, y_pred, average="macro", zero_division=0)

print(f"\nAccuracy : {accuracy:.4f}")
print(f"F1 Macro : {f1_macro:.4f}")

# Sauvegarde du modèle entraîné
import os

os.makedirs(MODEL_DIR, exist_ok=True)

model_path = os.path.join(
    MODEL_DIR,
    "unsw_nb15_random_forest_v2.joblib"
)

joblib.dump(pipeline, model_path)

print(f"\nModèle sauvegardé avec succès : {model_path}")