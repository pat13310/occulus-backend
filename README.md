# Occulus Backend
API de gestion de manettes XR (Réalité Étendue)

## Description

API spécialisée dans la gestion et le contrôle des manettes pour systèmes de réalité étendue.

## Fonctionnalités Principales

- Authentification sécurisée
- Gestion des périphériques de manettes XR
- Contrôle des interactions
- Configuration système
- Outils de débogage

## Prérequis

- Python 3.8+
- Environnement de développement XR

## Installation

```bash
# Cloner le dépôt
git clone https://github.com/pat13310/occulus-backend.git

# Créer un environnement virtuel
python -m venv venv
venv\Scripts\activate  # Commande pour Windows

# Installer les dépendances
pip install -r requirements.txt
```

## Démarrage

```bash
# Lancer le serveur
uvicorn src.main:app --reload
```

## Sécurité

- Utilisez HTTPS en production
- Gérez vos tokens de session
- Sécurisez les connexions des périphériques

## Contribution

1. Fork du projet
2. Créez une branche de fonctionnalité
3. Commitez vos modifications
4. Poussez et créez une Pull Request

## Licence

[À spécifier]

## Contact

[Informations de contact]