# ADB Dashboard API

## Description

API de gestion et de contrôle de périphériques Android via ADB (Android Debug Bridge).

## Fonctionnalités Principales

- Authentification sécurisée
- Gestion des périphériques Android
- Contrôle des applications
- Gestion des fichiers
- Configuration système
- Outils de débogage

## Prérequis

- Python 3.8+
- ADB installé
- Périphériques Android en mode débogage

## Installation

```bash
# Cloner le dépôt
git clone https://github.com/votre-organisation/adb-dashboard-api.git

# Créer un environnement virtuel
python -m venv venv
source venv/bin/activate  # Sur Windows: venv\Scripts\activate

# Installer les dépendances
pip install -r requirements.txt
```

## Configuration

1. Configurez les paramètres dans `config.py`
2. Assurez-vous que ADB est correctement installé
3. Activez le mode développeur sur vos périphériques Android

## Démarrage

```bash
# Lancer le serveur
uvicorn src.main:app --reload
```

## Documentation API

Consultez le [MANUEL_UTILISATION.md](MANUEL_UTILISATION.md) pour une documentation complète.

## Sécurité

- Utilisez HTTPS en production
- Gérez vos tokens de session
- Limitez l'accès réseau

## Contribution

1. Fork du projet
2. Créez une branche de fonctionnalité
3. Commitez vos modifications
4. Poussez et créez une Pull Request

## Licence

[Spécifiez votre licence]

## Contact

[Vos informations de contact]
