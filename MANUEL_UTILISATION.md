# Manuel d'Utilisation de l'API ADB Dashboard

## Introduction

Cette API permet de gérer et interagir avec des appareils Android à distance via ADB (Android Debug Bridge). Elle offre une variété de fonctionnalités pour la gestion des périphériques, des applications, des fichiers et des paramètres système.

## Authentification

### Connexion
- **Endpoint**: `POST /auth/login`
- **Paramètres**:
  - `username`: Nom d'utilisateur
  - `password`: Mot de passe
- **Réponse**: Token de session, durée de validité

### Déconnexion
- **Endpoint**: `POST /auth/logout`
- **Paramètres**:
  - `session_token`: Token de session actif

### Rafraîchissement de Session
- **Endpoint**: `POST /auth/session/refresh`
- **Paramètres**:
  - `session_token`: Token de session à rafraîchir

## Gestion des Périphériques

### Liste des Périphériques
- **Endpoint**: `GET /device/list`
- **Description**: Récupère la liste des périphériques ADB disponibles

### Connexion à un Périphérique
- **Endpoint**: `POST /device/connect`
- **Paramètres**:
  - `adresse_ip`: Adresse IP du périphérique
  - `port`: Port de connexion (défaut: 5555)

### Redémarrage du Périphérique
- **Endpoint**: `POST /device/restart`

## Gestion des Applications

### Liste des Applications
- **Endpoint**: `GET /app/list`
- **Description**: Récupère la liste des applications installées

### Installation d'Application
- **Endpoint**: `POST /app/install`
- **Paramètres**:
  - `fichier_apk`: Fichier APK à installer

### Désinstallation d'Application
- **Endpoint**: `POST /app/uninstall`
- **Paramètres**:
  - `nom_package`: Nom du package de l'application

### Détails d'une Application
- **Endpoint**: `GET /app/details/{nom_package}`

## Gestion des Fichiers

### Liste des Fichiers
- **Endpoint**: `GET /files/list`
- **Paramètres**:
  - `chemin`: Chemin du répertoire (défaut: /sdcard)
  - `recursif`: Recherche récursive (true/false)

### Upload de Fichier
- **Endpoint**: `POST /files/upload`
- **Paramètres**:
  - `fichier`: Fichier à uploader
  - `destination`: Chemin de destination

### Téléchargement de Fichier
- **Endpoint**: `POST /files/download`
- **Paramètres**:
  - `chemin_distant`: Chemin du fichier sur le périphérique
  - `destination_locale`: Chemin de destination local

## Gestion des Paramètres Système

### Paramètres WiFi
- **Endpoint**: `GET /settings/wifi`
- **Endpoint**: `POST /settings/wifi/connect`
  - Paramètres: `ssid`, `mot_de_passe`

### Paramètres Bluetooth
- **Endpoint**: `GET /settings/bluetooth`
- **Endpoint**: `POST /settings/bluetooth/toggle`
  - Paramètre: `activer` (true/false)

### Mode Avion
- **Endpoint**: `GET /settings/mode-avion`
- **Endpoint**: `POST /settings/mode-avion/toggle`
  - Paramètre: `activer` (true/false)

## Informations Système

### Informations Batterie
- **Endpoint**: `GET /battery`
- **Endpoint**: `GET /battery/details`

### Informations Réseau
- **Endpoint**: `GET /network`
- **Endpoint**: `GET /network/details`
- **Endpoint**: `GET /network/test`

### Informations Système
- **Endpoint**: `GET /system/details`
- **Endpoint**: `GET /performance`

## Débogage

### Logs Système
- **Endpoint**: `GET /logs/system`
- **Paramètres**:
  - `lignes`: Nombre de lignes à récupérer
  - `niveau`: Niveau de log

### Logs d'Application
- **Endpoint**: `GET /logs/application`
- **Paramètres**:
  - `nom_package`: Nom du package de l'application
  - `lignes`: Nombre de lignes à récupérer

### Capture de Débogage
- **Endpoint**: `POST /debug/capture`
- **Paramètres**:
  - `type_capture`: Type de capture (screenshot, etc.)

## Codes de Retour

- `200`: Succès
- `201`: Création réussie
- `400`: Erreur de requête
- `401`: Non autorisé
- `404`: Ressource non trouvée
- `500`: Erreur serveur

## Exemple d'Utilisation

```bash
# Connexion
curl -X POST http://localhost:8000/auth/login \
     -F "username=admin" \
     -F "password=admin"

# Liste des périphériques
curl -X GET http://localhost:8000/device/list \
     -H "Authorization: Bearer {session_token}"
```

## Sécurité

- Utilisez HTTPS en production
- Protégez vos tokens de session
- Limitez l'accès à l'API

## Dépannage

- Vérifiez que ADB est installé et configuré
- Assurez-vous que le périphérique est en mode débogage
- Consultez les logs en cas d'erreur

## Contributions

Les contributions sont les bienvenues. Veuillez soumettre des pull requests ou ouvrir des issues sur le dépôt GitHub.

## Licence

[Spécifiez votre licence ici]

---

**Note**: Ce manuel est susceptible d'évoluer. Consultez toujours la dernière version.
