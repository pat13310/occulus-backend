# Diagrammes d'Interactions de l'API ADB Dashboard

## Vue d'Ensemble des Interactions

Ce document décrit les principaux flux d'interactions entre les différents composants de l'API ADB Dashboard.

## Légende des Diagrammes

```
🟢 : Début de l'interaction
🔵 : Étape de traitement
🟠 : Décision/Condition
🔴 : Fin de l'interaction ou Erreur
➡️ : Flux d'interaction
```

## 1. Authentification et Gestion de Session

### Diagramme de Connexion

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant AdbServices
    participant SessionManager

    Client->>+API: POST /auth/login
    API->>+SessionManager: Vérifier identifiants
    SessionManager-->>-API: Identifiants valides
    API->>+SessionManager: Créer session
    SessionManager-->>-API: Générer token
    API-->>-Client: Retourner token de session
```

### Diagramme de Déconnexion

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant SessionManager

    Client->>+API: POST /auth/logout
    API->>+SessionManager: Invalider session
    SessionManager-->>-API: Session supprimée
    API-->>-Client: Confirmation de déconnexion
```

## 2. Gestion des Périphériques

### Diagramme de Connexion de Périphérique

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant AdbServices

    Client->>+API: POST /device/connect
    API->>+AdbServices: Établir connexion ADB
    AdbServices-->>-API: Résultat connexion
    API-->>-Client: Statut de connexion
```

### Diagramme de Liste des Périphériques

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant AdbServices

    Client->>+API: GET /device/list
    API->>+AdbServices: Lister périphériques
    AdbServices-->>-API: Liste des périphériques
    API-->>-Client: Retourner liste
```

## 3. Gestion des Applications

### Diagramme d'Installation d'Application

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant AdbServices

    Client->>+API: POST /app/install
    API->>+AdbServices: Préparer installation
    AdbServices->>AdbServices: Vérifier APK
    AdbServices->>AdbServices: Installer application
    AdbServices-->>-API: Résultat installation
    API-->>-Client: Statut d'installation
```

## 4. Gestion des Fichiers

### Diagramme d'Upload de Fichier

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant AdbServices
    participant Stockage

    Client->>+API: POST /files/upload
    API->>+AdbServices: Préparer transfert
    AdbServices->>+Stockage: Enregistrer fichier
    Stockage-->>-AdbServices: Confirmation
    AdbServices-->>-API: Résultat transfert
    API-->>-Client: Statut du transfert
```

## 5. Gestion des Paramètres Système

### Diagramme de Configuration WiFi

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant AdbServices
    participant SystemSettings

    Client->>+API: POST /settings/wifi/connect
    API->>+AdbServices: Configurer WiFi
    AdbServices->>+SystemSettings: Modifier paramètres
    SystemSettings-->>-AdbServices: Confirmation
    AdbServices-->>-API: Résultat configuration
    API-->>-Client: Statut de configuration
```

## 6. Gestion des Logs et Débogage

### Diagramme de Capture de Logs

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant AdbServices
    participant LogSystem

    Client->>+API: GET /logs/system
    API->>+AdbServices: Récupérer logs
    AdbServices->>+LogSystem: Extraire logs
    LogSystem-->>-AdbServices: Données de logs
    AdbServices-->>-API: Logs système
    API-->>-Client: Retourner logs
```

## Principes de Sécurité

1. Toutes les interactions passent par l'API
2. Authentification requise pour la plupart des endpoints
3. Validation et assainissement des entrées
4. Gestion des erreurs et des exceptions
5. Tokens de session avec durée de vie limitée

## Considérations de Performance

- Utilisation de connexions ADB optimisées
- Mise en cache des résultats fréquents
- Gestion asynchrone des requêtes
- Limitation du nombre de connexions simultanées

## Notes Techniques

- Les diagrammes sont générés avec Mermaid
- Représentent les flux logiques principaux
- Ne montrent pas tous les détails d'implémentation

## Contribution

Pour mettre à jour ces diagrammes :
1. Modifier le fichier DIAGRAMMES_INTERACTIONS.md
2. Utiliser la syntaxe Mermaid
3. Tester la lisibilité et la précision

---

**Avertissement** : Ces diagrammes sont des représentations conceptuelles. L'implémentation réelle peut varier.
