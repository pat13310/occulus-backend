import os
import sys
import logging
import json
from typing import Optional
import traceback

from fastapi import FastAPI, Request, HTTPException, Depends, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import File, UploadFile

from src.services.adb_services import AdbServices

# Configuration de la journalisation plus détaillée
logging.basicConfig(
    level=logging.DEBUG,  # Niveau de log le plus détaillé
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('debug.log', encoding='utf-8'),  # Log dans un fichier
        logging.StreamHandler()  # Log également dans la console
    ]
)
logger = logging.getLogger(__name__)

# Middleware de débogage personnalisé
class DebugMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Log des informations sur la requête
        logger.debug(f"Requête entrante : {request.method} {request.url.path}")
        logger.debug(f"En-têtes : {dict(request.headers)}")
        
        try:
            # Copier le corps de la requête pour le log
            body = await request.body()
            if body:
                logger.debug(f"Corps de la requête : {body.decode('utf-8')}")
        except Exception as e:
            logger.error(f"Erreur lors de la lecture du corps de la requête : {e}")
        
        response = await call_next(request)
        
        # Log de la réponse
        logger.debug(f"Statut de la réponse : {response.status_code}")
        
        return response

# Gestionnaire d'exceptions global
def create_app():
    app = FastAPI(
        title="ADB Dashboard",
        description="Dashboard de gestion des appareils Android",
        version="0.1.0"
    )

    # Ajout du middleware de débogage
    app.add_middleware(DebugMiddleware)

    # Configuration CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Autorise toutes les origines en développement
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(Exception)
    async def exception_handler(request: Request, exc: Exception):
        """
        Gestionnaire global des exceptions
        """
        # Log détaillé de l'exception
        logger.error(f"Erreur non gérée : {exc}")
        logger.error(f"Détails de la requête : {request.method} {request.url}")
        logger.error(traceback.format_exc())

        # Réponse d'erreur personnalisée
        return JSONResponse(
            status_code=500,
            content={
                "message": "Une erreur interne est survenue",
                "details": str(exc),
                "path": str(request.url)
            }
        )

    return app

# Créer l'application avec les configurations de débogage
app = create_app()

# Ajouter le répertoire parent au chemin de recherche
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Configuration de l'application avec des métadonnées personnalisées
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title="ADB API Dashboard",
        version="1.0.0",
        description="""
        ## Interface de Gestion des Appareils Android

        Cette API permet de gérer et d'interagir avec des appareils Android via ADB (Android Debug Bridge).

        ### Fonctionnalités principales :
        - Gestion des périphériques
        - Informations système
        - Contrôle réseau
        - Gestion de la batterie

        ### Technologies utilisées :
        - FastAPI
        - ADB
        - Python
        """,
        routes=app.routes,
    )
    
    # Personnalisation de la documentation
    openapi_schema["info"]["x-logo"] = {
        "url": "https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png"
    }
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app = FastAPI(
    title="ADB API Dashboard",
    description="Interface de gestion des appareils Android",
    version="1.0.0",
    docs_url="/documentation",  # Personnaliser l'URL de Swagger
    redoc_url="/redoc"
)

# Appliquer le schéma OpenAPI personnalisé
app.openapi = custom_openapi

# Ajout des routes de documentation
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.openapi.utils import get_openapi

# Route pour Swagger UI personnalisé
@app.get("/swagger", include_in_schema=False)
async def custom_swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="ADB API Dashboard - Swagger UI",
        swagger_js_url="https://unpkg.com/swagger-ui-dist@5.9.3/swagger-ui-bundle.js",
        swagger_css_url="https://unpkg.com/swagger-ui-dist@5.9.3/swagger-ui.css"
    )

# Route pour ReDoc
@app.get("/docs", include_in_schema=False)
async def redoc_html():
    return get_redoc_html(
        openapi_url="/openapi.json", 
        title="ADB API Dashboard - Documentation"
    )

# Configuration des templates
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
logger.info(f"Répertoire des templates : {templates_dir}")
logger.info(f"Fichiers dans le répertoire des templates : {os.listdir(templates_dir)}")

# Créer l'instance Jinja2Templates avec le répertoire correct
templates = Jinja2Templates(directory=templates_dir)

# Montage des fichiers statiques (optionnel)
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Importations pour la gestion des sessions
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta
import secrets

# Fonction pour générer un token sécurisé
def generer_token_securise(longueur=32):
    """
    Génère un token de session sécurisé
    
    Args:
        longueur (int): Longueur du token
    
    Returns:
        str: Token généré
    """
    import secrets
    return secrets.token_urlsafe(longueur)

# Stockage des sessions (à remplacer par une base de données dans un environnement de production)
sessions = {}

# Fonction pour créer une session
def create_session(username: str, duree_validite: int = 3600) -> str:
    """
    Créer une nouvelle session pour l'utilisateur
    
    Args:
        username (str): Nom d'utilisateur
        duree_validite (int): Durée de validité de la session en secondes
    
    Returns:
        str: Token de session
    """
    import time
    
    # Vérifier si l'utilisateur existe (à remplacer par une vérification en base de données)
    utilisateurs_valides = {"admin": "admin"}  # Exemple de dictionnaire d'utilisateurs
    if username not in utilisateurs_valides:
        raise ValueError("Utilisateur non reconnu")
    
    # Générer un nouveau token
    session_token = generer_token_securise()
    
    # Stocker les informations de session
    sessions[session_token] = {
        'username': username,
        'creation': time.time(),
        'expiration': time.time() + duree_validite
    }
    
    return session_token

# Fonction pour vérifier une session
def verify_session(session_token: str) -> bool:
    """
    Vérifier la validité d'une session
    
    Args:
        session_token (str): Token de session à vérifier
    
    Returns:
        bool: True si la session est valide, False sinon
    """
    import time
    
    # Vérifier si le token existe
    if session_token not in sessions:
        return False
    
    # Vérifier si la session a expiré
    session = sessions[session_token]
    if time.time() > session['expiration']:
        # Supprimer la session expirée
        del sessions[session_token]
        return False
    
    return True

# Fonction pour récupérer l'utilisateur connecté
def get_current_user(session_token: str) -> Optional[str]:
    """
    Récupérer l'utilisateur connecté à partir du token de session
    
    Args:
        session_token (str): Token de session
    
    Returns:
        str or None: Nom d'utilisateur ou None si non connecté
    """
    if verify_session(session_token):
        return sessions[session_token]['username']
    return None

# Route pour l'authentification
@app.post("/auth/login")
async def route_authentification(
    username: str = Form(...), 
    password: str = Form(...)
):
    try:
        # Vérification des identifiants (à remplacer par une vérification en base de données)
        utilisateurs_valides = {
            "admin": "admin",
            "utilisateur": "motdepasse"
        }
        
        if username not in utilisateurs_valides or utilisateurs_valides[username] != password:
            return JSONResponse(content={
                "status": "error", 
                "message": "Identifiants incorrects"
            }, status_code=401)
        
        # Créer une session
        session_token = create_session(username)
        
        return JSONResponse(content={
            "status": "success", 
            "message": "Connexion réussie", 
            "username": username,
            "session_token": session_token,
            "expires_in": 3600  # Durée de validité de la session en secondes
        }, status_code=200)
    
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": str(e)
        }, status_code=500)

# Route pour la déconnexion
@app.post("/auth/logout")
async def route_deconnexion(
    session_token: str = Form(...)
):
    try:
        # Vérifier si la session existe
        if session_token not in sessions:
            return JSONResponse(content={
                "status": "error", 
                "message": "Session invalide"
            }, status_code=400)
        
        # Supprimer la session
        del sessions[session_token]
        
        return JSONResponse(content={
            "status": "success", 
            "message": "Déconnexion réussie"
        }, status_code=200)
    
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": str(e)
        }, status_code=500)

# Route pour rafraîchir une session
@app.post("/auth/session/refresh")
async def route_rafraichir_session(
    session_token: str = Form(...)
):
    try:
        # Vérifier si la session existe
        if session_token not in sessions:
            return JSONResponse(content={
                "status": "error", 
                "message": "Session invalide"
            }, status_code=400)
        
        # Récupérer l'utilisateur
        username = sessions[session_token]['username']
        
        # Supprimer l'ancienne session
        del sessions[session_token]
        
        # Créer une nouvelle session
        nouveau_token = create_session(username)
        
        return JSONResponse(content={
            "status": "success", 
            "message": "Session rafraîchie", 
            "username": username,
            "nouveau_session_token": nouveau_token,
            "expires_in": 3600  # Durée de validité de la session en secondes
        }, status_code=200)
    
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": str(e)
        }, status_code=500)

# Route pour lister les sessions actives
@app.get("/auth/sessions")
async def route_lister_sessions_actives():
    try:
        import time
        
        # Filtrer les sessions actives
        sessions_actives = [
            {
                "username": session['username'], 
                "temps_restant": int(session['expiration'] - time.time())
            } 
            for session in sessions.values() 
            if time.time() < session['expiration']
        ]
        
        return JSONResponse(content={
            "status": "success", 
            "message": "Sessions actives récupérées",
            "nombre_sessions": len(sessions_actives),
            "sessions": sessions_actives
        }, status_code=200)
    
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": str(e)
        }, status_code=500)

@app.get("/", response_class=HTMLResponse)
async def racine(request: Request):
    """
    Page d'accueil avec les routes disponibles

    Args:
        request (Request): Requête HTTP

    Returns:
        HTMLResponse: Template d'index
    """
    try:
        logger.info(f"Chemin du template : {os.path.join(templates_dir, 'index.html')}")
        logger.info(f"Le fichier template existe : {os.path.exists(os.path.join(templates_dir, 'index.html'))}")
        
        # Routes disponibles
        routes = [
            {'name': 'Tableau de Bord', 'description': 'Tableau de bord complet des informations système', 'path': '/dashboard', 'icon': 'fas fa-chart-bar', 'color': 'blue'},
            {'name': 'Configuration IP', 'description': 'Configuration et connexion des périphériques', 'path': '/configuration-ip', 'icon': 'fas fa-network-wired', 'color': 'green'},
            {'name': 'Serveur ADB', 'description': 'Gestion du serveur ADB', 'path': '/serveur/demarrer', 'icon': 'fas fa-server', 'color': 'purple'}
        ]
        
        # Récupérer le message de connexion du cookie
        connexion_message = request.cookies.get('connexion_message', '')
        
        # Contexte du template
        context = {
            "request": request,
            "routes": routes,
            "resultat_connexion": {"message": connexion_message} if connexion_message else {},
            "erreur": None  # Ajouter un champ pour les erreurs explicites
        }
        
        logger.info("Routes disponibles : " + str(routes))
        logger.info(f"Répertoire des templates : {os.path.dirname(templates_dir)}")
        
        # Vérifier les fichiers dans le répertoire des templates
        try:
            fichiers_templates = os.listdir(os.path.dirname(templates_dir))
            logger.info(f"Fichiers dans le répertoire des templates : {fichiers_templates}")
        except Exception as e:
            logger.error(f"Erreur lors de la liste des fichiers templates : {e}")
        
        response = templates.TemplateResponse(
            "index.html", 
            context, 
            status_code=200
        )
        
        # Supprimer le cookie de message après l'avoir utilisé
        if connexion_message:
            response.delete_cookie(key="connexion_message")
        
        logger.info(f"Statut de la réponse : {response.status_code}")
        return response
    
    except Exception as e:
        logger.error(f"Erreur fatale lors du rendu de la page d'accueil : {e}")
        logger.error(traceback.format_exc())
        raise

@app.get("/hello/{nom}")
async def salutation(nom: str):
    return JSONResponse(content={"message": f"Bonjour, {nom}!"}, status_code=200)

@app.get("/devices")
async def lister_peripheriques():
    peripheriques = AdbServices.lister_peripheriques()
    return JSONResponse(content={"peripheriques": peripheriques}, status_code=200)

@app.get("/android/version")
async def version_android():
    version = AdbServices.version_android()
    return JSONResponse(content={"version_android": version}, status_code=200)

@app.get("/battery")
async def infos_batterie():
    """
    Récupère les informations de batterie
    
    Returns:
        JSONResponse
    """
    try:
        resultat_batterie = AdbServices.Systeme.batterie()
        return JSONResponse(content=resultat_batterie)
    except Exception as e:
        return JSONResponse(content={"statut": "Erreur", "message": str(e)}, status_code=500)

@app.get("/apps")
async def lister_applications():
    """
    Liste les applications installées sur le périphérique Android
    
    Returns:
        List[str]: Liste des noms des applications installées
    """
    try:
        applications = AdbServices.Applications.lister_applications()
        return applications
    except Exception as e:
        return {"erreur": str(e)}

@app.get("/network/ip")
async def ip_wifi():
    """Récupère l'adresse IP WiFi"""
    try:
        return {"ip_wifi": AdbServices.Reseau.ip_wifi()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/network/infos")
async def infos_reseau():
    """
    Récupère les informations réseau du périphérique Android
    
    Returns:
        Dict avec les informations réseau
    """
    try:
        resultat_reseau = AdbServices.Reseau.informations_reseau()
        
        # Log pour le débogage
        print("Informations réseau récupérées :", resultat_reseau)
        
        return resultat_reseau
    except Exception as e:
        print(f"Erreur lors de la récupération des informations réseau : {str(e)}")
        return {
            "statut": "Erreur", 
            "message": f"Impossible de récupérer les informations réseau : {str(e)}"
        }

@app.get("/network/test-connexion")
async def test_connexion_wifi():
    """
    Teste la connexion WiFi du périphérique
    
    Returns:
        Dict avec le résultat du test de connexion
    """
    try:
        resultat_test = AdbServices.Reseau.tester_connexion_wifi()
        return resultat_test
    except Exception as e:
        return {
            "statut": "Erreur", 
            "message": f"Impossible de tester la connexion : {str(e)}"
        }

@app.get("/network/details")
async def infos_reseau_detaillees():
    """
    Récupère des informations réseau détaillées du périphérique Android
    
    Returns:
        Dict avec les informations réseau complètes
    """
    try:
        resultat_reseau = AdbServices.Reseau.informations_reseau_detaillees()
        return resultat_reseau
    except Exception as e:
        print(f"Erreur lors de la récupération des informations réseau détaillées : {str(e)}")
        return {
            "statut": "Erreur", 
            "message": f"Impossible de récupérer les informations réseau détaillées : {str(e)}"
        }

@app.get("/network/test-complet")
async def test_connexion_reseau():
    """
    Effectue un test complet de connectivité réseau
    
    Returns:
        Dict avec les résultats des tests de connectivité
    """
    try:
        resultat_test = AdbServices.Reseau.tester_connexion_reseau()
        return resultat_test
    except Exception as e:
        print(f"Erreur lors du test de connectivité réseau : {str(e)}")
        return {
            "statut": "Erreur", 
            "message": f"Échec du test de connectivité : {str(e)}"
        }

@app.get("/network/wifi-details")
async def infos_wifi_detaillees():
    """
    Récupère des informations WiFi détaillées du périphérique Android
    
    Returns:
        Dict avec les informations WiFi complètes
    """
    try:
        resultat_wifi = AdbServices.Reseau.informations_wifi_detaillees()
        return resultat_wifi
    except Exception as e:
        print(f"Erreur lors de la récupération des informations WiFi : {str(e)}")
        return {
            "statut": "Erreur", 
            "message": f"Impossible de récupérer les informations WiFi : {str(e)}"
        }

@app.get("/system/redemarrer")
async def redemarrer_peripherique():
    """Redémarre le périphérique"""
    try:
        resultat = AdbServices.Systeme.redemarrer()
        return {"statut": "Redémarrage en cours", "details": resultat}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/configuration-ip", response_class=HTMLResponse)
async def page_configuration_ip(request: Request):
    """
    Affiche la page de configuration de l'adresse IP
    
    Returns:
        HTMLResponse: Page de configuration IP
    """
    return templates.TemplateResponse("configuration_ip.html", {
        "request": request,
        "resultat_connexion": {
            "statut": "",
            "message": "",
            "adresse_ip": "",
            "port": 5555
        }
    })

@app.post("/connect", response_class=HTMLResponse)
async def route_connecter_peripherique_avec_redirection(
    request: Request,
    adresse_ip: str = Form(...),
    port: int = Form(5555)
):
    """
    Connecte un périphérique et redirige selon le résultat de la connexion
    
    Args:
        request (Request): Requête HTTP
        adresse_ip (str): Adresse IP du périphérique
        port (int, optional): Port de connexion. Défaut à 5555.
    
    Returns:
        HTMLResponse ou RedirectResponse
    """
    # Vérification de l'adresse IP
    if not adresse_ip:
        return templates.TemplateResponse("configuration_ip.html", {
            "request": request, 
            "resultat_connexion": {
                "statut": "Erreur",
                "message": "Adresse IP manquante",
                "adresse_ip": adresse_ip,
                "port": port
            }
        }, status_code=400)
    
    try:
        # Utiliser la fonction existante de connexion
        resultat_connexion = AdbServices.Peripheriques.connecter_peripherique(adresse_ip, port)
        
        # Ajouter l'adresse IP et le port au résultat de connexion
        resultat_connexion['adresse_ip'] = adresse_ip
        resultat_connexion['port'] = port
        
        # Vérifier si la connexion a réussi
        if resultat_connexion.get('statut') in ['Succès', 'Déjà connecté']:
            # Rediriger vers la page racine avec un message de succès
            response = RedirectResponse(url="/", status_code=303)
            response.set_cookie(key="connexion_message", value=f"Périphérique connecté avec succès à {adresse_ip}:{port}")
            return response
        
        # Si la connexion échoue, rester sur la page de configuration avec le message d'erreur
        return templates.TemplateResponse("configuration_ip.html", {
            "request": request, 
            "resultat_connexion": resultat_connexion
        }, status_code=400)
    
    except Exception as e:
        # Gérer les erreurs inattendues
        return templates.TemplateResponse("configuration_ip.html", {
            "request": request, 
            "resultat_connexion": {
                "statut": "Erreur système",
                "message": f"Erreur lors de la connexion : {str(e)}",
                "details": str(e),
                "adresse_ip": adresse_ip,
                "port": port
            }
        }, status_code=500)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """
    Page de tableau de bord avec les informations système

    Args:
        request (Request): Requête HTTP

    Returns:
        HTMLResponse: Template du dashboard
    """
    # Définir un dictionnaire par défaut
    default_device_info = {
        'cpu_usage': 0,
        'memory_usage': 0,
        'android_version': 'Aucun appareil connecté',
        'battery_level': 0
    }

    try:
        # Vérifier la session de l'utilisateur
        session_token = request.cookies.get("session_token")
        current_user = get_current_user(session_token)
        
        if not current_user:
            # Rediriger vers la page d'accueil avec un message d'erreur
            response = RedirectResponse(url="/", status_code=303)
            response.set_cookie(
                key="connexion_message", 
                value="Veuillez vous connecter pour accéder au dashboard", 
                max_age=5,
                httponly=True
            )
            return response
        
        # Récupérer les informations système
        try:
            device_info = AdbServices.get_device_info()
            logger.info(f"DEBUG: device_info = {device_info}")
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des informations système : {e}")
            device_info = None
        
        # Préparer le contexte du template
        context = {
            "request": request,
            "utilisateur": current_user,
            "appareil_connecte": device_info is not None,
            "infos_appareil": device_info or default_device_info,
            "resultat_connexion": {"message": f"Bienvenue {current_user} !"}
        }
        logger.info(f"DEBUG: context = {context}")
        
        # Rendu du template
        response = templates.TemplateResponse(
            "dashboard.html", 
            context, 
            status_code=200
        )
        
        return response
    
    except Exception as e:
        logger.error(f"Erreur fatale lors du rendu du dashboard : {e}")
        logger.error(traceback.format_exc())
        
        # Préparer un contexte minimal
        context = {
            "request": request,
            "utilisateur": current_user if 'current_user' in locals() else None,
            "appareil_connecte": False,
            "infos_appareil": default_device_info,
            "erreur": "Erreur technique lors de l'accès au dashboard"
        }
        
        # Rendu du template avec le contexte minimal
        response = templates.TemplateResponse(
            "dashboard.html", 
            context, 
            status_code=500
        )
        
        return response

@app.post("/server/start")
async def route_demarrer_serveur(host: str = "0.0.0.0", port: int = 8000):
    try:
        # Logique de démarrage du serveur
        return JSONResponse(content={
            "status": "success", 
            "message": "Serveur démarré", 
            "host": host, 
            "port": port
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": str(e)
        }, status_code=500)

@app.post("/server/stop")
async def route_arreter_serveur():
    try:
        # Logique d'arrêt du serveur
        return JSONResponse(content={
            "status": "success", 
            "message": "Serveur arrêté"
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": str(e)
        }, status_code=500)

@app.post("/adb/server/start")
async def route_demarrer_serveur_adb():
    try:
        # Logique de démarrage du serveur ADB
        return JSONResponse(content={
            "status": "success", 
            "message": "Serveur ADB démarré"
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": str(e)
        }, status_code=500)

@app.post("/adb/server/stop")
async def route_arreter_serveur_adb():
    try:
        # Logique d'arrêt du serveur ADB
        return JSONResponse(content={
            "status": "success", 
            "message": "Serveur ADB arrêté"
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": str(e)
        }, status_code=500)

@app.get("/test")
async def route_test():
    """
    Route de test pour vérifier le fonctionnement du serveur
    
    Returns:
        dict: Message de test
    """
    return JSONResponse(content={"status": "OK", "message": "Serveur en ligne"}, status_code=200)

@app.get("/system-info", response_class=JSONResponse)
async def infos_systeme():
    """
    Récupère les informations détaillées du système Android
    
    Returns:
        JSONResponse avec les informations système
    """
    try:
        resultat_systeme = AdbServices.Systeme.infos_systeme()
        return resultat_systeme
    except Exception as e:
        return {
            "statut": "Erreur", 
            "message": f"Impossible de récupérer les informations système : {str(e)}"
        }

@app.get("/performances")
async def infos_performances():
    """
    Récupère les informations de performances du système Android
    
    Returns:
        Dict avec les informations de performances
    """
    try:
        resultat_performances = AdbServices.Systeme.performances()
        return resultat_performances
    except Exception as e:
        return {
            "statut": "Erreur", 
            "message": f"Impossible de récupérer les informations de performances : {str(e)}"
        }

@app.get("/system/battery-details")
async def infos_batterie_detaillees():
    """
    Récupère des informations détaillées sur la batterie du périphérique Android
    
    Returns:
        Dict avec les informations de batterie complètes
    """
    try:
        print("Début de la récupération des informations de batterie")
        resultat_batterie = AdbServices.Systeme.informations_batterie_detaillees()
        print(f"Résultat batterie : {resultat_batterie}")
        return resultat_batterie
    except Exception as e:
        print(f"Erreur lors de la récupération des informations de batterie : {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "statut": "Erreur", 
                "message": f"Impossible de récupérer les informations de batterie : {str(e)}"
            }
        )

@app.get("/system/battery")
async def route_infos_batterie():
    """
    Route pour obtenir les informations de batterie
    
    Returns:
        JSONResponse avec les informations de batterie
    """
    try:
        resultat_batterie = AdbServices.Systeme.informations_batterie_detaillees()
        return resultat_batterie
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "statut": "Erreur", 
                "message": f"Impossible de récupérer les informations de batterie : {str(e)}"
            }
        )

@app.get("/system/network")
async def route_infos_reseau():
    """
    Route pour obtenir les informations réseau détaillées
    
    Returns:
        JSONResponse avec les informations réseau
    """
    try:
        resultat_reseau = AdbServices.Systeme.informations_reseau_detaillees()
        return resultat_reseau
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "statut": "Erreur", 
                "message": f"Impossible de récupérer les informations réseau : {str(e)}"
            }
        )

@app.get("/api/dashboard-data", response_model=dict)
async def get_dashboard_data():
    """
    Route API pour récupérer dynamiquement les données du dashboard
    
    Returns:
        dict: Données de performances, système et batterie
    """
    try:
        # Log de débogage
        logging.info("Début de la récupération des données du dashboard")
        
        # Vérifier la connexion ADB
        peripheriques = []
        try:
            peripheriques = AdbServices.lister_peripheriques()
        except Exception as adb_error:
            logging.warning(f"Erreur lors de la récupération des périphériques ADB : {adb_error}")
        
        if not peripheriques:
            logging.warning("Aucun périphérique ADB connecté")
            return {
                "utilisation_cpu": 0,
                "utilisation_memoire": 0,
                "version_android": 'Aucun appareil connecté',
                "niveau_batterie": 0
            }
        
        # Récupérer les données de performances
        performances = AdbServices.infos_performances()
        logging.info(f"Données de performances : {performances}")
        
        # Récupérer les informations système
        systeme = AdbServices.infos_systeme()
        logging.info(f"Informations système : {systeme}")
        
        # Récupérer les informations de batterie
        batterie = AdbServices.infos_batterie()
        logging.info(f"Informations batterie : {batterie}")
        
        # Préparer les données de réponse
        dashboard_data = {
            "utilisation_cpu": int(performances.get('cpu_usage', 0)),
            "utilisation_memoire": performances.get('memory_usage', 0),
            "version_android": systeme.get('android_version', 'N/A'),
            "niveau_batterie": batterie.get('niveau', 0)
        }
        
        logging.info(f"Données du dashboard : {dashboard_data}")
        
        return dashboard_data
    except Exception as e:
        logging.error(f"Erreur lors de la récupération des données du dashboard : {e}")
        logging.error(traceback.format_exc())
        
        return {
            "utilisation_cpu": 0,
            "utilisation_memoire": 0,
            "version_android": 'Erreur',
            "niveau_batterie": 0,
            "erreur": str(e)
        }

@app.get("/main", response_class=HTMLResponse)
async def main_page(request: Request):
    logger.info("Début du rendu de la page principale")
    try:
        return templates.TemplateResponse("main.html", {
            "request": request,
            "titre_page": "Tableau de Bord Principal"
        })
    except Exception as e:
        logger.error(f"Erreur lors du rendu de main.html : {e}")
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")

# Afficher toutes les routes disponibles
print("Routes disponibles :")
for route in app.routes:
    try:
        print(f"Route: {route.path}")
    except Exception as e:
        print(f"Erreur lors de l'affichage d'une route : {e}")

# Gestionnaire personnalisé pour les erreurs 404
@app.exception_handler(404)
async def page_non_trouvee(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=404,
        content={
            "status": "error",
            "code": 404,
            "message": "Ressource non trouvée",
            "path": str(request.url.path)
        }
    )

@app.exception_handler(404)
async def page_non_trouvee_json(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=404,
        content={
            "status": "error",
            "code": 404,
            "message": "Ressource non trouvée",
            "path": str(request.url.path)
        }
    )

@app.exception_handler(500)
async def erreur_serveur_json(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "code": 500,
            "message": "Erreur interne du serveur",
            "details": str(exc.detail) if hasattr(exc, 'detail') else "Erreur non spécifiée"
        }
    )

@app.exception_handler(401)
async def non_autorise_json(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=401,
        content={
            "status": "error",
            "code": 401,
            "message": "Non autorisé",
            "details": str(exc.detail) if hasattr(exc, 'detail') else "Accès refusé"
        }
    )

@app.exception_handler(403)
async def interdit_json(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=403,
        content={
            "status": "error",
            "code": 403,
            "message": "Accès interdit",
            "details": str(exc.detail) if hasattr(exc, 'detail') else "Vous n'avez pas les permissions nécessaires"
        }
    )

@app.get("/ip")
async def ip_wifi():
    ip = AdbServices.ip_wifi()
    return JSONResponse(content={"ip_wifi": ip}, status_code=200)

@app.get("/network")
async def infos_reseau():
    infos = AdbServices.infos_reseau()
    return JSONResponse(content={"infos_reseau": infos}, status_code=200)

@app.get("/network/test")
async def test_connexion_wifi():
    resultat = AdbServices.test_connexion_wifi()
    return JSONResponse(content={"test_connexion": resultat}, status_code=200)

@app.get("/network/details")
async def infos_reseau_detaillees():
    infos = AdbServices.infos_reseau_detaillees()
    return JSONResponse(content={"infos_reseau_detaillees": infos}, status_code=200)

@app.get("/apps")
async def lister_applications():
    apps = AdbServices.lister_applications()
    return JSONResponse(content={"applications": apps}, status_code=200)

@app.get("/battery/details")
async def infos_batterie_detaillees():
    infos = AdbServices.infos_batterie_detaillees()
    return JSONResponse(content={"batterie_details": infos}, status_code=200)

@app.get("/performance")
async def infos_performances():
    performances = AdbServices.infos_performances()
    return JSONResponse(content={"performances": performances}, status_code=200)

@app.get("/system/details")
async def infos_systeme_detaillees():
    infos = AdbServices.infos_systeme()
    return JSONResponse(content={"systeme_details": infos}, status_code=200)

@app.get("/wifi/details")
async def infos_wifi_detaillees():
    infos = AdbServices.infos_wifi_detaillees()
    return JSONResponse(content={"wifi_details": infos}, status_code=200)

@app.get("/network/connectivity")
async def test_connexion_reseau():
    resultats = AdbServices.test_connexion_reseau()
    return JSONResponse(content={"test_connexion_reseau": resultats}, status_code=200)

@app.post("/device/connect")
async def route_connecter_peripherique(
    adresse_ip: str = Form(...), 
    port: int = Form(5555)
):
    try:
        resultat = AdbServices.connecter_peripherique(adresse_ip, port)
        return JSONResponse(content={
            "status": "success", 
            "message": "Périphérique connecté", 
            "adresse_ip": adresse_ip,
            "port": port,
            "details": resultat
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Échec de la connexion au périphérique",
            "details": str(e)
        }, status_code=400)

@app.post("/device/restart")
async def route_redemarrer_peripherique():
    try:
        resultat = AdbServices.redemarrer_peripherique()
        return JSONResponse(content={
            "status": "success", 
            "message": "Périphérique redémarré",
            "details": resultat
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Échec du redémarrage du périphérique",
            "details": str(e)
        }, status_code=500)

@app.get("/device/ip/configure")
async def route_configuration_ip(request: Request):
    try:
        configurations_ip = AdbServices.recuperer_configurations_ip()
        return JSONResponse(content={
            "status": "success", 
            "message": "Configurations IP récupérées",
            "configurations": configurations_ip
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Impossible de récupérer les configurations IP",
            "details": str(e)
        }, status_code=500)

@app.post("/device/ip/configure")
async def route_configurer_ip(
    nouvelle_ip: str = Form(...),
    masque_reseau: str = Form(...),
    passerelle: str = Form(...)
):
    try:
        resultat = AdbServices.configurer_ip(
            nouvelle_ip, 
            masque_reseau, 
            passerelle
        )
        return JSONResponse(content={
            "status": "success", 
            "message": "Configuration IP mise à jour",
            "nouvelle_ip": nouvelle_ip,
            "masque_reseau": masque_reseau,
            "passerelle": passerelle,
            "details": resultat
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Échec de la configuration IP",
            "details": str(e)
        }, status_code=400)

@app.get("/device/list")
async def route_lister_peripheriques_disponibles():
    try:
        peripheriques = AdbServices.lister_peripheriques_disponibles()
        return JSONResponse(content={
            "status": "success", 
            "message": "Périphériques disponibles récupérés",
            "peripheriques": peripheriques,
            "nombre_peripheriques": len(peripheriques)
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Impossible de lister les périphériques",
            "details": str(e)
        }, status_code=500)

@app.post("/app/install")
async def route_installer_application(
    fichier_apk: UploadFile = File(...)
):
    try:
        # Sauvegarde temporaire du fichier APK
        chemin_temporaire = f"/tmp/{fichier_apk.filename}"
        with open(chemin_temporaire, "wb") as buffer:
            buffer.write(await fichier_apk.read())
        
        # Installation de l'application
        resultat = AdbServices.installer_application(chemin_temporaire)
        
        # Suppression du fichier temporaire
        os.unlink(chemin_temporaire)
        
        return JSONResponse(content={
            "status": "success", 
            "message": "Application installée avec succès",
            "nom_application": fichier_apk.filename,
            "details": resultat
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Échec de l'installation de l'application",
            "details": str(e)
        }, status_code=400)

@app.post("/app/uninstall")
async def route_desinstaller_application(
    nom_package: str = Form(...)
):
    try:
        resultat = AdbServices.desinstaller_application(nom_package)
        return JSONResponse(content={
            "status": "success", 
            "message": "Application désinstallée avec succès",
            "nom_package": nom_package,
            "details": resultat
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Échec de la désinstallation de l'application",
            "details": str(e)
        }, status_code=400)

@app.get("/app/list")
async def route_lister_applications_installees():
    try:
        applications = AdbServices.lister_applications_installees()
        return JSONResponse(content={
            "status": "success", 
            "message": "Liste des applications récupérée",
            "applications": applications,
            "nombre_applications": len(applications)
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Impossible de lister les applications",
            "details": str(e)
        }, status_code=500)

@app.get("/app/details/{nom_package}")
async def route_details_application(nom_package: str):
    try:
        details = AdbServices.obtenir_details_application(nom_package)
        return JSONResponse(content={
            "status": "success", 
            "message": "Détails de l'application récupérés",
            "nom_package": nom_package,
            "details": details
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Impossible de récupérer les détails de l'application",
            "details": str(e)
        }, status_code=404)

@app.get("/files/list")
async def route_lister_fichiers(
    chemin: str = "/sdcard", 
    recursif: bool = False
):
    try:
        fichiers = AdbServices.lister_fichiers(chemin, recursif)
        return JSONResponse(content={
            "status": "success", 
            "message": "Liste des fichiers récupérée",
            "chemin": chemin,
            "recursif": recursif,
            "fichiers": fichiers,
            "nombre_fichiers": len(fichiers)
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Impossible de lister les fichiers",
            "details": str(e),
            "chemin": chemin
        }, status_code=500)

@app.post("/files/upload")
async def route_upload_fichier(
    fichier: UploadFile = File(...),
    destination: str = Form("/sdcard/")
):
    try:
        # Sauvegarde temporaire du fichier
        chemin_temporaire = f"/tmp/{fichier.filename}"
        with open(chemin_temporaire, "wb") as buffer:
            buffer.write(await fichier.read())
        
        # Upload du fichier vers le périphérique
        resultat = AdbServices.upload_fichier(
            chemin_local=chemin_temporaire, 
            chemin_distant=f"{destination}/{fichier.filename}"
        )
        
        # Suppression du fichier temporaire
        os.unlink(chemin_temporaire)
        
        return JSONResponse(content={
            "status": "success", 
            "message": "Fichier uploadé avec succès",
            "nom_fichier": fichier.filename,
            "destination": destination,
            "details": resultat
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Échec de l'upload du fichier",
            "details": str(e)
        }, status_code=400)

@app.post("/files/download")
async def route_telecharger_fichier(
    chemin_distant: str = Form(...),
    destination_locale: str = Form("/tmp")
):
    try:
        resultat = AdbServices.telecharger_fichier(
            chemin_distant=chemin_distant, 
            destination_locale=destination_locale
        )
        
        return JSONResponse(content={
            "status": "success", 
            "message": "Fichier téléchargé avec succès",
            "chemin_distant": chemin_distant,
            "destination_locale": destination_locale,
            "details": resultat
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Échec du téléchargement du fichier",
            "details": str(e)
        }, status_code=400)

@app.delete("/files/delete")
async def route_supprimer_fichier(
    chemin: str = Form(...)
):
    try:
        resultat = AdbServices.supprimer_fichier(chemin)
        return JSONResponse(content={
            "status": "success", 
            "message": "Fichier supprimé avec succès",
            "chemin": chemin,
            "details": resultat
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Échec de la suppression du fichier",
            "details": str(e)
        }, status_code=400)

@app.get("/files/info")
async def route_informations_fichier(
    chemin: str = "/sdcard"
):
    try:
        infos = AdbServices.obtenir_informations_fichier(chemin)
        return JSONResponse(content={
            "status": "success", 
            "message": "Informations du fichier récupérées",
            "chemin": chemin,
            "informations": infos
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Impossible de récupérer les informations du fichier",
            "details": str(e),
            "chemin": chemin
        }, status_code=404)

@app.post("/files/mkdir")
async def route_creer_repertoire(
    chemin: str = Form(...)
):
    try:
        resultat = AdbServices.creer_repertoire(chemin)
        return JSONResponse(content={
            "status": "success", 
            "message": "Répertoire créé avec succès",
            "chemin": chemin,
            "details": resultat
        }, status_code=201)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Échec de la création du répertoire",
            "details": str(e)
        }, status_code=400)

@app.get("/logs/system")
async def route_logs_systeme(
    lignes: int = 100, 
    niveau: str = "INFO"
):
    try:
        logs = AdbServices.recuperer_logs_systeme(
            nombre_lignes=lignes, 
            niveau_log=niveau
        )
        return JSONResponse(content={
            "status": "success", 
            "message": "Logs système récupérés",
            "nombre_lignes": lignes,
            "niveau_log": niveau,
            "logs": logs
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Impossible de récupérer les logs système",
            "details": str(e)
        }, status_code=500)

@app.get("/logs/application")
async def route_logs_application(
    nom_package: str,
    lignes: int = 100
):
    try:
        logs = AdbServices.recuperer_logs_application(
            package=nom_package, 
            nombre_lignes=lignes
        )
        return JSONResponse(content={
            "status": "success", 
            "message": "Logs de l'application récupérés",
            "nom_package": nom_package,
            "nombre_lignes": lignes,
            "logs": logs
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Impossible de récupérer les logs de l'application",
            "details": str(e)
        }, status_code=404)

@app.post("/debug/capture")
async def route_capture_debug(
    type_capture: str = Form("screenshot"),
    options: Optional[str] = Form(None)
):
    try:
        resultat = AdbServices.capturer_informations_debug(
            type_capture=type_capture,
            options=options
        )
        return JSONResponse(content={
            "status": "success", 
            "message": "Capture de débogage effectuée",
            "type_capture": type_capture,
            "details": resultat
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Échec de la capture de débogage",
            "details": str(e)
        }, status_code=500)

@app.get("/debug/diagnostics")
async def route_diagnostics_systeme():
    try:
        diagnostics = AdbServices.generer_diagnostics_systeme()
        return JSONResponse(content={
            "status": "success", 
            "message": "Diagnostics système générés",
            "diagnostics": diagnostics
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Impossible de générer les diagnostics système",
            "details": str(e)
        }, status_code=500)

@app.get("/config/list")
async def route_lister_configurations():
    try:
        configurations = AdbServices.lister_configurations_systeme()
        return JSONResponse(content={
            "status": "success", 
            "message": "Configurations système récupérées",
            "configurations": configurations
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Impossible de récupérer les configurations",
            "details": str(e)
        }, status_code=500)

@app.get("/config/get")
async def route_obtenir_configuration(
    cle_configuration: str
):
    try:
        valeur = AdbServices.obtenir_configuration(cle_configuration)
        return JSONResponse(content={
            "status": "success", 
            "message": "Configuration récupérée",
            "cle": cle_configuration,
            "valeur": valeur
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Impossible de récupérer la configuration",
            "details": str(e),
            "cle": cle_configuration
        }, status_code=404)

@app.post("/config/set")
async def route_definir_configuration(
    cle_configuration: str = Form(...),
    valeur: str = Form(...)
):
    try:
        resultat = AdbServices.definir_configuration(
            cle_configuration, 
            valeur
        )
        return JSONResponse(content={
            "status": "success", 
            "message": "Configuration mise à jour",
            "cle": cle_configuration,
            "valeur": valeur,
            "details": resultat
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Impossible de définir la configuration",
            "details": str(e)
        }, status_code=400)

@app.get("/settings/wifi")
async def route_parametres_wifi():
    try:
        parametres = AdbServices.recuperer_parametres_wifi()
        return JSONResponse(content={
            "status": "success", 
            "message": "Paramètres WiFi récupérés",
            "parametres": parametres
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Impossible de récupérer les paramètres WiFi",
            "details": str(e)
        }, status_code=500)

@app.post("/settings/wifi/connect")
async def route_connexion_wifi(
    ssid: str = Form(...),
    mot_de_passe: str = Form(...)
):
    try:
        resultat = AdbServices.connecter_wifi(
            ssid=ssid, 
            mot_de_passe=mot_de_passe
        )
        return JSONResponse(content={
            "status": "success", 
            "message": "Connexion WiFi établie",
            "ssid": ssid,
            "details": resultat
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Échec de la connexion WiFi",
            "details": str(e)
        }, status_code=400)

@app.get("/settings/bluetooth")
async def route_parametres_bluetooth():
    try:
        parametres = AdbServices.recuperer_parametres_bluetooth()
        return JSONResponse(content={
            "status": "success", 
            "message": "Paramètres Bluetooth récupérés",
            "parametres": parametres
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Impossible de récupérer les paramètres Bluetooth",
            "details": str(e)
        }, status_code=500)

@app.post("/settings/bluetooth/toggle")
async def route_activer_bluetooth(
    activer: bool = Form(...)
):
    try:
        resultat = AdbServices.activer_bluetooth(activer)
        return JSONResponse(content={
            "status": "success", 
            "message": f"Bluetooth {'activé' if activer else 'désactivé'}",
            "etat": activer,
            "details": resultat
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Impossible de modifier l'état du Bluetooth",
            "details": str(e)
        }, status_code=400)

@app.get("/settings/mode-avion")
async def route_mode_avion():
    try:
        etat = AdbServices.verifier_mode_avion()
        return JSONResponse(content={
            "status": "success", 
            "message": "État du mode avion récupéré",
            "mode_avion_actif": etat
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Impossible de vérifier le mode avion",
            "details": str(e)
        }, status_code=500)

@app.post("/settings/mode-avion/toggle")
async def route_activer_mode_avion(
    activer: bool = Form(...)
):
    try:
        resultat = AdbServices.definir_mode_avion(activer)
        return JSONResponse(content={
            "status": "success", 
            "message": f"Mode avion {'activé' if activer else 'désactivé'}",
            "etat": activer,
            "details": resultat
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error", 
            "message": "Impossible de modifier le mode avion",
            "details": str(e)
        }, status_code=400)
