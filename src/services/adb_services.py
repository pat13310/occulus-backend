import subprocess
import shutil
import os
import signal
import sys
import re
import logging

logger = logging.getLogger(__name__)

try:
    import psutil
    PSUTIL_DISPONIBLE = True
except ImportError:
    PSUTIL_DISPONIBLE = False

from typing import List, Dict, Any
from enum import Enum, auto
import traceback

class AdbServiceCategory(Enum):
    PERIPHERIQUE = auto()
    RESEAU = auto()
    SYSTEME = auto()
    APPLICATION = auto()
    FICHIERS = auto()

class AdbServices:
    _serveur_process = None

    @staticmethod
    def _verifier_adb_disponible() -> bool:
        """
        Vérifie si la commande ADB est disponible
        
        Returns:
            bool: True si ADB est disponible, False sinon
        """
        return shutil.which("adb") is not None

    @staticmethod
    def _execute_adb_command(command: List[str], gerer_erreurs: bool = True) -> str:
        """
        Exécute une commande ADB et retourne sa sortie
        
        Args:
            command (List[str]): Commande ADB à exécuter
            gerer_erreurs (bool, optional): Gère les erreurs. Défaut à True.
        
        Returns:
            str: Sortie de la commande
        
        Raises:
            RuntimeError: Si ADB n'est pas disponible ou aucun périphérique connecté
        """
        if not AdbServices._verifier_adb_disponible():
            raise RuntimeError("ADB n'est pas installé ou n'est pas dans le chemin système")

        try:
            result = subprocess.run(
                ["adb"] + command, 
                capture_output=True, 
                text=True, 
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            if gerer_erreurs:
                return f"Erreur : {e.stderr}"
            raise RuntimeError(f"Échec de l'exécution de la commande ADB : {e.stderr}")

    @staticmethod
    def lister_peripheriques():
        """
        Liste les périphériques Android connectés via ADB
        
        Returns:
            list: Liste des identifiants des périphériques connectés
        """
        try:
            # Exécuter la commande ADB pour lister les périphériques
            resultat = subprocess.run(
                ["adb", "devices"], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            
            # Analyser la sortie pour extraire les identifiants des périphériques
            lignes = resultat.stdout.strip().split('\n')[1:]
            peripheriques = [
                ligne.split()[0] 
                for ligne in lignes 
                if ligne.strip() and 'device' in ligne
            ]
            
            logger.info(f"Périphériques ADB détectés : {peripheriques}")
            return peripheriques
        
        except subprocess.TimeoutExpired:
            logger.warning("Délai d'attente dépassé lors de la recherche de périphériques ADB")
            return []
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des périphériques ADB : {e}")
            return []

    class Peripheriques:
        @staticmethod
        def lister_peripheriques():
            """
            Liste les périphériques Android connectés via ADB
            
            Returns:
                list: Liste des identifiants des périphériques connectés
            """
            try:
                # Exécuter la commande ADB pour lister les périphériques
                resultat = subprocess.run(
                    ["adb", "devices"], 
                    capture_output=True, 
                    text=True, 
                    timeout=5
                )
                
                # Analyser la sortie pour extraire les identifiants des périphériques
                lignes = resultat.stdout.strip().split('\n')[1:]
                peripheriques = [
                    ligne.split()[0] 
                    for ligne in lignes 
                    if ligne.strip() and 'device' in ligne
                ]
                
                logger.info(f"Périphériques ADB détectés : {peripheriques}")
                return peripheriques
            
            except subprocess.TimeoutExpired:
                logger.warning("Délai d'attente dépassé lors de la recherche de périphériques ADB")
                return []
            except Exception as e:
                logger.error(f"Erreur lors de la récupération des périphériques ADB : {e}")
                return []

      
        @classmethod
        def connecter_peripherique(cls, adresse_ip, port=5555):
            """
            Connecte un périphérique Android via ADB
            
            Args:
                adresse_ip (str): Adresse IP du périphérique
                port (int, optional): Port de connexion. Défaut à 5555.
            
            Returns:
                dict: Résultat de la connexion avec statut et message
            """
            try:
                # Vérification des paramètres d'entrée
                if not adresse_ip:
                    return {
                        "statut": "Erreur",
                        "message": "Adresse IP manquante",
                        "details": "L'adresse IP est requise pour établir une connexion"
                    }
                
                # Commande de connexion ADB
                commande = f"adb connect {adresse_ip}:{port}"
                
                # Exécution de la commande
                resultat = subprocess.run(
                    commande, 
                    shell=True, 
                    capture_output=True, 
                    text=True, 
                    encoding='utf-8',
                    errors='replace'
                )
                
                # Analyse du résultat
                output = resultat.stdout.strip()
                
                # Gestion des différents cas de connexion
                if "connected to" in output.lower():
                    return {
                        "statut": "Succès",
                        "message": "Connexion établie",
                        "details": output
                    }
                elif "already connected" in output.lower():
                    return {
                        "statut": "Déjà connecté",
                        "message": "Périphérique déjà connecté",
                        "details": output
                    }
                else:
                    return {
                        "statut": "Erreur",
                        "message": "Échec de connexion",
                        "details": output or resultat.stderr.strip()
                    }
            
            except Exception as e:
                return {
                    "statut": "Erreur système",
                    "message": "Impossible de se connecter",
                    "details": str(e)
                }

        @staticmethod
        def infos_peripherique(serial: str = None) -> Dict[str, str]:
            """
            Récupère les informations d'un périphérique
            
            Args:
                serial (str, optional): Numéro de série du périphérique
            
            Returns:
                Dict[str, str]: Informations du périphérique
            """
            try:
                cmd = ["shell", "getprop"] if serial is None else ["-s", serial, "shell", "getprop"]
                props_raw = AdbServices._execute_adb_command(cmd)
                
                props = {}
                for ligne in props_raw.split("\n"):
                    if ": " in ligne:
                        cle, valeur = ligne.split(": ", 1)
                        props[cle.strip('[]')] = valeur.strip('[]')
                
                return props if props else {"statut": "Aucune information disponible pour le périphérique"}
            except Exception as e:
                return {"erreur": f"Impossible de récupérer les informations du périphérique : {str(e)}"}

    class Reseau:
        @classmethod
        def _execute_adb_command(cls, commande: List[str]) -> str:
            """
            Exécute une commande ADB
            
            Args:
                commande (List[str]): Commande à exécuter
            
            Returns:
                str: Résultat de la commande
            """
            return AdbServices._execute_adb_command(commande)

        @staticmethod
        def ip_wifi() -> str:
            """
            Récupère l'adresse IP du périphérique en WiFi
            
            Returns:
                str: Adresse IP WiFi
            """
            try:
                return AdbServices._execute_adb_command(["shell", "ip", "addr", "show", "wlan0"])
            except Exception:
                return "Impossible de récupérer l'adresse IP du périphérique"

        @staticmethod
        def ping(host: str, count: int = 4) -> str:
            """
            Effectue un ping vers un hôte
            
            Args:
                host (str): Hôte à ping
                count (int, optional): Nombre de paquets. Défaut à 4.
            
            Returns:
                str: Résultat du ping
            """
            try:
                return AdbServices._execute_adb_command(["shell", "ping", "-c", str(count), host])
            except Exception as e:
                return f"Échec du ping : {str(e)}"

        @classmethod
        def informations_reseau(cls) -> Dict[str, Any]:
            """
            Récupère les informations réseau du périphérique Android
            
            Returns:
                Dict[str, Any]: Informations détaillées sur le réseau
            """
            try:
                # Récupérer l'adresse IP WiFi
                ip_wifi_cmd = ["shell", "ip", "addr", "show", "wlan0"]
                ip_wifi = cls._execute_adb_command(ip_wifi_cmd)
                ip_address = "N/A"
                wifi_status = "Déconnecté"
                
                # Commande alternative pour l'IP
                if not ip_wifi or "N/A" in str(ip_wifi):
                    ip_wifi_alt = cls._execute_adb_command(["shell", "ifconfig", "wlan0"])
                    if ip_wifi_alt and "inet " in str(ip_wifi_alt):
                        ip_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", str(ip_wifi_alt))
                        if ip_match:
                            ip_address = ip_match.group(1)
                            wifi_status = "Connecté"
                else:
                    # Extraire l'adresse IP de la sortie originale
                    ip_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", str(ip_wifi))
                    if ip_match:
                        ip_address = ip_match.group(1)
                        wifi_status = "Connecté"
                
                # Récupérer le nom du réseau WiFi
                ssid_cmd = ["shell", "dumpsys", "wifi", "|", "grep", "SSID"]
                ssid = cls._execute_adb_command(ssid_cmd)
                reseau_wifi = "Inconnu"
                
                if ssid and "SSID:" in str(ssid):
                    try:
                        reseau_wifi = str(ssid).split("SSID:")[1].split(",")[0].strip()
                    except:
                        pass
                
                # Vérifier la connectivité
                ping_cmd = ["shell", "ping", "-c", "1", "8.8.8.8"]
                ping_result = cls._execute_adb_command(ping_cmd)
                connexion_internet = "Non connecté"
                
                if ping_result and "0% packet loss" in str(ping_result):
                    connexion_internet = "Connecté"
                
                return {
                    "statut": "Succès",
                    "donnees": {
                        "adresse_ip": ip_address,
                        "statut_wifi": wifi_status,
                        "reseau_wifi": reseau_wifi,
                        "connexion_internet": connexion_internet
                    }
                }
            
            except Exception as e:
                return {
                    "statut": "Erreur",
                    "message": f"Impossible de récupérer les informations réseau : {str(e)}",
                    "details": str(e)
                }

        @classmethod
        def tester_connexion_wifi(cls) -> Dict[str, Any]:
            """
            Teste la connexion WiFi du périphérique
            
            Returns:
                Dict[str, Any]: Résultat du test de connexion
            """
            try:
                # Ping de google.com
                ping_google = cls._execute_adb_command(["shell", "ping", "-c", "4", "google.com"])
                
                if ping_google:
                    # Analyse générique des résultats de ping
                    ping_match = re.search(r"(\d+) packets transmitted, (\d+) received, (\d+)% packet loss", str(ping_google))
                    if ping_match:
                        return {
                            "statut": "Succès",
                            "connectivite": "Connecté à Internet",
                            "details": {
                                'paquets_envoyes': ping_match.group(1),
                                'paquets_recus': ping_match.group(2),
                                'perte_paquets': f"{ping_match.group(3)}%",
                                'statut': 'Succès' if int(ping_match.group(3)) == 0 else 'Partiel'
                            }
                        }
                    else:
                        return {
                            "statut": "Avertissement",
                            "connectivite": "Connectivité limitée",
                            "details": ping_google
                        }
            
            except Exception as e:
                return {
                    "statut": "Erreur",
                    "message": f"Échec du test de connexion : {str(e)}",
                    "details": str(e)
                }

        @classmethod
        def informations_reseau_detaillees(cls) -> Dict[str, Any]:
            """
            Récupère des informations réseau détaillées du périphérique Android
            
            Returns:
                Dict[str, Any]: Informations complètes sur le réseau
            """
            try:
                # Informations WiFi
                wifi_details = {}
                wifi_info_cmd = ["shell", "dumpsys", "wifi"]
                wifi_info = cls._execute_adb_command(wifi_info_cmd)
                
                if wifi_info:
                    # Extraire les informations détaillées du WiFi
                    wifi_sections = {
                        "SSID": r"mWifiInfo.*?SSID: (.*?)[,\n]",
                        "Adresse MAC": r"mWifiInfo.*?MAC: (.*?)[,\n]",
                        "Force du signal": r"mWifiInfo.*?rssi=(-?\d+)",
                        "Vitesse de connexion": r"mWifiInfo.*?link speed (\d+) Mbps",
                        "Fréquence": r"mWifiInfo.*?frequency (\d+) MHz"
                    }
                    
                    for cle, motif in wifi_sections.items():
                        match = re.search(motif, wifi_info, re.DOTALL)
                        if match:
                            wifi_details[cle] = match.group(1).strip()
                
                # Informations réseau IP
                ip_details = {}
                ip_info_cmd = ["shell", "ip", "addr"]
                ip_info = cls._execute_adb_command(ip_info_cmd)
                
                if ip_info:
                    # Interfaces réseau
                    interfaces = re.findall(r"^\d+:\s+(\w+).*?inet\s+(\d+\.\d+\.\d+\.\d+).*?scope\s+(\w+)", 
                                            str(ip_info), re.MULTILINE | re.DOTALL)
                    ip_details['interfaces'] = [
                        {
                            'nom': interface[0], 
                            'adresse_ip': interface[1], 
                            'portee': interface[2]
                        } for interface in interfaces
                    ]
                
                # Informations de connexion
                connexion_details = {}
                
                # Test de connexion Internet
                ping_google = cls._execute_adb_command(["shell", "ping", "-c", "4", "8.8.8.8"])
                ping_details = {}
                if ping_google:
                    ping_match = re.search(r"(\d+) packets transmitted, (\d+) received, (\d+)% packet loss", str(ping_google))
                    if ping_match:
                        ping_details = {
                            'paquets_envoyes': ping_match.group(1),
                            'paquets_recus': ping_match.group(2),
                            'perte_paquets': f"{ping_match.group(3)}%",
                            'statut': 'Succès' if int(ping_match.group(3)) == 0 else 'Partiel'
                        }
                
                # Informations DNS
                dns_cmd = ["shell", "getprop", "net.dns1"]
                dns_serveur = cls._execute_adb_command(dns_cmd)
                
                # Informations de routage
                route_cmd = ["shell", "ip", "route"]
                route_info = cls._execute_adb_command(route_cmd)
                routes = []
                if route_info:
                    route_matches = re.findall(r"default via (\d+\.\d+\.\d+\.\d+) dev (\w+)", str(route_info))
                    routes = [
                        {
                            'passerelle': route[0], 
                            'interface': route[1]
                        } for route in route_matches
                    ]
                
                # Réseau mobile (si disponible)
                mobile_info_cmd = ["shell", "dumpsys", "telephony.registry"]
                mobile_info = cls._execute_adb_command(mobile_info_cmd)
                mobile_details = {}
                if mobile_info:
                    mobile_sections = {
                        "Opérateur": r"mOperatorAlphaLong=(.*?)[,\n]",
                        "Type de réseau": r"mDataNetworkType=(\w+)",
                        "Statut de la connexion": r"mDataConnectionState=(\d+)"
                    }
                    
                    for cle, motif in mobile_sections.items():
                        match = re.search(motif, mobile_info, re.DOTALL)
                        if match:
                            mobile_details[cle] = match.group(1).strip()
                
                return {
                    "statut": "Succès",
                    "donnees": {
                        "wifi": wifi_details,
                        "ip": ip_details,
                        "connexion": {
                            "ping": ping_details,
                            "dns": dns_serveur.strip() if dns_serveur else "N/A",
                            "routes": routes
                        },
                        "mobile": mobile_details
                    }
                }
            
            except Exception as e:
                return {
                    "statut": "Erreur",
                    "message": f"Impossible de récupérer les informations réseau détaillées : {str(e)}",
                    "details": str(e)
                }

        @classmethod
        def tester_connexion_reseau(cls) -> Dict[str, Any]:
            """
            Test complet de la connectivité réseau
            
            Returns:
                Dict[str, Any]: Résultats détaillés des tests de connectivité
            """
            try:
                # Tests de connectivité
                tests = {
                    "google": cls._execute_adb_command(["shell", "ping", "-c", "4", "google.com"]),
                    "cloudflare": cls._execute_adb_command(["shell", "ping", "-c", "4", "1.1.1.1"]),
                    "dns_google": cls._execute_adb_command(["shell", "nslookup", "google.com", "8.8.8.8"]),
                    "traceroute": cls._execute_adb_command(["shell", "traceroute", "-n", "google.com"])
                }
                
                # Analyse des résultats
                resultats = {}
                for nom, resultat in tests.items():
                    if resultat:
                        # Analyse générique des résultats de ping
                        if nom in ["google", "cloudflare"]:
                            ping_match = re.search(r"(\d+) packets transmitted, (\d+) received, (\d+)% packet loss", str(resultat))
                            if ping_match:
                                resultats[nom] = {
                                    'paquets_envoyes': ping_match.group(1),
                                    'paquets_recus': ping_match.group(2),
                                    'perte_paquets': f"{ping_match.group(3)}%",
                                    'statut': 'Succès' if int(ping_match.group(3)) == 0 else 'Partiel'
                                }
                            else:
                                resultats[nom] = {'statut': 'Échec', 'details': resultat}
                        else:
                            resultats[nom] = {'statut': 'Succès', 'details': resultat}
                    else:
                        resultats[nom] = {'statut': 'Échec', 'details': 'Aucune réponse'}
                
                return {
                    "statut": "Succès",
                    "connectivite": resultats,
                    "resume": {
                        "internet_global": "Connecté" if all(test.get('statut') == 'Succès' for test in resultats.values()) else "Problèmes détectés"
                    }
                }
            
            except Exception as e:
                return {
                    "statut": "Erreur",
                    "message": f"Échec du test de connectivité : {str(e)}",
                    "details": str(e)
                }

        @classmethod
        def informations_wifi_detaillees(cls) -> Dict[str, Any]:
            """
            Récupère des informations WiFi détaillées et avancées
            
            Returns:
                Dict[str, Any]: Informations complètes sur le WiFi
            """
            try:
                # Commandes multiples pour obtenir des informations WiFi
                commandes_wifi = {
                    "dumpsys_wifi": ["shell", "dumpsys", "wifi"],
                    "wlan_info": ["shell", "cat", "/sys/class/net/wlan0/address"],
                    "iwconfig": ["shell", "iwconfig", "wlan0"],
                    "ip_link": ["shell", "ip", "link", "show", "wlan0"],
                    "iw_dev": ["shell", "iw", "dev", "wlan0", "info"]
                }
                
                # Dictionnaire pour stocker toutes les informations
                wifi_info: Dict[str, Any] = {
                    "statut": "En cours",
                    "donnees": {
                        "connexion": {},
                        "signal": {},
                        "securite": {},
                        "configuration": {}
                    }
                }
                
                # Exécuter chaque commande et collecter les informations
                for nom_commande, commande in commandes_wifi.items():
                    try:
                        resultat = cls._execute_adb_command(commande)
                        
                        if not resultat:
                            continue
                        
                        # Traitement spécifique selon la commande
                        if nom_commande == "dumpsys_wifi":
                            # Extraction des informations de base
                            wifi_sections = {
                                "SSID": r"mWifiInfo.*?SSID: (.*?)[,\n]",
                                "Adresse MAC": r"mWifiInfo.*?MAC: (.*?)[,\n]",
                                "Force du signal (RSSI)": r"mWifiInfo.*?rssi=(-?\d+)",
                                "Vitesse de connexion": r"mWifiInfo.*?link speed (\d+) Mbps",
                                "Fréquence": r"mWifiInfo.*?frequency (\d+) MHz",
                                "État de la connexion": r"mWifiInfo.*?supplicant state (\w+)",
                                "Niveau de sécurité": r"mWifiInfo.*?security type (\w+)"
                            }
                            
                            for cle, motif in wifi_sections.items():
                                match = re.search(motif, resultat, re.DOTALL | re.IGNORECASE)
                                if match:
                                    # Déterminer la section en fonction de la clé
                                    if cle in ["SSID", "Adresse MAC", "État de la connexion", "Niveau de sécurité"]:
                                        wifi_info["donnees"]["connexion"][cle] = match.group(1).strip()
                                    elif cle in ["Force du signal (RSSI)", "Vitesse de connexion", "Fréquence"]:
                                        wifi_info["donnees"]["signal"][cle] = match.group(1).strip()
                        
                        elif nom_commande == "wlan_info":
                            # Adresse MAC alternative
                            wifi_info["donnees"]["connexion"]["Adresse MAC (alt)"] = resultat.strip()
                        
                        elif nom_commande == "iwconfig":
                            # Informations supplémentaires de configuration
                            config_sections = {
                                "Mode": r"mode:(\w+)",
                                "Sensibilité du signal": r"Sensitivity=(\d+)",
                                "Niveau de bruit": r"Noise level=(-?\d+) dBm"
                            }
                            
                            for cle, motif in config_sections.items():
                                match = re.search(motif, resultat, re.IGNORECASE)
                                if match:
                                    wifi_info["donnees"]["configuration"][cle] = match.group(1).strip()
                        
                        elif nom_commande == "ip_link":
                            # État de l'interface
                            etat_match = re.search(r"state\s+(\w+)", resultat)
                            if etat_match:
                                wifi_info["donnees"]["connexion"]["État de l'interface"] = etat_match.group(1)
                        
                        elif nom_commande == "iw_dev":
                            # Informations avancées de sécurité
                            securite_sections = {
                                "Type de chiffrement": r"encryption:\s*(\w+)",
                                "Protocole d'authentification": r"auth types:\s*(.*?)\n"
                            }
                            
                            for cle, motif in securite_sections.items():
                                match = re.search(motif, resultat, re.DOTALL | re.IGNORECASE)
                                if match:
                                    wifi_info["donnees"]["securite"][cle] = match.group(1).strip()
            
                    except Exception as e:
                        print(f"Erreur lors du traitement de {nom_commande}: {str(e)}")
        
                # Calculs et interprétations supplémentaires
                if wifi_info["donnees"]["signal"].get("Force du signal (RSSI)"):
                    try:
                        rssi = int(wifi_info["donnees"]["signal"]["Force du signal (RSSI)"])
                        wifi_info["donnees"]["signal"]["Qualité du signal"] = (
                            "Excellent" if rssi >= -50 else
                            "Bon" if rssi >= -60 else
                            "Moyen" if rssi >= -70 else
                            "Faible" if rssi >= -80 else
                            "Très faible"
                        )
                    except (ValueError, TypeError) as e:
                        print(f"Erreur lors du calcul de la qualité du signal : {str(e)}")
        
                wifi_info["statut"] = "Succès"
                return wifi_info
    
            except Exception as e:
                return {
                    "statut": "Erreur",
                    "message": f"Impossible de récupérer les informations WiFi : {str(e)}",
                    "details": str(e)
                }

    class Systeme:
        @classmethod
        def _execute_adb_command(cls, commande: List[str]) -> str:
            """
            Exécute une commande ADB et retourne sa sortie
            
            Args:
                commande (List[str]): Liste des arguments de la commande ADB
            
            Returns:
                str: Sortie de la commande
            """
            return AdbServices._execute_adb_command(commande)

        @classmethod
        def version_android(cls) -> str:
            """
            Récupère la version d'Android
            
            Returns:
                str: Version d'Android
            """
            try:
                return AdbServices._execute_adb_command(["shell", "getprop", "ro.build.version.release"])
            except Exception:
                return "Version Android non disponible"

        @classmethod
        def redemarrer(cls) -> str:
            """
            Redémarre le périphérique
            
            Returns:
                str: Résultat du redémarrage
            """
            try:
                return AdbServices._execute_adb_command(["reboot"])
            except Exception as e:
                return f"Erreur lors du redémarrage : {str(e)}"

        @classmethod
        def batterie(cls) -> Dict[str, Any]:
            """
            Récupère les informations détaillées de la batterie
            
            Returns:
                Dict[str, Any]: Informations de la batterie
            """
            try:
                # Exécuter la commande complète dumpsys battery
                batterie_info_raw = AdbServices._execute_adb_command(["shell", "dumpsys", "battery"])
                
                # Initialiser un dictionnaire pour stocker les informations
                batterie_info = {}
                
                # Parser les lignes de la sortie
                for ligne in batterie_info_raw.split("\n"):
                    if ": " in ligne:
                        cle, valeur = ligne.split(":", 1)
                        batterie_info[cle.strip()] = valeur.strip()
                
                # Mapper les codes d'état de la batterie
                etats_batterie = {
                    "1": "Non chargé",
                    "2": "En charge",
                    "3": "Chargé",
                    "4": "Déchargement",
                    "5": "Non disponible"
                }
                
                # Extraire les informations
                niveau = int(batterie_info.get('level', 0))
                etat_code = batterie_info.get('status', '5')
                etat_libelle = etats_batterie.get(str(etat_code), "Inconnu")
                
                # Convertir la température (généralement en dixièmes de degré)
                temperature = float(batterie_info.get('temperature', 0)) / 10
                
                # Convertir la tension
                tension = int(batterie_info.get('voltage', 0))
                
                # Construire le dictionnaire de résultat
                resultat = {
                    "niveau": niveau,
                    "niveau_pourcentage": f"{niveau}%",
                    "etat_code": etat_code,
                    "etat_libelle": etat_libelle,
                    "temperature": temperature,
                    "temperature_formatee": f"{temperature}°C",
                    "tension": tension,
                    "tension_formatee": f"{tension} mV",
                    "details": {
                        "chargeur_ac": batterie_info.get('AC powered', 'N/A'),
                        "chargeur_usb": batterie_info.get('USB powered', 'N/A'),
                        "chargeur_sans_fil": batterie_info.get('Wireless powered', 'N/A'),
                        "technologie": batterie_info.get('technology', 'N/A')
                    }
                }
                
                return resultat
            
            except Exception as e:
                return {
                    "statut": "Erreur",
                    "message": f"Impossible de récupérer les informations de batterie : {str(e)}",
                    "details": str(e)
                }

        @classmethod
        def informations_batterie_detaillees(cls) -> Dict[str, Any]:
            """
            Récupère des informations détaillées sur la batterie du périphérique Android
            
            Returns:
                Dict[str, Any]: Informations complètes sur la batterie
            """
            try:
                # Commandes pour récupérer les informations de batterie
                commandes_batterie = {
                    "dumpsys_battery": ["shell", "dumpsys", "battery"],
                    "batteryinfo": ["shell", "dumpsys", "batterystats"],
                    "thermal_zone": ["shell", "cat", "/sys/class/thermal/thermal_zone0/temp"],
                    "battery_health": ["shell", "cat", "/sys/class/power_supply/battery/health"],
                    "battery_capacity": ["shell", "cat", "/sys/class/power_supply/battery/capacity"],
                    "battery_status": ["shell", "cat", "/sys/class/power_supply/battery/status"],
                    "battery_voltage": ["shell", "cat", "/sys/class/power_supply/battery/voltage_now"]
                }
                
                # Dictionnaire pour stocker toutes les informations
                batterie_info: Dict[str, Any] = {
                    "statut": "En cours",
                    "donnees": {
                        "etat_general": {},
                        "performance": {},
                        "temperature": {},
                        "historique_charge": {}
                    }
                }
                
                # Exécuter chaque commande et collecter les informations
                for nom_commande, commande in commandes_batterie.items():
                    try:
                        resultat = cls._execute_adb_command(commande)
                        
                        if not resultat:
                            continue
                        
                        # Traitement spécifique selon la commande
                        if nom_commande == "dumpsys_battery":
                            # Extraction des informations de base
                            sections_batterie = {
                                "Niveau de charge": r"level: (\d+)",
                                "Statut de charge": r"status: (\w+)",
                                "Santé de la batterie": r"health: (\w+)",
                                "Température": r"temperature: (\d+)",
                                "Tension": r"voltage: (\d+)",
                                "Technologie": r"technology: (\w+)"
                            }
                            
                            for cle, motif in sections_batterie.items():
                                match = re.search(motif, resultat, re.IGNORECASE)
                                if match:
                                    valeur = match.group(1)
                                    
                                    # Traitement spécifique pour certaines valeurs
                                    if cle == "Température":
                                        valeur = f"{float(valeur) / 10}°C"
                                    elif cle == "Tension":
                                        valeur = f"{float(valeur) / 1000} V"
                                    
                                    batterie_info["donnees"]["etat_general"][cle] = valeur
                        
                        elif nom_commande == "batteryinfo":
                            # Informations de performance et historique
                            historique_sections = {
                                "Temps depuis la dernière charge": r"Charge level .*? time=(\d+)",
                                "Cycles de charge": r"Charge cycles: (\d+)",
                                "Consommation moyenne": r"Computed drain: ([\d.]+)"
                            }
                            
                            for cle, motif in historique_sections.items():
                                match = re.search(motif, resultat, re.IGNORECASE)
                                if match:
                                    batterie_info["donnees"]["historique_charge"][cle] = match.group(1)
                        
                        elif nom_commande == "thermal_zone":
                            # Température du système
                            try:
                                temp_systeme = float(resultat.strip()) / 1000
                                batterie_info["donnees"]["temperature"]["Température du système"] = f"{temp_systeme}°C"
                            except (ValueError, TypeError):
                                pass
                        
                        elif nom_commande == "battery_health":
                            batterie_info["donnees"]["etat_general"]["État de santé"] = resultat.strip()
                        
                        elif nom_commande == "battery_capacity":
                            batterie_info["donnees"]["performance"]["Capacité actuelle"] = f"{resultat.strip()}%"
                        
                        elif nom_commande == "battery_status":
                            batterie_info["donnees"]["etat_general"]["Statut actuel"] = resultat.strip()
                        
                        elif nom_commande == "battery_voltage":
                            try:
                                tension = float(resultat.strip()) / 1_000_000
                                batterie_info["donnees"]["performance"]["Tension actuelle"] = f"{tension:.2f} V"
                            except (ValueError, TypeError):
                                pass
            
                    except Exception as e:
                        print(f"Erreur lors du traitement de {nom_commande}: {str(e)}")
        
                # Calculs et interprétations supplémentaires
                if batterie_info["donnees"]["etat_general"].get("Niveau de charge"):
                    niveau_charge = int(batterie_info["donnees"]["etat_general"]["Niveau de charge"])
                    
                    # Évaluation de l'état de la batterie
                    batterie_info["donnees"]["performance"]["État de la batterie"] = (
                        "Excellent" if niveau_charge > 90 else
                        "Bon" if niveau_charge > 70 else
                        "Moyen" if niveau_charge > 50 else
                        "Faible" if niveau_charge > 30 else
                        "Critique"
                    )
        
                batterie_info["statut"] = "Succès"
                return batterie_info
    
            except Exception as e:
                return {
                    "statut": "Erreur",
                    "message": f"Impossible de récupérer les informations de batterie : {str(e)}",
                    "details": str(e)
                }

        @classmethod
        def infos_systeme(cls) -> Dict[str, Any]:
            """
            Récupère les informations détaillées du système Android
            
            Returns:
                Dict[str, Any]: Informations système complètes
            """
            try:
                # Récupérer les informations système via différentes commandes ADB
                infos = {}
                
                # Version Android
                version_android = cls._execute_adb_command(["shell", "getprop", "ro.build.version.release"])
                infos['version_android'] = version_android.strip() if version_android else "N/A"
                
                # Version SDK
                sdk_version = cls._execute_adb_command(["shell", "getprop", "ro.build.version.sdk"])
                infos['version_sdk'] = sdk_version.strip() if sdk_version else "N/A"
                
                # Modèle de l'appareil
                modele = cls._execute_adb_command(["shell", "getprop", "ro.product.model"])
                infos['modele'] = modele.strip() if modele else "N/A"
                
                # Fabricant
                fabricant = cls._execute_adb_command(["shell", "getprop", "ro.product.manufacturer"])
                infos['fabricant'] = fabricant.strip() if fabricant else "N/A"
                
                # Numéro de série
                numero_serie = cls._execute_adb_command(["shell", "getprop", "ro.serialno"])
                infos['numero_serie'] = numero_serie.strip() if numero_serie else "N/A"
                
                # Informations du processeur
                cpu_info = cls._execute_adb_command(["shell", "cat", "/proc/cpuinfo"])
                if cpu_info:
                    # Extraire quelques informations de base du processeur
                    cpu_lines = cpu_info.split("\n")
                    cpu_details = {}
                    for ligne in cpu_lines:
                        if ":" in ligne:
                            cle, valeur = ligne.split(":", 1)
                            cpu_details[cle.strip()] = valeur.strip()
                    
                    infos['processeur'] = {
                        'model': cpu_details.get('model name', 'N/A'),
                        'cores': cpu_details.get('processor', 'N/A'),
                        'architecture': cpu_details.get('Architecture', 'N/A')
                    }
                else:
                    infos['processeur'] = "Impossible de récupérer les informations"
                
                # Mémoire
                memoire_totale = cls._execute_adb_command(["shell", "cat", "/proc/meminfo"])
                if memoire_totale:
                    memoire_lignes = memoire_totale.split("\n")
                    memoire_details = {}
                    for ligne in memoire_lignes:
                        if ":" in ligne:
                            cle, valeur = ligne.split(":", 1)
                            memoire_details[cle.strip()] = valeur.strip()
                    
                    infos['memoire'] = {
                        'total': memoire_details.get('MemTotal', 'N/A'),
                        'libre': memoire_details.get('MemFree', 'N/A'),
                        'disponible': memoire_details.get('MemAvailable', 'N/A')
                    }
                else:
                    infos['memoire'] = "Impossible de récupérer les informations"
                
                return {
                    "statut": "Succès",
                    "donnees": infos
                }
            
            except Exception as e:
                return {
                    "statut": "Erreur",
                    "message": f"Impossible de récupérer les informations système : {str(e)}",
                    "details": str(e)
                }

        @classmethod
        def performances(cls) -> Dict[str, Any]:
            """
            Récupère les informations de performances du système Android
            
            Returns:
                Dict[str, Any]: Informations de performances
            """
            try:
                # Récupérer l'utilisation du CPU
                cpu_info = cls._execute_adb_command(["shell", "top", "-n", "1", "-b"])
                cpu_usage = "N/A"
                if cpu_info:
                    # Extraire le pourcentage d'utilisation du CPU
                    cpu_lines = cpu_info.split("\n")
                    for ligne in cpu_lines:
                        if "CPU" in ligne and "%" in ligne:
                            cpu_usage = ligne.split(",")[0].strip()
                            break
        
                # Récupérer l'utilisation de la mémoire
                memoire_info = cls._execute_adb_command(["shell", "free"])
                memoire_usage = "N/A"
                if memoire_info:
                    memoire_lignes = memoire_info.split("\n")
                    if len(memoire_lignes) > 1:
                        memoire_cols = memoire_lignes[1].split()
                        total = int(memoire_cols[1])
                        used = int(memoire_cols[2])
                        memoire_usage = f"{used/total*100:.2f}%" if total > 0 else "N/A"
        
                # Récupérer les processus principaux
                processus_info = cls._execute_adb_command(["shell", "ps"])
                processus_principaux = []
                if processus_info:
                    processus_lignes = processus_info.split("\n")
                    for ligne in processus_lignes[1:6]:  # Limiter aux 5 premiers processus
                        colonnes = ligne.split()
                        if len(colonnes) >= 9:
                            processus_principaux.append({
                                "pid": colonnes[1],
                                "nom": colonnes[-1],
                                "cpu": colonnes[4] if len(colonnes) > 4 else "N/A"
                            })
        
                return {
                    "statut": "Succès",
                    "donnees": {
                        "utilisation_cpu": cpu_usage,
                        "utilisation_memoire": memoire_usage,
                        "processus_principaux": processus_principaux
                    }
                }
    
            except Exception as e:
                return {
                    "statut": "Erreur",
                    "message": f"Impossible de récupérer les informations de performances : {str(e)}",
                    "details": str(e)
                }

        @classmethod
        def infos_performances(cls) -> Dict[str, Any]:
            """
            Récupère les informations de performances du système Android
            
            Returns:
                Dict[str, Any]: Informations de performances
            """
            try:
                # Récupérer l'utilisation du CPU
                cpu_raw = cls._execute_adb_command(["shell", "top", "-n", "1", "-b"])
                cpu_match = re.search(r'CPU\s*:\s*(\d+)%', cpu_raw)
                cpu_usage = int(cpu_match.group(1)) if cpu_match else 0

                # Récupérer l'utilisation de la mémoire
                mem_raw = cls._execute_adb_command(["shell", "free"])
                mem_lines = [line for line in mem_raw.split('\n') if 'Mem:' in line]
                
                if mem_lines:
                    mem_parts = mem_lines[0].split()
                    total_mem = int(mem_parts[1])
                    used_mem = int(mem_parts[2])
                    memory_usage = int((used_mem / total_mem) * 100) if total_mem > 0 else 0
                else:
                    memory_usage = 0

                return {
                    "cpu_usage": cpu_usage,
                    "memory_usage": memory_usage,
                    "cpu_temperature": 0  # TODO: Implémenter la récupération de la température
                }
            except Exception as e:
                print(f"Erreur lors de la récupération des performances : {e}")
                return {
                    "cpu_usage": 0,
                    "memory_usage": 0,
                    "cpu_temperature": 0
                }

        @classmethod
        def infos_systeme(cls) -> Dict[str, Any]:
            """
            Récupère les informations détaillées du système Android
            
            Returns:
                Dict[str, Any]: Informations système complètes
            """
            try:
                # Récupérer la version d'Android
                android_version_raw = cls._execute_adb_command(["shell", "getprop", "ro.build.version.release"])
                android_version = android_version_raw.strip()

                # Récupérer le modèle de l'appareil
                model_raw = cls._execute_adb_command(["shell", "getprop", "ro.product.model"])
                model = model_raw.strip()

                # Récupérer la version SDK
                sdk_version_raw = cls._execute_adb_command(["shell", "getprop", "ro.build.version.sdk"])
                sdk_version = int(sdk_version_raw.strip())

                return {
                    "android_version": android_version,
                    "model": model,
                    "sdk_version": sdk_version
                }
            except Exception as e:
                print(f"Erreur lors de la récupération des informations système : {e}")
                return {
                    "android_version": "N/A",
                    "model": "Inconnu",
                    "sdk_version": 0
                }

        @classmethod
        def infos_batterie(cls) -> Dict[str, Any]:
            """
            Récupère les informations de batterie
            
            Returns:
                Dict[str, Any]: Informations de batterie
            """
            try:
                # Récupérer les informations de batterie
                batterie_raw = cls._execute_adb_command(["shell", "dumpsys", "battery"])
                
                # Extraire le niveau de batterie
                niveau_match = re.search(r'level: (\d+)', batterie_raw)
                niveau = int(niveau_match.group(1)) if niveau_match else 0

                # Extraire le statut de la batterie
                statut_match = re.search(r'status: (\w+)', batterie_raw)
                statut = statut_match.group(1) if statut_match else "Inconnu"

                # Extraire la température de la batterie
                temperature_match = re.search(r'temperature: (\d+)', batterie_raw)
                temperature = int(temperature_match.group(1)) / 10 if temperature_match else 0

                return {
                    "niveau": niveau,
                    "statut": statut,
                    "temperature": temperature
                }
            except Exception as e:
                print(f"Erreur lors de la récupération des informations de batterie : {e}")
                return {
                    "niveau": 0,
                    "statut": "Inconnu",
                    "temperature": 0
                }

    class Applications:
        @staticmethod
        def lister_applications(options: str = "-f") -> List[str]:
            """
            Liste les applications installées
            
            Args:
                options (str, optional): Options de listing. Défaut à "-f"
            
            Returns:
                List[str]: Liste des noms des applications
            """
            try:
                # Utiliser la commande pour lister tous les packages
                apps_raw = AdbServices._execute_adb_command(["shell", "pm", "list", "packages", options])
                
                # Extraire les noms des packages
                apps = []
                for ligne in apps_raw.split("\n"):
                    ligne = ligne.strip()
                    if ligne.startswith("package:"):
                        # Extraire le nom du package après "package:"
                        nom_app = ligne.split("package:")[1].strip()
                        apps.append(nom_app)
                
                # Trier les applications alphabétiquement
                apps.sort()
                
                return apps if apps else ["Aucune application trouvée"]
            
            except Exception as e:
                return [f"Erreur lors du listage des applications : {str(e)}"]

        @staticmethod
        def installer_application(chemin_apk: str) -> str:
            """
            Installe une application
            
            Args:
                chemin_apk (str): Chemin vers le fichier APK
            
            Returns:
                str: Résultat de l'installation
            """
            try:
                return AdbServices._execute_adb_command(["install", chemin_apk])
            except Exception as e:
                return f"Échec de l'installation de l'application : {str(e)}"

    class Fichiers:
        @staticmethod
        def lister_fichiers(chemin: str = "/sdcard") -> List[str]:
            """
            Liste les fichiers dans un répertoire
            
            Args:
                chemin (str, optional): Chemin du répertoire. Défaut à "/sdcard"
            
            Returns:
                List[str]: Liste des fichiers
            """
            try:
                fichiers_raw = AdbServices._execute_adb_command(["shell", "ls", "-l", chemin])
                fichiers = [fichier.strip() for fichier in fichiers_raw.split("\n") if fichier.strip()]
                
                return fichiers if fichiers else ["Aucun fichier trouvé dans le répertoire"]
            
            except Exception as e:
                return [f"Erreur lors du listage des fichiers : {str(e)}"]

        @staticmethod
        def copier_fichier(source: str, destination: str) -> str:
            """
            Copie un fichier
            
            Args:
                source (str): Chemin source
                destination (str): Chemin de destination
            
            Returns:
                str: Résultat de la copie
            """
            try:
                return AdbServices._execute_adb_command(["pull", source, destination])
            except Exception as e:
                return f"Échec de la copie du fichier : {str(e)}"

    @classmethod
    def get_device_info(cls):
        """
        Récupère les informations du premier appareil Android connecté
        
        Returns:
            dict or None: Informations de l'appareil ou None si aucun appareil n'est connecté
        """
        try:
            # Lister les périphériques connectés
            peripheriques = cls.Peripheriques.lister_peripheriques()
            logger.info(f"Périphériques détectés : {peripheriques}")
            
            if not peripheriques:
                logger.warning("Aucun périphérique détecté")
                return None
            
            # Prendre le premier appareil
            device_serial = peripheriques[0]
            logger.info(f"Appareil sélectionné : {device_serial}")
            
            # Récupérer les informations de performances
            performances = cls.Systeme.infos_performances()
            logger.info(f"Performances : {performances}")
            
            # Récupérer les informations système
            systeme = cls.Systeme.infos_systeme()
            logger.info(f"Système : {systeme}")
            
            # Récupérer les informations de batterie
            batterie = cls.Systeme.infos_batterie()
            logger.info(f"Batterie : {batterie}")
            
            # Construire et retourner le dictionnaire d'informations
            device_info = {
                'cpu_usage': int(performances.get('cpu_usage', 0)),
                'memory_usage': performances.get('memory_usage', 0),
                'android_version': systeme.get('android_version', 'N/A'),
                'battery_level': batterie.get('niveau', 0),
                'device_serial': device_serial
            }
            logger.info(f"Informations de l'appareil : {device_info}")
            return device_info
        
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des informations de l'appareil : {e}")
            logger.error(traceback.format_exc())
            return None

    @staticmethod
    def get_device_info():
        """
        Récupère les informations du premier appareil Android connecté
        
        Returns:
            dict or None: Informations de l'appareil ou None si aucun appareil n'est connecté
        """
        try:
            # Lister les périphériques connectés
            peripheriques = AdbServices.Peripheriques.lister_peripheriques()
            logger.info(f"Périphériques détectés : {peripheriques}")
            
            if not peripheriques:
                logger.warning("Aucun périphérique détecté")
                return None
            
            # Prendre le premier appareil
            device_serial = peripheriques[0]
            logger.info(f"Appareil sélectionné : {device_serial}")
            
            # Récupérer les informations de performances
            performances = AdbServices.Systeme.infos_performances()
            logger.info(f"Performances : {performances}")
            
            # Récupérer les informations système
            systeme = AdbServices.Systeme.infos_systeme()
            logger.info(f"Système : {systeme}")
            
            # Récupérer les informations de batterie
            batterie = AdbServices.Systeme.infos_batterie()
            logger.info(f"Batterie : {batterie}")
            
            # Construire et retourner le dictionnaire d'informations
            device_info = {
                'cpu_usage': int(performances.get('cpu_usage', 0)),
                'memory_usage': performances.get('memory_usage', 0),
                'android_version': systeme.get('android_version', 'N/A'),
                'battery_level': batterie.get('niveau', 0),
                'device_serial': device_serial
            }
            logger.info(f"Informations de l'appareil : {device_info}")
            return device_info
        
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des informations de l'appareil : {e}")
            logger.error(traceback.format_exc())
            return None

    @classmethod
    def demarrer_serveur(cls, host: str = "0.0.0.0", port: int = 8000) -> Dict[str, str]:
        """
        Démarre le serveur FastAPI
        
        Args:
            host (str, optional): Adresse d'écoute. Défaut à "0.0.0.0".
            port (int, optional): Port d'écoute. Défaut à 8000.
        
        Returns:
            Dict[str, str]: Résultat du démarrage du serveur
        """
        try:
            # Vérifier si un serveur est déjà en cours
            if cls._serveur_process is not None and hasattr(cls._serveur_process, 'poll') and cls._serveur_process.poll() is None:
                return {"statut": "Erreur", "message": "Un serveur est déjà en cours d'exécution"}
            
            # Commande pour démarrer le serveur
            commande = [
                sys.executable, "-m", "uvicorn", 
                "main:app", 
                "--host", host, 
                "--port", str(port), 
                "--reload"
            ]
            
            # Démarrer le processus
            cls._serveur_process = subprocess.Popen(
                commande, 
                cwd="E:/XROcculus/Backend/fastapi_projet",
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            return {
                "statut": "Succès", 
                "message": f"Serveur démarré sur http://{host}:{port}",
                "pid": cls._serveur_process.pid
            }
        
        except Exception as e:
            return {"statut": "Erreur", "message": str(e)}

    @classmethod
    def arreter_serveur(cls) -> Dict[str, str]:
        """
        Arrête le serveur FastAPI
        
        Returns:
            Dict[str, str]: Résultat de l'arrêt du serveur
        """
        try:
            if cls._serveur_process is None:
                return {"statut": "Erreur", "message": "Aucun serveur en cours d'exécution"}
            
            # Terminer le processus
            if hasattr(cls._serveur_process, 'terminate'):
                cls._serveur_process.terminate()
            
            return {"statut": "Succès", "message": "Serveur arrêté"}
        
        except Exception as e:
            return {"statut": "Erreur", "message": str(e)}

    @classmethod
    def demarrer_serveur_adb(cls) -> Dict[str, str]:
        """
        Démarre le serveur ADB
        
        Returns:
            Dict[str, str]: Résultat du démarrage du serveur ADB
        """
        try:
            # Exécuter la commande adb start-server
            resultat = subprocess.run(
                ["adb", "start-server"], 
                capture_output=True, 
                text=True, 
                check=True
            )
            
            return {
                "statut": "Succès", 
                "message": "Serveur ADB démarré avec succès",
                "details": resultat.stdout.strip()
            }
        
        except subprocess.CalledProcessError as e:
            return {
                "statut": "Erreur", 
                "message": "Échec du démarrage du serveur ADB",
                "details": e.stderr.strip()
            }
        except FileNotFoundError:
            return {
                "statut": "Erreur", 
                "message": "Commande ADB non trouvée. Assurez-vous qu'ADB est installé et dans le PATH."
            }
        except Exception as e:
            return {
                "statut": "Erreur", 
                "message": f"Erreur inattendue : {str(e)}"
            }

    @classmethod
    def arreter_serveur_adb(cls) -> Dict[str, str]:
        """
        Arrête le serveur ADB
        
        Returns:
            Dict[str, str]: Résultat de l'arrêt du serveur ADB
        """
        try:
            # Exécuter la commande adb kill-server
            resultat = subprocess.run(
                ["adb", "kill-server"], 
                capture_output=True, 
                text=True, 
                check=True
            )
            
            return {
                "statut": "Succès", 
                "message": "Serveur ADB arrêté avec succès",
                "details": resultat.stdout.strip()
            }
        
        except subprocess.CalledProcessError as e:
            return {
                "statut": "Erreur", 
                "message": "Échec de l'arrêt du serveur ADB",
                "details": e.stderr.strip()
            }
        except FileNotFoundError:
            return {
                "statut": "Erreur", 
                "message": "Commande ADB non trouvée. Assurez-vous qu'ADB est installé et dans le PATH."
            }
        except Exception as e:
            return {
                "statut": "Erreur", 
                "message": f"Erreur inattendue : {str(e)}"
            }

    @classmethod
    def get_device_info(cls):
        """
        Récupère les informations du premier appareil Android connecté
        
        Returns:
            dict or None: Informations de l'appareil ou None si aucun appareil n'est connecté
        """
        try:
            # Lister les périphériques connectés
            peripheriques = cls.Peripheriques.lister_peripheriques()
            logger.info(f"Périphériques détectés : {peripheriques}")
            
            if not peripheriques:
                logger.warning("Aucun périphérique détecté")
                return None
            
            # Prendre le premier appareil
            device_serial = peripheriques[0]
            logger.info(f"Appareil sélectionné : {device_serial}")
            
            # Récupérer les informations de performances
            performances = cls.Systeme.infos_performances()
            logger.info(f"Performances : {performances}")
            
            # Récupérer les informations système
            systeme = cls.Systeme.infos_systeme()
            logger.info(f"Système : {systeme}")
            
            # Récupérer les informations de batterie
            batterie = cls.Systeme.infos_batterie()
            logger.info(f"Batterie : {batterie}")
            
            # Construire et retourner le dictionnaire d'informations
            device_info = {
                'cpu_usage': int(performances.get('cpu_usage', 0)),
                'memory_usage': performances.get('memory_usage', 0),
                'android_version': systeme.get('android_version', 'N/A'),
                'battery_level': batterie.get('niveau', 0),
                'device_serial': device_serial
            }
            logger.info(f"Informations de l'appareil : {device_info}")
            return device_info
        
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des informations de l'appareil : {e}")
            logger.error(traceback.format_exc())
            return None

    @staticmethod
    def get_device_info():
        """
        Récupère les informations du premier appareil Android connecté
        
        Returns:
            dict or None: Informations de l'appareil ou None si aucun appareil n'est connecté
        """
        try:
            # Lister les périphériques connectés
            peripheriques = AdbServices.Peripheriques.lister_peripheriques()
            logger.info(f"Périphériques détectés : {peripheriques}")
            
            if not peripheriques:
                logger.warning("Aucun périphérique détecté")
                return None
            
            # Prendre le premier appareil
            device_serial = peripheriques[0]
            logger.info(f"Appareil sélectionné : {device_serial}")
            
            # Récupérer les informations de performances
            performances = AdbServices.Systeme.infos_performances()
            logger.info(f"Performances : {performances}")
            
            # Récupérer les informations système
            systeme = AdbServices.Systeme.infos_systeme()
            logger.info(f"Système : {systeme}")
            
            # Récupérer les informations de batterie
            batterie = AdbServices.Systeme.infos_batterie()
            logger.info(f"Batterie : {batterie}")
            
            # Construire et retourner le dictionnaire d'informations
            device_info = {
                'cpu_usage': int(performances.get('cpu_usage', 0)),
                'memory_usage': performances.get('memory_usage', 0),
                'android_version': systeme.get('android_version', 'N/A'),
                'battery_level': batterie.get('niveau', 0),
                'device_serial': device_serial
            }
            logger.info(f"Informations de l'appareil : {device_info}")
            return device_info
        
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des informations de l'appareil : {e}")
            logger.error(traceback.format_exc())
            return None

    @staticmethod
    def get_device_info() -> Dict[str, Any]:
        """
        Récupère les informations système complètes du périphérique Android
        
        Returns:
            Dict[str, Any]: Informations système du périphérique
        """
        try:
            # Vérifier si un périphérique est connecté
            peripheriques = AdbServices.Peripheriques.lister_peripheriques()
            if not peripheriques:
                return {
                    'cpu_usage': 0,
                    'memory_usage': 0,
                    'android_version': 'Aucun appareil connecté',
                    'battery_level': 0
                }
            
            # Utiliser le premier périphérique connecté
            serial = peripheriques[0]
            
            # Récupérer les informations système
            props = AdbServices.Peripheriques.infos_peripherique(serial)
            
            # Récupérer les informations de performances
            try:
                # Commande pour obtenir l'utilisation du CPU
                cpu_usage_cmd = ["shell", "top", "-n", "1", "-b"]
                cpu_output = AdbServices._execute_adb_command(cpu_usage_cmd)
                cpu_match = re.search(r'CPU\s*:\s*(\d+)%', cpu_output)
                cpu_usage = int(cpu_match.group(1)) if cpu_match else 0
            except Exception:
                cpu_usage = 0
            
            # Récupérer l'utilisation de la mémoire
            try:
                memory_cmd = ["shell", "free"]
                memory_output = AdbServices._execute_adb_command(memory_cmd)
                memory_match = re.search(r'Mem:\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)', memory_output)
                total_memory = int(memory_match.group(1)) if memory_match else 0
                memory_usage = int((total_memory / 100) * 100) if total_memory > 0 else 0
            except Exception:
                memory_usage = 0
            
            # Version Android
            android_version = props.get('ro.build.version.release', 'Inconnu')
            
            # Niveau de batterie
            try:
                battery_cmd = ["shell", "dumpsys", "battery"]
                battery_output = AdbServices._execute_adb_command(battery_cmd)
                battery_match = re.search(r'level: (\d+)', battery_output)
                battery_level = int(battery_match.group(1)) if battery_match else 0
            except Exception:
                battery_level = 0
            
            return {
                'cpu_usage': cpu_usage,
                'memory_usage': memory_usage,
                'android_version': android_version,
                'battery_level': battery_level
            }
        
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des informations système : {e}")
            return {
                'cpu_usage': 0,
                'memory_usage': 0,
                'android_version': 'Erreur de récupération',
                'battery_level': 0
            }
