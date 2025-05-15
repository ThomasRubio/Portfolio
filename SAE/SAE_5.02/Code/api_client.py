import requests
import urllib3
from typing import Dict, Any, Optional
from datetime import datetime

# Désactiver les avertissements pour les requêtes non sécurisées
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class TodoListAPIClient:
    def __init__(self, base_url="https://ec2-13-39-24-139.eu-west-3.compute.amazonaws.com"):
        self.base_url = base_url.rstrip('/')
        self.token = None
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        # Tables mères et indépendantes en premier
        self.tables = [
            'USER',           # Table de base - pas de dépendance
            'ETIQUETTES',     # Table indépendante - pas de dépendance
            'GROUPE',         # Dépend uniquement de USER
            'MEMBRE',         # Dépend de USER et GROUPE (avec CASCADE)
            'INVITATION',     # Dépend de USER et GROUPE (avec CASCADE)
            'DOSSIER',        # Dépend de GROUPE (avec CASCADE)
            'TACHES',         # Dépend de DOSSIER et USER (avec CASCADE sur DOSSIER)
            'DROIT',          # Dépend de USER et TACHES
            'SOUS_TACHES',    # Dépend de TACHES (avec CASCADE)
            'COMMENTAIRES',   # Dépend de TACHES et USER (avec CASCADE)
            'HISTORIQUE',     # Dépend de TACHES et USER
            'TACHE_ETIQUETTE',# Dépend de TACHES et ETIQUETTES (avec CASCADE)
            'GOOGLE_AGENDA',  # Dépend de DOSSIER (avec CASCADE)
            'GOOGLE_TACHE',   # Dépend de TACHES (avec CASCADE)
            'TACHE_USER'      # Dépend de TACHES et USER (table de liaison)
        ]
        
        self.dependencies = {
            'GROUPE': ['USER'],
            'MEMBRE': ['USER', 'GROUPE'],
            'INVITATION': ['USER', 'GROUPE'],
            'DOSSIER': ['GROUPE'],
            'TACHES': ['DOSSIER', 'USER'],
            'DROIT': ['USER', 'TACHES'],
            'SOUS_TACHES': ['TACHES'],
            'COMMENTAIRES': ['TACHES', 'USER'],
            'HISTORIQUE': ['TACHES', 'USER'],
            'TACHE_ETIQUETTE': ['TACHES', 'ETIQUETTES'],
            'GOOGLE_AGENDA': ['DOSSIER'],
            'GOOGLE_TACHE': ['TACHES'],
            'TACHE_USER': ['TACHES', 'USER']
        }

        self.response_keys = {
            'USER': 'users',
            'GROUPE': 'groupes',
            'DOSSIER': 'dossiers',
            'TACHES': 'taches',
            'DROIT': 'droits',
            'ETIQUETTES': 'etiquettes',
            'TACHE_ETIQUETTE': 'tache_etiquette',
            'INVITATION': 'invitations',
            'MEMBRE': 'membres',
            'HISTORIQUE': 'historique',
            'SOUS_TACHES': 'sous_taches',
            'COMMENTAIRES': 'commentaires',
            'GOOGLE_AGENDA': 'google_agenda',
            'GOOGLE_TACHE': 'google_tache',
            'TACHE_USER': 'tache_user'
        }
        
        self.export_endpoints = {
            'USER': '/api/export/users',
            'GROUPE': '/api/export/groupes', 
            'DOSSIER': '/api/export/dossiers',
            'TACHES': '/api/export/taches',
            'DROIT': '/api/export/droits',
            'ETIQUETTES': '/api/export/etiquettes',
            'TACHE_ETIQUETTE': '/api/export/tache_etiquette',
            'INVITATION': '/api/export/invitations',
            'MEMBRE': '/api/export/membres',
            'HISTORIQUE': '/api/export/historique',
            'SOUS_TACHES': '/api/export/sous_taches',
            'COMMENTAIRES': '/api/export/commentaires',
            'GOOGLE_AGENDA': '/api/export/google_agenda',
            'GOOGLE_TACHE': '/api/export/google_tache',
            'TACHE_USER': '/api/export/tache_user'
        }

    def verify_dependencies(self) -> bool:
        """Vérifie que l'ordre des tables respecte les dépendances"""
        for table_name, deps in self.dependencies.items():
            table_index = self.tables.index(table_name)
            for dep in deps:
                dep_index = self.tables.index(dep)
                if dep_index > table_index:
                    print(f"❌ Erreur de dépendance : {table_name} dépend de {dep} mais vient avant")
                    return False
                print(f"✓ Dépendance valide : {table_name} -> {dep}")
        return True

    def export_table(self, table_name: str) -> Optional[Dict]:
        """Récupère les données d'une table depuis l'API"""
        if not self.token:
            raise Exception("Vous devez être connecté")
            
        try:
            endpoint = self.export_endpoints.get(table_name)
            if not endpoint:
                print(f"❌ Pas d'endpoint d'export trouvé pour {table_name}")
                return None
                
            url = f"{self.base_url}{endpoint}"
            print(f"Tentative d'export depuis: {url}")
            
            response = requests.get(
                url,
                headers=self.headers,
                verify=False,
                timeout=30
            )
            
            if response.status_code == 404:
                print(f"❌ Endpoint non trouvé: {url}")
                return None
                
            response.raise_for_status()
            data = response.json()
            
            expected_key = self.response_keys.get(table_name)
            total_key = f"{expected_key}_total" if expected_key else None
            
            if expected_key in data:
                records = data[expected_key]
                if isinstance(records, list):
                    print(f"✓ {len(records)} enregistrements récupérés pour {table_name}")
                    return {
                        table_name: records,
                        'total': data.get(total_key, len(records))
                    }
            
            print(f"❌ Format de réponse invalide pour {table_name}")
            return None
            
        except Exception as e:
            print(f"❌ Erreur lors de l'export de {table_name}: {str(e)}")
            return None

    def login(self, username: str, password: str) -> bool:
        """Connexion à l'API"""
        try:
            response = requests.post(
                f"{self.base_url}/auth/login",
                json={
                    "username": username,
                    "mdp": password
                },
                headers=self.headers,
                verify=False,
                timeout=30
            )
            
            print(f"Login attempt for {username}")
            print(f"Response status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                if "token" in data:
                    self.token = data["token"]
                    self.headers["Authorization"] = f"Bearer {self.token}"
                    print("✓ Connexion réussie")
                    return True
            return False
            
        except Exception as e:
            print(f"❌ Erreur de connexion: {str(e)}")
            return False

    def verify_dependencies(self) -> bool:
        """Vérifie que l'ordre des tables respecte les dépendances"""
        dependencies = {
            'TACHES': ['DOSSIER'],
            'DOSSIER': ['GROUPE'],
            'TACHE_ETIQUETTE': ['TACHES', 'ETIQUETTES'],
            'SOUS_TACHES': ['TACHES'],
            'COMMENTAIRES': ['TACHES', 'USER'],
            'HISTORIQUE': ['TACHES', 'USER'],
            'GOOGLE_AGENDA': ['DOSSIER'],
            'GOOGLE_TACHE': ['TACHES'],
            'TACHE_USER': ['TACHES', 'USER'],
            'MEMBRE': ['USER', 'GROUPE'],
            'INVITATION': ['USER', 'GROUPE'],
            'DROIT': ['USER', 'TACHES']
        }
        
        # Vérifie que les dépendances sont satisfaites dans l'ordre des tables
        for table_name, deps in dependencies.items():
            table_index = self.tables.index(table_name)
            for dep in deps:
                dep_index = self.tables.index(dep)
                if dep_index > table_index:
                    print(f"❌ Erreur de dépendance : {table_name} dépend de {dep} mais vient avant")
                    return False
        return True
