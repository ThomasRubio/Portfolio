import unittest
import requests
import json
from datetime import datetime, timedelta
import logging
import sys
import time
from colorama import init, Fore, Style
from typing import Dict, Any, List
from urllib3.exceptions import InsecureRequestWarning

# Désactiver les avertissements pour les certificats auto-signés
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

class TodoListAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Configuration initiale pour tous les tests"""
        cls.base_url = "https://ec2-13-39-24-139.eu-west-3.compute.amazonaws.com"
        cls.session = requests.Session()
        cls.session.verify = False
        cls.test_data = {}
        cls.register_and_login()

    def setUp(self):
        """Configuration avant chaque test"""
        self.timestamp = int(time.time())
        if not hasattr(self, 'session'):
            self.session = self.__class__.session
        if not hasattr(self, 'test_data'):
            self.test_data = self.__class__.test_data

    @classmethod
    def tearDownClass(cls):
        """Nettoyage après tous les tests"""
        try:
            if hasattr(cls, 'test_data'):
                # Nettoyage des ressources créées pendant les tests
                if 'groupe_id' in cls.test_data:
                    cls.session.delete(f"{cls.base_url}/groupes/{cls.test_data['groupe_id']}")
                if 'dossier_id' in cls.test_data:
                    cls.session.delete(f"{cls.base_url}/dossiers/{cls.test_data['dossier_id']}")
                if 'tache_id' in cls.test_data:
                    cls.session.delete(f"{cls.base_url}/taches/{cls.test_data['tache_id']}")
            if hasattr(cls, 'session'):
                cls.session.close()
        except Exception as e:
            print(f"Erreur lors du nettoyage: {str(e)}")

    # Tests de base et d'authentification
    def test_01_root_endpoint(self):
        """Test de l'endpoint racine"""
        response = self.session.get(f"{self.base_url}/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('name', data)
        self.assertIn('version', data)
        self.assertIn('endpoints', data)

    def test_02_health_check(self):
        """Test du health check"""
        response = self.session.get(f"{self.base_url}/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['status'], 'healthy')
        self.assertEqual(data['database'], 'connected')

    def test_03_register_and_login(self):
        """Test complet du cycle d'inscription et connexion"""
        timestamp = int(time.time())
        register_data = {
            "nom": "Test",
            "prenom": "User",
            "mail": f"test{timestamp}@example.com",
            "username": f"testuser{timestamp}",
            "mdp": "TestPassword123!"
        }
        
        response = self.session.post(f"{self.base_url}/auth/register", json=register_data)
        print(f"Register response: {response.status_code}")
        print(f"Response content: {response.text}")
        self.assertIn(response.status_code, [201, 400])
        
        if response.status_code == 201:
            self.assertIn('user', response.json())
            
            login_data = {
                "username": register_data['username'],
                "mdp": register_data['mdp']
            }
            response = self.session.post(f"{self.base_url}/auth/login", json=login_data)
            self.assertEqual(response.status_code, 200)
            self.assertIn('token', response.json())

    def test_04_invalid_login(self):
        """Test de tentative de connexion invalide"""
        login_data = {
            "username": "invalid_user",
            "mdp": "invalid_password"
        }
        response = self.session.post(f"{self.base_url}/auth/login", json=login_data)
        self.assertEqual(response.status_code, 401)

    def test_05_token_refresh(self):
        """Test du rafraîchissement du token"""
        response = self.session.post(f"{self.base_url}/auth/refresh")
        print(f"Refresh response: {response.status_code}")
        print(f"Response content: {response.text}")
        self.assertEqual(response.status_code, 200)
        self.assertIn('token', response.json())

    def test_06_logout(self):
        """Test de la déconnexion"""
        response = self.session.post(f"{self.base_url}/auth/logout")
        self.assertEqual(response.status_code, 200)

    # Tests de gestion des groupes
    def test_07_groupe_crud(self):
        """Test CRUD complet pour les groupes"""
        # Création
        group_data = {"nom": f"Groupe Test {int(time.time() * 1000)}"}
        response = self.session.post(f"{self.base_url}/groupes", json=group_data)
        print(f"Group CRUD test - Create response: {response.status_code}")
        print(f"Response content: {response.text}")
        self.assertEqual(response.status_code, 201)
        groupe_id = response.json()['id_groupe']
        self.test_data['groupe_id'] = groupe_id

        # Lecture
        response = self.session.get(f"{self.base_url}/groupes/{groupe_id}")
        self.assertEqual(response.status_code, 200)

        # Mise à jour
        update_data = {"nom": f"Groupe Modifié {int(time.time() * 1000)}"}
        response = self.session.put(
            f"{self.base_url}/groupes/{groupe_id}",
            json=update_data
        )
        print(f"Group update response: {response.status_code}")
        print(f"Response content: {response.text}")
        self.assertEqual(response.status_code, 200)

        # Suppression
        response = self.session.delete(f"{self.base_url}/groupes/{groupe_id}")
        self.assertEqual(response.status_code, 204)

    # Tests de gestion des dossiers
    def test_08_dossier_crud(self):
        """Test CRUD complet pour les dossiers"""
        # Création du groupe parent
        groupe_data = {"nom": f"Groupe Parent {int(time.time() * 1000)}"}
        response = self.session.post(f"{self.base_url}/groupes", json=groupe_data)
        self.assertEqual(response.status_code, 201)
        groupe_id = response.json()['id_groupe']

        # Création du dossier
        dossier_data = {"nom": f"Dossier Test {int(time.time() * 1000)}"}
        response = self.session.post(
            f"{self.base_url}/groupes/{groupe_id}/dossiers",
            json=dossier_data
        )
        print(f"Create folder response: {response.status_code}")
        print(f"Response content: {response.text}")
        self.assertEqual(response.status_code, 201)
        dossier_id = response.json()['id_dossier']

        # Attendre un peu pour éviter le rate limiting
        time.sleep(0.1)

        # Lecture
        response = self.session.get(f"{self.base_url}/dossiers/{dossier_id}")
        print(f"Get folder response: {response.status_code}")
        print(f"Response content: {response.text}")
        self.assertEqual(response.status_code, 200)

        # Mise à jour
        update_data = {"nom": f"Dossier Modifié {int(time.time() * 1000)}"}
        response = self.session.put(
            f"{self.base_url}/dossiers/{dossier_id}",
            json=update_data
        )
        self.assertEqual(response.status_code, 200)

        # Suppression
        response = self.session.delete(f"{self.base_url}/dossiers/{dossier_id}")
        self.assertEqual(response.status_code, 204)
        
    # Tests de gestion des tâches
    def test_09_tache_crud(self):
        """Test CRUD complet pour les tâches"""
        # Création du groupe parent
        groupe_data = {"nom": f"Groupe Parent {int(time.time() * 1000)}"}
        response = self.session.post(f"{self.base_url}/groupes", json=groupe_data)
        self.assertEqual(response.status_code, 201)
        groupe_id = response.json()['id_groupe']

        # Création du dossier parent
        dossier_data = {"nom": f"Dossier Parent {int(time.time() * 1000)}"}
        response = self.session.post(
            f"{self.base_url}/groupes/{groupe_id}/dossiers",
            json=dossier_data
        )
        self.assertEqual(response.status_code, 201)
        dossier_id = response.json()['id_dossier']

        # Création de la tâche
        timestamp = int(time.time() * 1000)
        tache_data = {
            "titre": f"Tâche Test {timestamp}",
            "sous_titre": "Sous-titre de test",
            "texte": "Description de test",
            "priorite": 1,
            "statut": 0
        }
        response = self.session.post(
            f"{self.base_url}/dossiers/{dossier_id}/taches",
            json=tache_data
        )
        print(f"Create task response: {response.status_code}")
        print(f"Response content: {response.text}")
        self.assertEqual(response.status_code, 201)

    # Méthodes utilitaires
    @classmethod
    def register_and_login(cls):
        """Enregistre un utilisateur de test et récupère le token"""
        timestamp = int(time.time())
        register_data = {
            "nom": "Test",
            "prenom": "User",
            "mail": f"test{timestamp}@example.com",
            "username": f"testuser{timestamp}",
            "mdp": "TestPassword123!"
        }
        
        try:
            # Tentative d'enregistrement
            register_response = cls.session.post(
                f"{cls.base_url}/auth/register",
                json=register_data
            )
            
            print(f"Register response: {register_response.status_code}")
            print(f"Register content: {register_response.text}")
            
            if register_response.status_code == 201:
                user_data = register_response.json()
                cls.test_data['user_id'] = user_data['user']['id_user']
                token = user_data['token']
            else:
                # Si l'enregistrement échoue, on essaie de se connecter
                login_response = cls.session.post(
                    f"{cls.base_url}/auth/login",
                    json={
                        "username": register_data['username'],
                        "mdp": register_data['mdp']
                    }
                )
                
                print(f"Login response: {login_response.status_code}")
                print(f"Login content: {login_response.text}")
                
                if login_response.status_code != 200:
                    raise Exception(f"Login failed: {login_response.text}")
                    
                token = login_response.json()['token']
            
            cls.session.headers.update({
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            })
            
            cls.test_data['token'] = token
            cls.test_data['user_credentials'] = register_data
            
            print("Final headers:", cls.session.headers)
            
        except Exception as e:
            print(f"Authentication error: {str(e)}")
            raise

    def create_test_group(self):
        """Crée un groupe de test et retourne son ID"""
        unique_timestamp = int(time.time() * 1000)  # Millisecondes pour plus d'unicité
        group_name = f"Groupe Test {unique_timestamp}"
        data = {"nom": group_name}
        
        print(f"Attempting to create group: {data}")
        
        response = self.session.post(
            f"{self.base_url}/groupes",
            json=data
        )
        
        print(f"Create group response: {response.status_code}")
        print(f"Response content: {response.text}")
        
        # Si le groupe existe déjà, on essaie avec un nouveau nom
        if response.status_code == 400:
            group_name = f"Groupe Test {unique_timestamp}_2"
            data = {"nom": group_name}
            response = self.session.post(
                f"{self.base_url}/groupes",
                json=data
            )
        
        self.assertEqual(response.status_code, 201)
        response_data = response.json()
        return response_data['id_groupe']

    def create_test_folder(self):
        """Crée un dossier de test et retourne son ID"""
        groupe_id = self.create_test_group()
        data = {"nom": f"Dossier Test {self.timestamp}"}
        
        print(f"Attempting to create folder in group {groupe_id}: {data}")
        
        response = self.session.post(
            f"{self.base_url}/groupes/{groupe_id}/dossiers",
            json=data
        )
        
        print(f"Create folder response: {response.status_code}")
        print(f"Response content: {response.text}")
        
        self.assertEqual(response.status_code, 201)
        return response.json()['id_dossier']

    def create_test_task(self):
        """Crée une tâche de test et retourne son ID"""
        dossier_id = self.create_test_folder()
        data = {
            "titre": f"Tâche Test {self.timestamp}",
            "sous_titre": "Sous-titre de test",
            "texte": "Description de test",
            "priorite": 1,
            "statut": 0
        }
        
        print(f"Attempting to create task in folder {dossier_id}: {data}")
        
        response = self.session.post(
            f"{self.base_url}/dossiers/{dossier_id}/taches",
            json=data
        )
        
        print(f"Create task response: {response.status_code}")
        print(f"Response content: {response.text}")
        
        self.assertEqual(response.status_code, 201)
        return response.json()['id_tache']

    def test_10_task_assignment(self):
        """Test d'assignation de tâches aux utilisateurs"""
        # Création d'une nouvelle tâche
        tache_id = self.create_test_task()
        
        # Création d'un nouvel utilisateur pour l'assignation
        timestamp = int(time.time())
        register_data = {
            "nom": "Test",
            "prenom": "Assignee",
            "mail": f"assignee{timestamp}@example.com",
            "username": f"assignee{timestamp}",
            "mdp": "TestPassword123!"
        }
        
        # Enregistrement du nouvel utilisateur
        response = self.session.post(f"{self.base_url}/auth/register", json=register_data)
        self.assertEqual(response.status_code, 201)
        assignee_id = response.json()['user']['id_user']
        
        # Assignation de la tâche
        assign_data = {"user_id": assignee_id}
        response = self.session.post(
            f"{self.base_url}/taches/{tache_id}/assign",
            json=assign_data
        )
        print(f"Task assignment response: {response.status_code}")
        print(f"Response content: {response.text}")
        self.assertEqual(response.status_code, 201)

    def test_11_etiquettes(self):
        """Test de gestion des étiquettes"""
        # Création d'une étiquette
        etiquette_data = {"description": f"Étiquette Test {int(time.time() * 1000)}"}
        response = self.session.post(f"{self.base_url}/etiquettes", json=etiquette_data)
        print(f"Create label response: {response.status_code}")
        print(f"Response content: {response.text}")
        self.assertEqual(response.status_code, 201)
        etiquette_id = response.json()['id_etiquettes']

        # Création d'une tâche pour l'association
        tache_id = self.create_test_task()

        # Association de l'étiquette à la tâche via la route correcte
        response = self.session.post(f"{self.base_url}/taches/{tache_id}/etiquettes", 
                                json={"id_etiquettes": etiquette_id})
        self.assertEqual(response.status_code, 201)


    def test_12_commentaires(self):
        """Test de gestion des commentaires"""
        tache_id = self.create_test_task()
        
        # Création d'un commentaire
        commentaire_data = {"commentaire": f"Commentaire Test {self.timestamp}"}
        response = self.session.post(
            f"{self.base_url}/taches/{tache_id}/commentaires",
            json=commentaire_data
        )
        print(f"Create comment response: {response.status_code}")
        print(f"Response content: {response.text}")
        self.assertEqual(response.status_code, 201)

    def test_13_sous_taches(self):
        """Test de gestion des sous-tâches"""
        tache_id = self.create_test_task()
        
        # Création d'une sous-tâche avec tous les champs requis
        sous_tache_data = {
            "titre": f"Sous-tâche Test {self.timestamp}",
            "id_tache": tache_id,  # Ajout de l'ID de la tâche parent qui est requis
            "priorite": 1,
            "statut": 0,
            "date_fin": None
        }
        response = self.session.post(
            f"{self.base_url}/taches/{tache_id}/sous-taches",
            json=sous_tache_data
        )
        print(f"Create subtask response: {response.status_code}")
        print(f"Response content: {response.text}")
        self.assertEqual(response.status_code, 201)

    def test_14_google_integration(self):
        """Test de l'intégration Google"""
        dossier_id = self.create_test_folder()
        
        # Test Google Agenda
        agenda_data = {
            "google_id_cal": f"google_calendar_{self.timestamp}",
            "local_id_cal": dossier_id
        }
        response = self.session.post(f"{self.base_url}/google/agendas", json=agenda_data)
        print(f"Google Calendar integration response: {response.status_code}")
        print(f"Response content: {response.text}")
        self.assertEqual(response.status_code, 201)

    def test_15_permissions(self):
        """Test des permissions et droits d'accès"""
        # Création d'un nouvel utilisateur pour le test
        timestamp = int(time.time() * 1000)
        register_data = {
            "nom": "Test",
            "prenom": "Member",
            "mail": f"member{timestamp}@example.com",
            "username": f"member{timestamp}",
            "mdp": "TestPassword123!"
        }
        
        response = self.session.post(f"{self.base_url}/auth/register", json=register_data)
        print(f"Register member response: {response.status_code}")
        print(f"Response content: {response.text}")
        self.assertEqual(response.status_code, 201)
        member_id = response.json()['user']['id_user']

        time.sleep(0.2)  # Attendre pour éviter le rate limiting

        # Création d'un groupe
        groupe_data = {"nom": f"Groupe Test Permissions {timestamp}"}
        response = self.session.post(f"{self.base_url}/groupes", json=groupe_data)
        self.assertEqual(response.status_code, 201)
        groupe_id = response.json()['id_groupe']

        time.sleep(0.2)  # Attendre pour éviter le rate limiting

        # Test d'ajout d'un membre
        membre_data = {
            "id_user": member_id,
            "role": "editeur"
        }
        response = self.session.post(
            f"{self.base_url}/groupes/{groupe_id}/membres",
            json=membre_data
        )
        print(f"Permissions test response: {response.status_code}")
        print(f"Response content: {response.text}")
        self.assertEqual(response.status_code, 201)

    def test_16_historique(self):
        """Test de l'historique des actions"""
        response = self.session.get(f"{self.base_url}/historique")
        print(f"Historique response: {response.status_code}")
        print(f"Response content: {response.text}")
        self.assertEqual(response.status_code, 200)

    def test_17_invitation_workflow(self):
        """Test du workflow complet d'invitation"""
        # Création d'un nouvel utilisateur pour l'invitation
        timestamp = int(time.time() * 1000)
        register_data = {
            "nom": "Test",
            "prenom": "Invite",
            "mail": f"invite{timestamp}@example.com",
            "username": f"invite{timestamp}",
            "mdp": "TestPassword123!"
        }
        
        response = self.session.post(f"{self.base_url}/auth/register", json=register_data)
        self.assertEqual(response.status_code, 201)
        invite_id = response.json()['user']['id_user']

        time.sleep(0.2)  # Attendre pour éviter le rate limiting

        # Création d'un groupe
        groupe_id = self.create_test_group()
        
        # Attendre pour éviter le rate limiting
        time.sleep(0.2)

        # Création d'une invitation
        invitation_data = {
            "id_groupe": groupe_id,
            "id_user": invite_id
        }
        response = self.session.post(f"{self.base_url}/invitations", json=invitation_data)
        print(f"Invitation creation response: {response.status_code}")
        print(f"Response content: {response.text}")
        self.assertEqual(response.status_code, 201)

    def test_18_search_and_filters(self):
        """Test des fonctionnalités de recherche et filtrage"""
        dossier_id = self.create_test_folder()
        
        # Création d'une tâche avec des attributs spécifiques
        tache_data = {
            "titre": f"Recherche Test {self.timestamp}",
            "priorite": 1,
            "statut": 0,
            "date_fin": (datetime.utcnow() + timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S')
        }
        response = self.session.post(
            f"{self.base_url}/dossiers/{dossier_id}/taches",
            json=tache_data
        )
        self.assertEqual(response.status_code, 201)

        # Test des filtres
        response = self.session.get(
            f"{self.base_url}/dossiers/{dossier_id}/taches",
            params={
                'priorite': 1,
                'statut': 0
            }
        )
        print(f"Search and filter response: {response.status_code}")
        print(f"Response content: {response.text}")
        self.assertEqual(response.status_code, 200)
        self.assertGreater(len(response.json()), 0)

    def test_19_batch_operations(self):
        """Test des opérations par lots"""
        dossier_id = self.create_test_folder()
        
        # Création de plusieurs tâches
        tasks = []
        for i in range(3):
            response = self.session.post(
                f"{self.base_url}/dossiers/{dossier_id}/taches",
                json={
                    "titre": f"Tâche Batch {i} {self.timestamp}",
                    "priorite": i,
                    "statut": 0
                }
            )
            self.assertEqual(response.status_code, 201)
            tasks.append(response.json()['id_tache'])

        # Vérification de la liste
        response = self.session.get(f"{self.base_url}/dossiers/{dossier_id}/taches")
        print(f"Batch operations response: {response.status_code}")
        print(f"Response content: {response.text}")
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(len(response.json()), len(tasks))

    def test_20_error_handling(self):
        """Test de la gestion des erreurs"""
        # Test avec un ID invalide qui n'existe pas
        response = self.session.get(f"{self.base_url}/taches/999999999")
        print(f"Error handling response: {response.status_code}")
        print(f"Response content: {response.text}")
        self.assertEqual(response.status_code, 404)

    def test_etiquettes_crud(self):
        """Test CRUD complet pour les étiquettes"""
        # Création
        etiquette_data = {"description": f"Étiquette Test {self.timestamp}"}
        response = self.session.post(f"{self.base_url}/etiquettes", json=etiquette_data)
        self.assertEqual(response.status_code, 201)
        etiquette_id = response.json()['id_etiquettes']

        # Lecture
        response = self.session.get(f"{self.base_url}/etiquettes")
        self.assertEqual(response.status_code, 200)

        # Mise à jour
        update_data = {"description": f"Étiquette Modifiée {self.timestamp}"}
        response = self.session.put(f"{self.base_url}/etiquettes/{etiquette_id}", json=update_data)
        self.assertEqual(response.status_code, 200)

        # Suppression
        response = self.session.delete(f"{self.base_url}/etiquettes/{etiquette_id}")
        self.assertEqual(response.status_code, 204)
    
    def test_task_history(self):
        """Test de l'historique d'une tâche spécifique"""
        tache_id = self.create_test_task()
        response = self.session.get(f"{self.base_url}/taches/{tache_id}/historique")
        self.assertEqual(response.status_code, 200)
        
    def test_google_sync_crud(self):
        """Test CRUD complet pour les synchronisations Google"""
        # Google Calendar
        dossier_id = self.create_test_folder()
        calendar_data = {
            "google_id_cal": f"test_cal_{self.timestamp}",
            "local_id_cal": dossier_id
        }
        response = self.session.post(f"{self.base_url}/google/agendas", json=calendar_data)
        self.assertEqual(response.status_code, 201)
        calendar_id = response.json()['id_gagenda']

        # Vérification Calendar
        response = self.session.get(f"{self.base_url}/google/agendas/{calendar_id}")
        self.assertEqual(response.status_code, 200)

        # Suppression Calendar
        response = self.session.delete(f"{self.base_url}/google/agendas/{calendar_id}")
        self.assertEqual(response.status_code, 204)

        # Google Tasks
        tache_id = self.create_test_task()
        task_data = {
            "google_id_event": f"test_event_{self.timestamp}",
            "local_id_event": tache_id
        }
        response = self.session.post(f"{self.base_url}/google/taches", json=task_data)
        self.assertEqual(response.status_code, 201)
        task_id = response.json()['id_gtache']

        # Vérification Task
        response = self.session.get(f"{self.base_url}/google/taches/{task_id}")
        self.assertEqual(response.status_code, 200)

        # Suppression Task
        response = self.session.delete(f"{self.base_url}/google/taches/{task_id}")
        self.assertEqual(response.status_code, 204)
    def test_current_user(self):
        response = self.session.get(f"{self.base_url}/users/me")
        self.assertEqual(response.status_code, 200)
    
    def test_users_list(self):
        response = self.session.get(f"{self.base_url}/users")
        self.assertEqual(response.status_code, 200)   
        
    def test_droits_crud(self):
        """Test CRUD complet pour les droits"""
        tache_id = self.create_test_task()
        timestamp = int(time.time())
        
        # Créer un nouvel utilisateur
        register_data = {
            "nom": "Test",
            "prenom": "User",
            "mail": f"test{timestamp}@example.com",
            "username": f"testuser{timestamp}",
            "mdp": "TestPassword123!"
        }
        response = self.session.post(f"{self.base_url}/auth/register", json=register_data)
        self.assertEqual(response.status_code, 201)
        user_id = response.json()['user']['id_user']

        # Création droit
        droit_data = {
            "id_user": user_id,
            "id_tache": tache_id,
            "droit": 1
        }
        response = self.session.post(f"{self.base_url}/droits", json=droit_data)
        self.assertEqual(response.status_code, 201)
        droit_id = response.json()['id_droit']

        # Lecture droits
        response = self.session.get(f"{self.base_url}/droits")
        self.assertEqual(response.status_code, 200)

        # Mise à jour droit
        update_data = {"droit": 2}
        response = self.session.put(f"{self.base_url}/droits/{droit_id}", json=update_data)
        self.assertEqual(response.status_code, 200)

        # Suppression droit
        response = self.session.delete(f"{self.base_url}/droits/{droit_id}")
        self.assertEqual(response.status_code, 204) 
    
    def test_unassign_etiquette(self):
        tache_id = self.create_test_task()
        etiquette_data = {"description": f"Test {self.timestamp}"}
        response = self.session.post(f"{self.base_url}/etiquettes", json=etiquette_data)
        self.assertEqual(response.status_code, 201)
        etiquette_id = response.json()['id_etiquettes']
        
        response = self.session.delete(f"{self.base_url}/taches/{tache_id}/etiquettes/{etiquette_id}")
        self.assertEqual(response.status_code, 204)
        
    def test_commentaires_crud(self):
        """Test CRUD complet pour les commentaires"""
        tache_id = self.create_test_task()
        
        # Création
        commentaire_data = {"commentaire": f"Test {self.timestamp}"}
        response = self.session.post(f"{self.base_url}/taches/{tache_id}/commentaires", json=commentaire_data)
        self.assertEqual(response.status_code, 201)
        commentaire_id = response.json()['id_commentaire']
        
        # Lecture
        response = self.session.get(f"{self.base_url}/taches/{tache_id}/commentaires")
        self.assertEqual(response.status_code, 200)
        
        # Mise à jour
        update_data = {"commentaire": f"Test modifié {self.timestamp}"}
        response = self.session.put(f"{self.base_url}/commentaires/{commentaire_id}", json=update_data)
        self.assertEqual(response.status_code, 200)
        
        # Suppression
        response = self.session.delete(f"{self.base_url}/commentaires/{commentaire_id}")
        self.assertEqual(response.status_code, 204)
        
    def test_sous_taches_crud(self):
        """Test CRUD complet pour les sous-tâches"""
        tache_id = self.create_test_task()
        
        # Création avec toutes les données requises
        data = {
            "titre": f"Sous-tâche {self.timestamp}",
            "id_tache": tache_id,  # Ajout de l'ID de la tâche parent
            "priorite": 1,
            "statut": 0,
            "date_fin": datetime.utcnow().strftime('%Y-%m-%d')  # Format de date correct
        }
        response = self.session.post(f"{self.base_url}/taches/{tache_id}/sous-taches", json=data)
        self.assertEqual(response.status_code, 201)
        sous_tache_id = response.json()['id_sous_tache']
        
        # Lecture
        response = self.session.get(f"{self.base_url}/taches/{tache_id}/sous-taches")
        self.assertEqual(response.status_code, 200)
        
        # Mise à jour avec tous les champs requis
        update_data = {
            "titre": f"Sous-tâche modifiée {self.timestamp}",
            "priorite": 2,
            "statut": 1,
            "date_fin": datetime.utcnow().strftime('%Y-%m-%d')
        }
        response = self.session.put(f"{self.base_url}/sous-taches/{sous_tache_id}", json=update_data)
        self.assertEqual(response.status_code, 200)

        # Suppression
        response = self.session.delete(f"{self.base_url}/sous-taches/{sous_tache_id}")
        self.assertEqual(response.status_code, 204)
    
    def test_tache_user_crud(self):
        """Test complet de l'assignation/désassignation des tâches aux utilisateurs"""
        tache_id = self.create_test_task()
        timestamp = int(time.time())
        
        # Créer un utilisateur pour le test
        register_data = {
            "nom": "Test",
            "prenom": "User",
            "mail": f"test{timestamp}@example.com",
            "username": f"testuser{timestamp}",
            "mdp": "TestPassword123!"
        }
        response = self.session.post(f"{self.base_url}/auth/register", json=register_data)
        self.assertEqual(response.status_code, 201)
        user_id = response.json()['user']['id_user']

        # Assignation
        assign_data = {"user_id": user_id}
        response = self.session.post(f"{self.base_url}/taches/{tache_id}/assign", json=assign_data)
        self.assertEqual(response.status_code, 201)

        # Vérification des tâches assignées
        response = self.session.get(f"{self.base_url}/users/{user_id}/tasks")
        self.assertEqual(response.status_code, 200)
        
        # Désassignation
        response = self.session.delete(f"{self.base_url}/taches/{tache_id}/unassign/{user_id}")
        self.assertEqual(response.status_code, 204)
        
    # Modifiez la fonction test_invitations_crud comme suit
    def test_invitations_crud(self):
        """Test complet des invitations"""
        groupe_id = self.create_test_group()
        timestamp = int(time.time())
        
        # Créer un utilisateur pour l'invitation
        register_data = {
            "nom": "Test",
            "prenom": "Invite",
            "mail": f"invite{timestamp}@example.com",
            "username": f"invite{timestamp}",
            "mdp": "TestPassword123!"
        }
        response = self.session.post(f"{self.base_url}/auth/register", json=register_data)
        self.assertEqual(response.status_code, 201)
        user_id = response.json()['user']['id_user']
        
        # S'assurer d'être admin du groupe
        membre_data = {
            "id_user": self.test_data.get('user_id'),
            "role": "admin"
        }
        self.session.post(f"{self.base_url}/groupes/{groupe_id}/membres", json=membre_data)
        
        # Créer invitation
        invitation_data = {
            "id_groupe": groupe_id,
            "id_user": user_id
        }
        response = self.session.post(f"{self.base_url}/invitations", json=invitation_data)
        self.assertEqual(response.status_code, 201)
        invitation_id = response.json()['id_invitation']
        
        # Lire invitations
        response = self.session.get(f"{self.base_url}/invitations")
        self.assertEqual(response.status_code, 200)
    
    def test_membres_crud(self):
        """Test CRUD complet pour les membres"""
        # Créer un groupe en tant qu'admin
        groupe_id = self.create_test_group()
        timestamp = int(time.time())
        
        # Création d'un utilisateur pour le test
        register_data = {
            "nom": "Test",
            "prenom": "Membre",
            "mail": f"membre{timestamp}@example.com",
            "username": f"membre{timestamp}",
            "mdp": "TestPassword123!"
        }
        response = self.session.post(f"{self.base_url}/auth/register", json=register_data)
        self.assertEqual(response.status_code, 201)
        user_id = response.json()['user']['id_user']

        # Lecture des membres
        response = self.session.get(f"{self.base_url}/groupes/{groupe_id}/membres")
        self.assertEqual(response.status_code, 200)

        # Ajout d'un membre avec les champs requis
        membre_data = {
            "id_user": user_id,
            "role": "editeur"
        }
        response = self.session.post(f"{self.base_url}/groupes/{groupe_id}/membres", json=membre_data)
        self.assertEqual(response.status_code, 201)
    
if __name__ == '__main__':
    unittest.main(verbosity=2)