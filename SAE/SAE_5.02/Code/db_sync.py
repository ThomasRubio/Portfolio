import pymysql
from typing import Dict, List
from datetime import datetime
import logging

# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

class DatabaseSync:
    def __init__(self, host='mysql-db', user='todoux_user', password='root', db='todolist_db'):
        self.connection = pymysql.connect(
            host=host,
            user=user,
            password=password,
            db=db,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )
        self.cursor = self.connection.cursor()

    def create_tables(self):
        """Crée toutes les tables nécessaires"""
        print("Création des tables...")
        
        queries = [
            """CREATE TABLE IF NOT EXISTS SETTINGS (
                setting_key VARCHAR(50) PRIMARY KEY,
                setting_value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )""",
            
            """CREATE TABLE IF NOT EXISTS USER (
                id_user INT AUTO_INCREMENT PRIMARY KEY,
                nom VARCHAR(40) NOT NULL,
                prenom VARCHAR(40) NOT NULL,
                mail VARCHAR(120) NOT NULL,
                username VARCHAR(40) NOT NULL,
                mdp VARCHAR(120) NOT NULL,
                otp_enabled TINYINT(1) DEFAULT 0,
                otp_secret VARCHAR(32)
            )""",
            
            """CREATE TABLE IF NOT EXISTS GROUPE (
                id_groupe INT AUTO_INCREMENT PRIMARY KEY,
                nom VARCHAR(60) NOT NULL,
                synchro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                id_user INT,
                date_creation DATETIME DEFAULT CURRENT_TIMESTAMP,
                permissions INT DEFAULT 0,
                FOREIGN KEY (id_user) REFERENCES USER(id_user)
            )""",

            """CREATE TABLE IF NOT EXISTS DOSSIER (
                id_dossier INT AUTO_INCREMENT PRIMARY KEY,
                nom VARCHAR(60) NOT NULL,
                id_groupe INT,
                FOREIGN KEY (id_groupe) REFERENCES GROUPE(id_groupe) ON DELETE CASCADE
            )""",

            """CREATE TABLE IF NOT EXISTS TACHES (
                id_tache INT AUTO_INCREMENT PRIMARY KEY,
                titre VARCHAR(60) NOT NULL,
                sous_titre VARCHAR(60),
                texte VARCHAR(200),
                commentaire VARCHAR(200),
                date_debut TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                date_fin TIMESTAMP NULL,
                priorite INT,
                statut INT DEFAULT 0,
                id_dossier INT,
                id_user INT,
                FOREIGN KEY (id_dossier) REFERENCES DOSSIER(id_dossier) ON DELETE CASCADE,
                FOREIGN KEY (id_user) REFERENCES USER(id_user)
            )""",

            """CREATE TABLE IF NOT EXISTS DROIT (
                id_droit INT AUTO_INCREMENT PRIMARY KEY,
                id_user INT,
                id_tache INT,
                droit INT NOT NULL,
                FOREIGN KEY (id_user) REFERENCES USER(id_user),
                FOREIGN KEY (id_tache) REFERENCES TACHES(id_tache) ON DELETE CASCADE
            )""",

            """CREATE TABLE IF NOT EXISTS ETIQUETTES (
                id_etiquettes INT AUTO_INCREMENT PRIMARY KEY,
                description VARCHAR(300) NOT NULL
            )""",

            """CREATE TABLE IF NOT EXISTS TACHE_ETIQUETTE (
                id_tache INT,
                id_etiquettes INT,
                PRIMARY KEY (id_tache, id_etiquettes),
                FOREIGN KEY (id_tache) REFERENCES TACHES(id_tache) ON DELETE CASCADE,
                FOREIGN KEY (id_etiquettes) REFERENCES ETIQUETTES(id_etiquettes) ON DELETE CASCADE
            )""",

            """CREATE TABLE IF NOT EXISTS INVITATION (
                id_invitation INT AUTO_INCREMENT PRIMARY KEY,
                id_groupe INT,
                id_user INT,
                statut VARCHAR(20) DEFAULT 'En attente',
                FOREIGN KEY (id_groupe) REFERENCES GROUPE(id_groupe) ON DELETE CASCADE,
                FOREIGN KEY (id_user) REFERENCES USER(id_user) ON DELETE CASCADE
            )""",

            """CREATE TABLE IF NOT EXISTS MEMBRE (
                id_membre INT AUTO_INCREMENT PRIMARY KEY,
                id_groupe INT,
                id_user INT,
                role ENUM('admin', 'lecture', 'éditeur') DEFAULT 'lecture',
                FOREIGN KEY (id_groupe) REFERENCES GROUPE(id_groupe) ON DELETE CASCADE,
                FOREIGN KEY (id_user) REFERENCES USER(id_user) ON DELETE CASCADE
            )""",

            """CREATE TABLE IF NOT EXISTS HISTORIQUE (
                id_historique INT AUTO_INCREMENT PRIMARY KEY,
                id_tache INT,
                id_user INT,
                action VARCHAR(255),
                date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (id_tache) REFERENCES TACHES(id_tache) ON DELETE CASCADE,
                FOREIGN KEY (id_user) REFERENCES USER(id_user)
            )""",

            """CREATE TABLE IF NOT EXISTS SOUS_TACHES (
                id_sous_tache INT AUTO_INCREMENT PRIMARY KEY,
                id_tache INT,
                titre VARCHAR(255),
                priorite INT,
                date_fin DATE,
                statut INT,
                FOREIGN KEY (id_tache) REFERENCES TACHES(id_tache) ON DELETE CASCADE
            )""",

            """CREATE TABLE IF NOT EXISTS COMMENTAIRES (
                id_commentaire INT AUTO_INCREMENT PRIMARY KEY,
                id_tache INT,
                id_user INT,
                commentaire TEXT,
                date_commentaire TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (id_tache) REFERENCES TACHES(id_tache) ON DELETE CASCADE,
                FOREIGN KEY (id_user) REFERENCES USER(id_user) ON DELETE CASCADE
            )""",

            """CREATE TABLE IF NOT EXISTS GOOGLE_AGENDA (
                id_gagenda INT AUTO_INCREMENT PRIMARY KEY,
                google_id_cal VARCHAR(100),
                local_id_cal INT,
                FOREIGN KEY (local_id_cal) REFERENCES DOSSIER(id_dossier) ON DELETE CASCADE
            )""",

            """CREATE TABLE IF NOT EXISTS GOOGLE_TACHE (
                id_gtache INT AUTO_INCREMENT PRIMARY KEY,
                google_id_event VARCHAR(100),
                local_id_event INT,
                FOREIGN KEY (local_id_event) REFERENCES TACHES(id_tache) ON DELETE CASCADE
            )""",

            """CREATE TABLE IF NOT EXISTS TACHE_USER (
                id_tache INT NOT NULL,
                id_user INT NOT NULL,
                PRIMARY KEY (id_tache, id_user),
                FOREIGN KEY (id_tache) REFERENCES TACHES(id_tache) ON DELETE CASCADE,
                FOREIGN KEY (id_user) REFERENCES USER(id_user)
            )"""
        ]
        
        try:
            for query in queries:
                self.cursor.execute(query)
            self.connection.commit()
            print("✓ Tables créées avec succès")
        except Exception as e:
            print(f"❌ Erreur lors de la création des tables: {str(e)}")
            self.connection.rollback()

    def get_last_sync_date(self, table_name: str) -> datetime:
        """Récupère la dernière date de synchronisation d'une table"""
        try:
            query = "SELECT setting_value FROM SETTINGS WHERE setting_key = %s"
            self.cursor.execute(query, [f"last_sync_{table_name}"])
            result = self.cursor.fetchone()
            if result and result['setting_value']:
                return datetime.fromisoformat(result['setting_value'])
            return None
        except Exception as e:
            print(f"❌ Erreur lecture date sync {table_name}: {str(e)}")
            return None

    def get_max_date(self, table_name: str, date_field: str) -> datetime:
        """Récupère la date la plus récente d'une table"""
        try:
            query = f"SELECT MAX({date_field}) as max_date FROM {table_name}"
            self.cursor.execute(query)
            result = self.cursor.fetchone()
            return result['max_date'] if result and result['max_date'] else None
        except Exception as e:
            print(f"❌ Erreur lecture date max {table_name}: {str(e)}")
            return None

    def update_sync_date(self, table_name: str):
        """Met à jour la date de dernière synchronisation"""
        try:
            current_time = datetime.utcnow().isoformat()
            query = """
                INSERT INTO SETTINGS (setting_key, setting_value)
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE setting_value = %s
            """
            self.cursor.execute(query, [f"last_sync_{table_name}", current_time, current_time])
            self.connection.commit()
        except Exception as e:
            print(f"❌ Erreur mise à jour date sync {table_name}: {str(e)}")
            self.connection.rollback()

    def needs_sync(self, table_name: str, data: Dict) -> bool:
        """Détermine si une synchronisation est nécessaire"""
        if not data:
            return False
            
        # Correction des champs de date pour correspondre aux colonnes réelles
        date_fields = {
            'USER': None,  # La table USER n'a pas de champ date
            'GROUPE': 'date_creation', 
            'TACHES': 'date_debut',
            'COMMENTAIRES': 'date_commentaire',
            'HISTORIQUE': 'date'
        }
        
        # Si pas de champ de date défini pour la table, on sync toujours
        date_field = date_fields.get(table_name)
        if not date_field:
            return True
            
        try:
            # Récupérer la date la plus récente en local
            last_local_date = self.get_max_date(table_name, date_field)
            if not last_local_date:
                return True

            # Trouver la clé principale des données
            main_key = next((k for k in data.keys() 
                        if k != 'total' and 
                        not k.endswith('_total')), None)
            if not main_key:
                return False
                
            records = data[main_key]
            if not isinstance(records, list):
                records = [records]
                
            # Vérifier si des données sont plus récentes
            for record in records:
                if date_field in record:
                    try:
                        record_date = datetime.fromisoformat(str(record[date_field]).replace('Z', '+00:00'))
                        if record_date > last_local_date:
                            return True
                    except:
                        continue
                        
            return False
            
        except Exception as e:
            print(f"❌ Erreur vérification sync {table_name}: {str(e)}")
            return True  # En cas d'erreur, on force la synchronisation

    def sync_table(self, table_name: str, data: Dict, force_update=False):
        """Synchronise une table avec gestion de la suppression des données locales obsolètes"""
        try:
            if not force_update and not self.needs_sync(table_name, data):
                print(f"Pas de nouvelles données pour {table_name}")
                return

            cleaned_data = self.clean_data(data, table_name)
            if cleaned_data:
                records_count = len(cleaned_data)
                print(f"Synchronisation de {records_count} enregistrements pour {table_name}")
                
                # Désactive temporairement les contraintes pour l'insertion
                self.cursor.execute("SET FOREIGN_KEY_CHECKS = 0")
                
                try:
                    # 1. Récupérer les IDs présents dans l'API
                    api_ids = set()
                    primary_key = self._get_primary_key(table_name)
                    
                    # Gestion des clés primaires composites
                    if isinstance(primary_key, list):
                        # Pour les tables avec clés composites, on crée un tuple des valeurs des clés
                        api_ids = {
                            tuple(str(record[key]) for key in primary_key)
                            for record in cleaned_data
                            if all(key in record for key in primary_key)
                        }
                    else:
                        # Pour les tables avec clé simple
                        api_ids = {
                            str(record[primary_key])
                            for record in cleaned_data
                            if primary_key in record
                        }

                    # 2. Récupérer les IDs présents en local
                    if isinstance(primary_key, list):
                        # Pour les tables avec clés composites
                        query = f"SELECT {', '.join(primary_key)} FROM {table_name}"
                        self.cursor.execute(query)
                        local_ids = {
                            tuple(str(row[key]) for key in primary_key)
                            for row in self.cursor.fetchall()
                        }
                    else:
                        # Pour les tables avec clé simple
                        query = f"SELECT {primary_key} FROM {table_name}"
                        self.cursor.execute(query)
                        local_ids = {str(row[primary_key]) for row in self.cursor.fetchall()}

                    # 3. Identifier les enregistrements à supprimer
                    ids_to_delete = local_ids - api_ids
                    
                    # 4. Supprimer les enregistrements obsolètes
                    if ids_to_delete:
                        if isinstance(primary_key, list):
                            for id_tuple in ids_to_delete:
                                conditions = " AND ".join(
                                    f"{key} = %s" for key in primary_key
                                )
                                query = f"DELETE FROM {table_name} WHERE {conditions}"
                                self.cursor.execute(query, id_tuple)
                        else:
                            placeholders = ", ".join(["%s"] * len(ids_to_delete))
                            query = f"DELETE FROM {table_name} WHERE {primary_key} IN ({placeholders})"
                            self.cursor.execute(query, list(ids_to_delete))
                        
                        print(f"✓ {table_name}: {len(ids_to_delete)} enregistrements obsolètes supprimés")

                    # 5. Mettre à jour ou insérer les nouvelles données
                    self.upsert_data(table_name, {'data': cleaned_data})
                    self.update_sync_date(table_name)
                    print(f"✓ {table_name}: {records_count} enregistrements synchronisés")

                finally:
                    self.cursor.execute("SET FOREIGN_KEY_CHECKS = 1")

        except Exception as e:
            print(f"❌ Erreur synchronisation {table_name}: {str(e)}")
            self.connection.rollback()

    def truncate_all_tables(self, tables: List[str]):
        """Supprime toutes les données des tables avec gestion des CASCADE"""
        if self.has_been_cleaned():
            print("Tables déjà nettoyées précédemment, skip...")
            return

        print("\nSuppression des données existantes...")
        self.cursor.execute("SET FOREIGN_KEY_CHECKS = 0")

        # Ordre de suppression en respectant les CASCADE
        deletion_order = [
            'TACHE_USER',      # Tables de liaison en premier
            'TACHE_ETIQUETTE',
            'GOOGLE_TACHE',    # Tables dépendantes avec CASCADE
            'GOOGLE_AGENDA',
            'HISTORIQUE',
            'COMMENTAIRES',
            'SOUS_TACHES',
            'DROIT',
            'TACHES',         # Tables principales
            'DOSSIER',
            'MEMBRE',
            'INVITATION',
            'GROUPE',
            'ETIQUETTES',     # Tables indépendantes
            'USER'            # Table de base en dernier
        ]
        
        try:
            for table in deletion_order:
                print(f"Nettoyage de la table {table}...")
                self.cursor.execute(f"TRUNCATE TABLE {table}")
            
            self.connection.commit()
            self.mark_as_cleaned()
            print("✓ Nettoyage terminé.")
        except Exception as e:
            print(f"❌ Erreur lors du nettoyage: {str(e)}")
            self.connection.rollback()
        finally:
            self.cursor.execute("SET FOREIGN_KEY_CHECKS = 1")

    def get_last_user(self) -> str:
        """Récupère le dernier utilisateur connecté"""
        try:
            query = "SELECT setting_value FROM SETTINGS WHERE setting_key = 'last_user'"
            self.cursor.execute(query)
            result = self.cursor.fetchone()
            return result['setting_value'] if result else None
        except Exception as e:
            print(f"❌ Erreur lors de la lecture du dernier utilisateur: {str(e)}")
            return None
    
    def save_last_user(self, username: str):
        """Sauvegarde l'utilisateur qui vient de se connecter"""
        try:
            query = """
                INSERT INTO SETTINGS (setting_key, setting_value)
                VALUES ('last_user', %s)
                ON DUPLICATE KEY UPDATE setting_value = %s
            """
            self.cursor.execute(query, (username, username))
            self.connection.commit()
        except Exception as e:
            print(f"❌ Erreur lors de la sauvegarde du dernier utilisateur: {str(e)}")
            self.connection.rollback()
            
    def is_same_user(self, username: str) -> bool:
        """Vérifie si l'utilisateur est le même que le dernier connecté"""
        last_user = self.get_last_user()
        return last_user == username
    
    def _get_primary_key(self, table_name: str) -> str:
        """Récupère le nom de la clé primaire d'une table"""
        primary_keys = {
            'USER': 'id_user',
            'GROUPE': 'id_groupe',
            'DOSSIER': 'id_dossier',
            'TACHES': 'id_tache',
            'DROIT': 'id_droit',
            'ETIQUETTES': 'id_etiquettes',
            'INVITATION': 'id_invitation',
            'MEMBRE': 'id_membre',
            'HISTORIQUE': 'id_historique',
            'SOUS_TACHES': 'id_sous_tache',
            'COMMENTAIRES': 'id_commentaire',
            'GOOGLE_AGENDA': 'id_gagenda',
            'GOOGLE_TACHE': 'id_gtache',
            'TACHE_ETIQUETTE': ['id_tache', 'id_etiquettes'],  # Composite
            'TACHE_USER': ['id_tache', 'id_user']              # Composite
        }
        return primary_keys.get(table_name)
    
    def clean_record(self, record: Dict, table_name: str) -> Dict:
        """Nettoie et convertit un enregistrement API vers le format de la base de données"""
        table_mapping = {
            'USER': {
                'id_user': 'id_user',
                'username': 'username',
                'mail': 'mail',
                'nom': 'nom',
                'prenom': 'prenom',
                'mdp': 'mdp',
                'otp_enabled': 'otp_enabled',
                'otp_secret': 'otp_secret'
            },
            'GROUPE': {
                'id_groupe': 'id_groupe',
                'nom': 'nom',
                'id_user': 'id_user',
                'date_creation': 'date_creation',
                'permissions': 'permissions',
                'synchro': 'synchro'
            },
            'DOSSIER': {
                'id_dossier': 'id_dossier',
                'nom': 'nom',
                'id_groupe': 'id_groupe'
            },
            'TACHES': {
                'id_tache': 'id_tache',
                'titre': 'titre',
                'sous_titre': 'sous_titre',
                'texte': 'texte',
                'commentaire': 'commentaire',
                'date_debut': 'date_debut',
                'date_fin': 'date_fin',
                'priorite': 'priorite',
                'statut': 'statut',
                'id_dossier': 'id_dossier',
                'id_user': 'id_user'
            },
            'DROIT': {
                'id_droit': 'id_droit',
                'id_user': 'id_user',
                'id_tache': 'id_tache',
                'droit': 'droit'
            },
            'ETIQUETTES': {
                'id_etiquettes': 'id_etiquettes',
                'description': 'description'
            },
            'TACHE_ETIQUETTE': {
                'id_tache': 'id_tache',
                'id_etiquettes': 'id_etiquettes'
            },
            'INVITATION': {
                'id_invitation': 'id_invitation',
                'id_groupe': 'id_groupe',
                'id_user': 'id_user',
                'statut': 'statut'
            },
            'MEMBRE': {
                'id_membre': 'id_membre',
                'id_groupe': 'id_groupe',
                'id_user': 'id_user',
                'role': 'role'
            },
            'HISTORIQUE': {
                'id_historique': 'id_historique',
                'id_tache': 'id_tache',
                'id_user': 'id_user',
                'action': 'action',
                'date': 'date'
            },
            'SOUS_TACHES': {
                'id_sous_tache': 'id_sous_tache',
                'id_tache': 'id_tache',
                'titre': 'titre',
                'priorite': 'priorite',
                'date_fin': 'date_fin',
                'statut': 'statut'
            },
            'COMMENTAIRES': {
                'id_commentaire': 'id_commentaire',
                'id_tache': 'id_tache',
                'id_user': 'id_user',
                'commentaire': 'commentaire',
                'date_commentaire': 'date_commentaire'
            },
            'GOOGLE_AGENDA': {
                'id_gagenda': 'id_gagenda',
                'google_id_cal': 'google_id_cal',
                'local_id_cal': 'local_id_cal'
            },
            'GOOGLE_TACHE': {
                'id_gtache': 'id_gtache',
                'google_id_event': 'google_id_event',
                'local_id_event': 'local_id_event'
            },
            'TACHE_USER': {
                'id_tache': 'id_tache',
                'id_user': 'id_user'
            }
        }

        cleaned = {}
        mapping = table_mapping.get(table_name, {})
        
        # Si pas de mapping défini, retourner l'enregistrement tel quel
        if not mapping:
            return record

        for api_field, db_field in mapping.items():
            if api_field in record:
                value = record[api_field]
                
                # Conversion des dates
                if (db_field.endswith('_date') or
                    db_field in ['date_debut', 'date_fin', 'date_creation', 
                            'date_commentaire', 'date', 'synchro']):
                    if value and isinstance(value, str):
                        try:
                            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
                        except ValueError:
                            try:
                                # Essai d'autres formats de date courants
                                value = datetime.strptime(value, '%Y-%m-%d')
                            except ValueError:
                                value = None

                # Conversion des booléens pour MySQL
                elif isinstance(value, bool):
                    value = 1 if value else 0

                # Conversion des IDs en entiers
                elif db_field.startswith('id_') and value is not None:
                    try:
                        value = int(float(str(value).replace(',', '')))
                    except (ValueError, TypeError):
                        continue

                # Conversion des énums
                elif db_field == 'role' and table_name == 'MEMBRE':
                    if value not in ['admin', 'lecture', 'éditeur']:
                        value = 'lecture'  # Valeur par défaut

                # Conversion des statuts d'invitation
                elif db_field == 'statut' and table_name == 'INVITATION':
                    if value not in ['En attente', 'Acceptée', 'Refusée']:
                        value = 'En attente'  # Valeur par défaut

                cleaned[db_field] = value

        # Ajout du mot de passe placeholder pour les utilisateurs si nécessaire
        if table_name == 'USER' and 'mdp' not in cleaned:
            cleaned['mdp'] = 'placeholder'

        return cleaned

    def clean_data(self, data: Dict, table_name: str) -> list:
        """Nettoie les données pour l'insertion"""
        if not data:
            return []

        key = next((k for k in data.keys() 
                   if k != 'total' and 
                   not k.endswith('_total') and 
                   not k.endswith('_count')), None)
        
        if not key:
            print(f"❌ Aucune donnée trouvée pour {table_name}")
            return []
                
        records = data[key]
        if not isinstance(records, list):
            records = [records]

        clean_records = []
        for record in records:
            cleaned = self.clean_record(record, table_name)
            if self.validate_record(cleaned, table_name):
                clean_records.append(cleaned)
                
        print(f"✓ {len(clean_records)} enregistrements nettoyés pour {table_name}")
        return clean_records

    
    def validate_record(self, record: Dict, table_name: str) -> bool:
        """Valide qu'un enregistrement contient les champs requis"""
        required_fields = {
            'USER': ['id_user', 'username', 'mail', 'nom', 'prenom'],  # 'mdp' retiré des champs requis
            'GROUPE': ['id_groupe', 'nom', 'id_user'],
            'DOSSIER': ['id_dossier', 'nom', 'id_groupe'],
            'TACHES': ['id_tache', 'titre', 'id_dossier'],
            'DROIT': ['id_droit', 'id_user', 'id_tache', 'droit'],
            'ETIQUETTES': ['id_etiquettes', 'description'],
            'TACHE_ETIQUETTE': ['id_tache', 'id_etiquettes'],
            'INVITATION': ['id_invitation', 'id_groupe', 'id_user', 'statut'],
            'MEMBRE': ['id_membre', 'id_groupe', 'id_user', 'role'],
            'HISTORIQUE': ['id_historique', 'id_tache', 'id_user', 'action'],
            'SOUS_TACHES': ['id_sous_tache', 'id_tache', 'titre', 'statut'],
            'COMMENTAIRES': ['id_commentaire', 'id_tache', 'id_user', 'commentaire'],
            'GOOGLE_AGENDA': ['id_gagenda', 'google_id_cal', 'local_id_cal'],
            'GOOGLE_TACHE': ['id_gtache', 'google_id_event', 'local_id_event'],
            'TACHE_USER': ['id_tache', 'id_user']
        }

        enum_fields = {
            'MEMBRE': {
                'role': ['admin', 'lecture', 'éditeur']
            },
            'INVITATION': {
                'statut': ['En attente', 'Acceptée', 'Refusée']
            }
        }

        # Vérification des champs requis
        if table_name in required_fields:
            if not all(field in record for field in required_fields[table_name]):
                missing = [f for f in required_fields[table_name] if f not in record]
                print(f"❌ Champs manquants pour {table_name}: {missing}")
                return False

        # Cas spécial pour USER lors d'une synchronisation
        if table_name == 'USER' and 'mdp' not in record:
            record['mdp'] = 'placeholder'  # Valeur par défaut pour la synchro
            print(f"ℹ️ Ajout d'un mot de passe placeholder pour l'utilisateur {record.get('username', 'inconnu')}")

        # Vérification des enums
        if table_name in enum_fields:
            for field, valid_values in enum_fields[table_name].items():
                if field in record and record[field] not in valid_values:
                    print(f"❌ Valeur invalide pour {field} dans {table_name}: {record[field]}")
                    return False

        return True
    
    def upsert_data(self, table_name: str, data: Dict, retry=False):
        """Met à jour ou insère les données avec gestion des contraintes"""
        try:
            records = self.clean_data(data, table_name)
            if not records:
                return

            primary_key = self._get_primary_key(table_name)
            if not primary_key:
                print(f"❌ Impossible de trouver la clé primaire pour {table_name}")
                return

            # Gestion spéciale pour les tables avec clé composite
            if table_name in ['TACHE_USER', 'TACHE_ETIQUETTE']:
                for record in records:
                    keys = list(record.keys())
                    values = [record[col] for col in keys]
                    placeholders = ', '.join(['%s'] * len(keys))
                    
                    # ON DUPLICATE KEY UPDATE pour gérer les conflits
                    update_stmt = ", ".join([f"{col}=VALUES({col})" for col in keys])
                    
                    query = f"""
                        INSERT INTO {table_name} ({', '.join(keys)})
                        VALUES ({placeholders})
                        ON DUPLICATE KEY UPDATE {update_stmt}
                    """
                    
                    self.cursor.execute(query, values)
            else:
                # Pour les autres tables, utilisation normale de l'upsert
                for record in records:
                    columns = list(record.keys())
                    values = [record[col] for col in columns]
                    update_stmt = ", ".join([f"{col}=VALUES({col})" for col in columns if col != primary_key])
                    
                    query = f"""
                        INSERT INTO {table_name} ({', '.join(columns)})
                        VALUES ({', '.join(['%s'] * len(columns))})
                        ON DUPLICATE KEY UPDATE {update_stmt}
                    """
                    
                    self.cursor.execute(query, values)
            
            self.connection.commit()
            print(f"✓ {table_name}: {len(records)} enregistrements mis à jour/insérés")

        except Exception as e:
            self.connection.rollback()
            if not retry and "foreign key constraint fails" in str(e).lower():
                print(f"Réessai pour {table_name}...")
                self.upsert_data(table_name, data, retry=True)
            else:
                print(f"❌ Erreur lors de la mise à jour de {table_name}: {str(e)}")
    
    def has_been_cleaned(self) -> bool:
        """Vérifie si les tables ont déjà été nettoyées"""
        try:
            query = "SELECT setting_value FROM SETTINGS WHERE setting_key = 'tables_cleaned'"
            self.cursor.execute(query)
            result = self.cursor.fetchone()
            return bool(result and result['setting_value'] == '1')
        except Exception as e:
            print(f"❌ Erreur lors de la vérification du nettoyage: {str(e)}")
            return False
    
    def mark_as_cleaned(self):
        """Marque les tables comme nettoyées"""
        try:
            query = """
                INSERT INTO SETTINGS (setting_key, setting_value)
                VALUES ('tables_cleaned', '1')
                ON DUPLICATE KEY UPDATE setting_value = '1'
            """
            self.cursor.execute(query)
            self.connection.commit()
        except Exception as e:
            print(f"❌ Erreur lors du marquage du nettoyage: {str(e)}")
            self.connection.rollback()

    def close(self):
        """Ferme la connexion à la base de données"""
        self.cursor.close()
        self.connection.close()
