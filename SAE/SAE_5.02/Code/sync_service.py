import time
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Optional
from datetime import datetime
from api_client import TodoListAPIClient
from db_sync import DatabaseSync

class SyncService:
    def __init__(self, interval: int = 30):
        self.interval = interval
        self.running = False
        self.current_thread: Optional[Future] = None
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.username = None
        self.password = None

    def sync_data(self):
        start_time = datetime.now()
        print(f"Sync started at {start_time}")

        try:
            api_client = TodoListAPIClient()
            db = DatabaseSync()

            if not self.username or not self.password:
                raise Exception("Credentials manquants")

            # Vérifier les dépendances avant de commencer
            if not api_client.verify_dependencies():
                raise Exception("Erreur dans l'ordre des dépendances")

            # Création des tables si nécessaire
            db.create_tables()
            
            # Connexion à l'API
            if not api_client.login(self.username, self.password):
                raise Exception("Échec de connexion à l'API")

            # Vérification du changement d'utilisateur
            should_reset = not db.is_same_user(self.username)
            if should_reset:
                # Nettoyer dans l'ordre inverse pour respecter les contraintes
                reversed_tables = api_client.tables.copy()
                reversed_tables.reverse()
                db.truncate_all_tables(reversed_tables)

            # Synchronisation dans l'ordre des dépendances
            for table in api_client.tables:
                if not self.running:
                    break
                    
                data = api_client.export_table(table)
                
                if data:
                    try:
                        # Force la synchronisation complète si c'est un nouvel utilisateur
                        db.sync_table(table, data, force_update=should_reset)
                        
                        # Attendre que les dépendances soient bien synchronisées
                        time.sleep(1)
                        
                    except Exception as e:
                        if "foreign key constraint" in str(e).lower():
                            # Continuer avec la table suivante
                            continue

            # Sauvegarde du dernier utilisateur
            db.save_last_user(self.username)

        except Exception as e:
            if 'db' in locals():
                db.connection.rollback()
        finally:
            if 'db' in locals():
                db.close()

        duration = datetime.now() - start_time
        print(f"Sync finished at {datetime.now()} (Duration: {duration})")

    def set_credentials(self, username: str, password: str):
        """Définit les credentials pour la synchronisation"""
        self.username = username
        self.password = password

    def _run_sync_loop(self):
        """Boucle principale de synchronisation"""
        while self.running:
            try:
                if not self.running:  # Vérification supplémentaire
                    break
                self.sync_data()
                
                # Vérifie régulièrement si on doit s'arrêter
                for _ in range(self.interval):
                    if not self.running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                if not self.running:  # Si on arrête pendant une erreur
                    break
                time.sleep(5)  # Attente plus courte en cas d'erreur

    def start(self):
        """Démarre le service de synchronisation"""
        if not self.running:
            self.running = True
            if self.executor._shutdown:
                self.executor = ThreadPoolExecutor(max_workers=1)
            self.current_thread = self.executor.submit(self._run_sync_loop)

    def stop(self):
        """Arrête proprement le service de synchronisation"""
        if self.running:
            self.running = False
            
            if self.current_thread:
                try:
                    # Attendre la fin de l'exécution actuelle
                    self.executor.shutdown(wait=True, cancel_futures=True)
                    self.current_thread = None
                except Exception as e:
                    pass
            
            # S'assurer que l'executor est fermé
            if not self.executor._shutdown:
                self.executor.shutdown(wait=True, cancel_futures=True)

    def restart(self):
        """Redémarre le service"""
        self.stop()
        time.sleep(1)  # Attente courte pour s'assurer de l'arrêt
        self.start()
    
    def __del__(self):
        """Destructeur pour s'assurer que tout est bien nettoyé"""
        self.stop()

if __name__ == "__main__":
    service = SyncService(interval=30)
    try:
        service.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        service.stop()
        print("\nService arrêté par l'utilisateur")
