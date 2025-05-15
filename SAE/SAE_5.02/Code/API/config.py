from dotenv import load_dotenv
import os
import pymysql
import multiprocessing  # Ajout de cet import

# Installer PyMySQL comme pilote MySQL
pymysql.install_as_MySQLdb()

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'votre_clé_secrète')

    # Construction de l'URL avec PyMySQL
    db_url = os.getenv('DATABASE_URL', 'mysql://user:password@localhost/todolist_db')
    if not db_url.startswith('mysql+pymysql://'):
        db_url = db_url.replace('mysql://', 'mysql+pymysql://')

    SQLALCHEMY_DATABASE_URI = db_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Options de connexion optimisées
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,
        'max_overflow': 20,
        'pool_timeout': 30,
        'pool_recycle': 1800,
        'pool_pre_ping': True,
        'connect_args': {
            'connect_timeout': 10,
            'read_timeout': 30,
            'write_timeout': 30
        }
    }

    # Configuration Gunicorn
    WORKERS = int(os.getenv('GUNICORN_WORKERS', multiprocessing.cpu_count() * 2 + 1))
    THREADS = int(os.getenv('GUNICORN_THREADS', '2'))
    TIMEOUT = int(os.getenv('GUNICORN_TIMEOUT', '120'))