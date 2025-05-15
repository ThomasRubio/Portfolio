from flask import Flask, request, jsonify, g, send_file
from functools import wraps
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException, BadRequest
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required,
    get_jwt_identity
)
import bcrypt
import re
import json
import pandas as pd
import io
from urllib.parse import urlparse
import pymysql
import logging
import os
import csv
import traceback
from datetime import datetime, timedelta
import logging
import sys
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import text, and_, or_ 
import functools
from werkzeug.middleware.proxy_fix import ProxyFix
from config import Config
from models import (
    db, User, Groupe, Dossier, Tache, Droit,
    Etiquette, Invitation, Membre, Historique,
    SousTache, Commentaire, GoogleAgenda, GoogleTache, TacheUser
)
from schemas import (
    ma, UserSchema, GroupeSchema, DossierSchema, TacheSchema,
    DroitSchema, EtiquetteSchema, InvitationSchema, MembreSchema,
    HistoriqueSchema, SousTacheSchema, CommentaireSchema,
    user_schema, users_schema, groupe_schema, groupes_schema,
    dossier_schema, dossiers_schema, tache_schema, taches_schema,
    droit_schema, droits_schema, etiquette_schema, etiquettes_schema,
    invitation_schema, invitations_schema, membre_schema, membres_schema,
    historique_schema, historiques_schema, sous_tache_schema, sous_taches_schema,
    commentaire_schema, commentaires_schema, google_agenda_schema, google_agendas_schema,
    google_tache_schema, google_taches_schema
)
from security import (
    validate_schema, validate_id, SecurityMiddleware,
    sanitize_input, sql_injection_check, rate_limit,
    require_permissions, check_permissions
)

# Configuration du logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/todolist/error.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('todolist')

# Création de l'application Flask
app = Flask(__name__)
app.config.from_object(Config)

# Support for proxy headers
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Application du middleware de sécurité
app.wsgi_app = SecurityMiddleware(app.wsgi_app)

# Initialize extensions
db.init_app(app)
ma.init_app(app)
jwt = JWTManager(app)

# Initialisation de CORS
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:3000"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

# Initialisation du rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per minute"],
    storage_uri="memory://",
    storage_options={"ignore_errors": True},
    strategy="fixed-window"
)

# Création des tables au démarrage
with app.app_context():
    try:
        db.create_all()
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Error creating tables: {str(e)}")

@app.errorhandler(BadRequest)
def handle_bad_request(e):
    return jsonify({
        "error": "Bad request",
        "message": "Invalid JSON format"
    }), 400

def get_connection():
    """
    Établit et retourne une connexion à la base de données MySQL en utilisant l'URL de la base de données.
    
    Returns:
        pymysql.Connection: Objet de connexion à la base de données
        
    Raises:
        pymysql.Error: En cas d'échec de connexion
    """
    try:
        # Parse DATABASE_URL
        db_url = os.getenv('DATABASE_URL')
        if not db_url:
            raise ValueError("DATABASE_URL not found in environment variables")
            
        url = urlparse(db_url)
        
        # Extraire les informations de connexion
        db_user = url.username
        db_password = url.password
        db_host = url.hostname
        db_name = url.path.strip('/')
        
        # Établir la connexion
        connection = pymysql.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database=db_name,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor,
            ssl={'ssl': True}  # Ajout du SSL pour AWS RDS
        )
        
        return connection
        
    except pymysql.Error as e:
        logger.error(f"Database connection error: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error while connecting to database: {str(e)}")
        raise

def is_valid_email(email):
    """
    Vérifie si une adresse email est valide.
    
    Args:
        email (str): Email à valider
        
    Returns:
        bool: True si l'email est valide, False sinon
    """
    # Regex pour la validation d'email
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    # Vérifications supplémentaires
    try:
        # Vérifier le format avec regex
        if not re.match(pattern, email):
            return False
            
        # Vérifier la longueur
        if len(email) > 254:
            return False
            
        # Vérifier la partie locale
        local_part = email.split('@')[0]
        if len(local_part) > 64:
            return False
            
        return True
        
    except Exception:
        return False
    
# Décorateurs personnalisés
def handle_db_errors(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error in {f.__name__}: {str(e)}")
            return jsonify({'error': 'Database error occurred'}), 500
        except Exception as e:
            logger.error(f"Unexpected error in {f.__name__}: {str(e)}")
            return jsonify({'error': 'An unexpected error occurred'}), 500
    return decorated_function

def log_activity(action):
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                result = f(*args, **kwargs)
                if isinstance(result, tuple):
                    response, status_code = result
                else:
                    response, status_code = result, 200

                if 200 <= status_code < 300:
                    user_id = get_jwt_identity()
                    new_log = Historique(
                        id_user=user_id,
                        action=action,
                        date=datetime.utcnow()
                    )
                    db.session.add(new_log)
                    db.session.commit()

                return result
            except Exception as e:
                logger.error(f"Error logging activity: {str(e)}")
                return result
        return decorated_function
    return decorator

def validate_json():
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method in ['POST', 'PUT']:
                if not request.is_json:
                    return jsonify({'error': 'Content-Type must be application/json'}), 415
                try:
                    request.get_json()
                except BadRequest:
                    return jsonify({
                        "error": "Bad request",
                        "message": "Invalid JSON format"
                    }), 400
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_data(data, required_fields):
    if not data:
        return False
    return all(field in data for field in required_fields)

def handle_exceptions(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error: {str(e)}")
            return jsonify({'error': 'Database error'}), 500
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return jsonify({'error': 'Internal server error'}), 500
    return wrapper

def create_response(data=None, message=None, status=200):
    response = {}
    if data is not None:
        response['data'] = data
    if message is not None:
        response['message'] = message
    return jsonify(response), status

# JWT configuration and error handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'status': 401,
        'sub_status': 42,
        'msg': 'Le token a expiré'
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        'status': 401,
        'sub_status': 43,
        'msg': 'Token invalide'
    }), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        'status': 401,
        'sub_status': 44,
        'msg': 'Token manquant'
    }), 401

@jwt.needs_fresh_token_loader
def token_not_fresh_callback(jwt_header, jwt_payload):
    return jsonify({
        'status': 401,
        'sub_status': 45,
        'msg': 'Token non actualisé'
    }), 401

# Context Processors
@app.before_request
def before_request():
    g.start = datetime.utcnow()

@app.after_request
def after_request(response):
    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    # Add timing header in debug mode
    if app.debug:
        duration = datetime.utcnow() - g.start
        response.headers['X-Execution-Time'] = str(duration.total_seconds())

    return response

# Fonction utilitaire pour valider le format d'un fichier
def allowed_file(filename):
    """
    Vérifie si l'extension du fichier est autorisée.
    
    Args:
        filename (str): Nom du fichier à vérifier
        
    Returns:
        bool: True si l'extension est autorisée, False sinon
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'csv', 'xlsx', 'xls'}

def import_table_data_api(table_name, headers, rows):
    """
    Fonction utilitaire pour importer les données d'une table spécifique.
    Gère la validation des données et l'insertion dans la base de données.
    
    Args:
        table_name (str): Nom de la table
        headers (list): Liste des noms de colonnes
        rows (list): Liste des lignes de données
        
    Returns:
        dict: Résultat de l'importation avec statut et message
    """
    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            # Désactiver temporairement les contraintes de clés étrangères
            cursor.execute("SET FOREIGN_KEY_CHECKS = 0")
            
            # Nettoyer la table existante
            cursor.execute(f"DELETE FROM {table_name}")
            
            # Préparer la requête d'insertion
            placeholders = ', '.join(['%s'] * len(headers))
            query = f"INSERT INTO {table_name} ({', '.join(headers)}) VALUES ({placeholders})"
            
            # Insérer les données ligne par ligne
            for row in rows:
                # Gérer les valeurs NULL
                cleaned_row = [None if val == '' else val for val in row]
                cursor.execute(query, cleaned_row)
            
            # Réactiver les contraintes
            cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
            
            connection.commit()
            return {
                'success': True,
                'message': f'Import réussi pour la table {table_name}'
            }

    except Exception as e:
        connection.rollback()
        logger.error(f"Error importing data for table {table_name}: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }
        
    finally:
        connection.close()

def validate_import_data(table_name, headers, rows):
    """
    Valide les données avant importation.
    
    Args:
        table_name (str): Nom de la table
        headers (list): Liste des noms de colonnes
        rows (list): Liste des lignes de données
        
    Returns:
        tuple: (bool, str) - Validité et message d'erreur
    """
    # Vérifier si tous les headers requis sont présents
    required_headers = get_required_headers(table_name)
    missing_headers = [h for h in required_headers if h not in headers]
    if missing_headers:
        return False, f"Colonnes manquantes pour {table_name}: {', '.join(missing_headers)}"

    # Vérifier la cohérence des données
    for row_idx, row in enumerate(rows, 1):
        if len(row) != len(headers):
            return False, f"Nombre de colonnes incorrect à la ligne {row_idx}"
            
        # Validation spécifique selon le type de table
        if table_name == 'USER':
            if not is_valid_email(row[headers.index('mail')]):
                return False, f"Email invalide à la ligne {row_idx}"
                
    return True, "Données valides"

def get_required_headers(table_name):
    """
    Retourne les colonnes requises pour chaque table.
    
    Args:
        table_name (str): Nom de la table
        
    Returns:
        list: Liste des colonnes requises
    """
    required_headers = {
        'USER': ['username', 'mdp', 'mail', 'nom', 'prenom'],
        'GROUPE': ['nom', 'id_user'],
        'DOSSIER': ['nom', 'id_groupe'],
        'TACHES': ['titre', 'id_dossier', 'id_user'],
        'DROIT': ['id_user', 'id_tache', 'droit'],
        'ETIQUETTES': ['description'],
        'INVITATION': ['id_groupe', 'id_user', 'statut'],
        'MEMBRE': ['id_groupe', 'id_user', 'role'],
        'HISTORIQUE': ['id_user', 'action', 'date'],
        'SOUS_TACHES': ['id_tache', 'titre'],
        'COMMENTAIRES': ['id_tache', 'id_user', 'commentaire', 'date_commentaire'],
        'GOOGLE_AGENDA': ['google_id_cal', 'local_id_cal'],
        'GOOGLE_TACHE': ['google_id_event', 'local_id_event']
    }
    return required_headers.get(table_name, [])

def parse_csv_file(file_content):
    """
    Parse un fichier CSV avec gestion des sections.
    
    Args:
        file_content (str): Contenu du fichier CSV
        
    Returns:
        dict: Données parsées par table
    """
    result = {}
    current_table = None
    headers = None
    rows = []
    
    reader = csv.reader(file_content.splitlines())
    for row in reader:
        if not row:
            continue
            
        if row[0].startswith("TABLE:"):
            if current_table and headers:
                result[current_table] = {
                    'headers': headers,
                    'rows': rows
                }
            current_table = row[0].split(":")[1].strip()
            headers = next(reader)
            rows = []
        else:
            rows.append(row)
            
    if current_table and headers:
        result[current_table] = {
            'headers': headers,
            'rows': rows
        }
        
    return result

def parse_excel_file(file):
    """
    Parse un fichier Excel.
    
    Args:
        file: Fichier Excel à parser
        
    Returns:
        dict: Données parsées par feuille/table
    """
    result = {}
    df_dict = pd.read_excel(file, sheet_name=None)
    
    for sheet_name, df in df_dict.items():
        table_name = sheet_name.strip()
        if not table_name:
            continue
            
        headers = df.columns.tolist()
        rows = df.values.tolist()
        
        result[table_name] = {
            'headers': headers,
            'rows': rows
        }
        
    return result

def clean_import_data(data):
    """
    Nettoie et valide les données avant import.
    
    Args:
        data (dict): Données à nettoyer
        
    Returns:
        dict: Données nettoyées
    """
    cleaned_data = {}
    
    for table_name, table_data in data.items():
        headers = table_data['headers']
        rows = table_data['rows']
        
        # Nettoyer les en-têtes
        clean_headers = [h.strip().lower() for h in headers]
        
        # Nettoyer les lignes
        clean_rows = []
        for row in rows:
            clean_row = []
            for val in row:
                if isinstance(val, str):
                    val = val.strip()
                if val == '':
                    val = None
                clean_row.append(val)
            clean_rows.append(clean_row)
            
        cleaned_data[table_name] = {
            'headers': clean_headers,
            'rows': clean_rows
        }
        
    return cleaned_data

# Routes d'authentification
@app.route('/auth/register', methods=['POST'])
@limiter.limit("10 per minute")  # Augmenté de 3 à 10
def register():
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400

        data = request.get_json()
        if not data or not all(k in data for k in ['username', 'mdp', 'mail', 'nom', 'prenom']):
            return jsonify({'error': 'Missing required fields'}), 400

        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'Username already exists'}), 400

        if User.query.filter_by(mail=data['mail']).first():
            return jsonify({'error': 'Email already exists'}), 400

        hashed_password = bcrypt.hashpw(
            data['mdp'].encode('utf-8'),
            bcrypt.gensalt()
        )

        new_user = User(
            username=data['username'],
            mdp=hashed_password.decode('utf-8'),
            mail=data['mail'].lower(),
            nom=data['nom'],
            prenom=data['prenom']
        )

        db.session.add(new_user)
        db.session.flush()

        access_token = create_access_token(
            identity=new_user.id_user,
            expires_delta=timedelta(days=1)
        )

        historique = Historique(
            id_user=new_user.id_user,
            action="Création du compte",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        db.session.commit()

        return jsonify({
            'message': 'Utilisateur créé avec succès',
            'token': access_token,
            'user': user_schema.dump(new_user)
        }), 201

    except Exception as e:
        print(f"Register error: {str(e)}\n{traceback.format_exc()}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Gestionnaires d'erreur
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": "Rate limit exceeded",
        "message": str(e.description)
    }), 429

@app.errorhandler(400)
def bad_request(e):
    return jsonify({
        "error": "Bad request",
        "message": str(e.description)
    }), 400

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({
        "error": "Method not allowed",
        "message": str(e.description)
    }), 405

@app.errorhandler(Exception)
def handle_error(error):
    """Gestionnaire d'erreur global amélioré"""
    if isinstance(error, BadRequest):
        return jsonify({
            "error": "Bad request",
            "message": "Invalid JSON format"
        }), 400
        
    logger.error(f"Unhandled error: {str(error)}", exc_info=True)

    response = {
        'error': "Une erreur interne est survenue",
        'type': error.__class__.__name__
    }

    if app.debug:
        response['detail'] = str(error)
        import traceback
        response['traceback'] = traceback.format_exc()

    return jsonify(response), 500

@app.route('/auth/login', methods=['POST'])
@limiter.limit("10 per minute")  # Augmenté de 5 à 10
def login():
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400

        data = request.get_json()
        if not data or 'username' not in data or 'mdp' not in data:
            return jsonify({'error': 'Missing username or password'}), 400

        user = User.query.filter_by(username=data['username']).first()

        if user and bcrypt.checkpw(
            data['mdp'].encode('utf-8'),
            user.mdp.encode('utf-8')
        ):
            access_token = create_access_token(
                identity=user.id_user,
                expires_delta=timedelta(days=1)
            )

            historique = Historique(
                id_user=user.id_user,
                action="Connexion réussie",
                date=datetime.utcnow()
            )
            db.session.add(historique)
            db.session.commit()

            return jsonify({
                'token': access_token,
                'user': user_schema.dump(user)
            }), 200

        return jsonify({'message': 'Identifiants invalides'}), 401

    except Exception as e:
        print(f"Login error: {str(e)}\n{traceback.format_exc()}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/auth/refresh', methods=['POST'])
@jwt_required()  # Changé de @jwt_required(refresh=True)
def refresh_token():
    try:
        current_user_id = get_jwt_identity()
        if not current_user_id:
            return jsonify({'error': 'Invalid token'}), 401

        new_token = create_access_token(
            identity=current_user_id,
            expires_delta=timedelta(days=1)
        )

        return jsonify({'token': new_token}), 200

    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': 'Token refresh failed'}), 401

@app.route('/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    user_id = get_jwt_identity()
    try:
        historique = Historique(
            id_user=user_id,
            action="Déconnexion",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        db.session.commit()

        # Note: With JWT, we can't actually invalidate the token
        # Client side should delete the token
        return jsonify({'message': 'Déconnexion réussie'}), 200
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({'error': 'Une erreur est survenue lors de la déconnexion'}), 500

# Routes de gestion des utilisateurs
@app.route('/users/me', methods=['GET'])
@jwt_required()
@handle_db_errors
def get_current_user():
    current_user_id = get_jwt_identity()
    user = User.query.get_or_404(current_user_id)
    return jsonify(user_schema.dump(user)), 200

@app.route('/users', methods=['GET'])
@jwt_required()
@handle_db_errors
def get_users():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 10, type=int), 100)
        
        users = User.query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        return jsonify({
            'users': users_schema.dump(users.items),
            'total': users.total,
            'pages': users.pages,
            'current_page': users.page
        }), 200
    except Exception as e:
        logger.error(f"Error fetching users: {str(e)}")
        return jsonify({'error': 'Error fetching users'}), 500

@app.route('/invitations/<int:invitation_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
@handle_db_errors
def manage_invitation(invitation_id):
    user_id = get_jwt_identity()
    invitation = Invitation.query.get_or_404(invitation_id)
        
    # Vérification des permissions
    if invitation.id_user != user_id:
        groupe = Groupe.query.get(invitation.id_groupe)
        if groupe.id_user != user_id:
            membre = Membre.query.filter_by(
                id_groupe=invitation.id_groupe,
                id_user=user_id,
                role='admin'
            ).first()
            if not membre:
                return jsonify({'error': 'Permission refusée'}), 403

    if request.method == 'GET':
        return jsonify(invitation_schema.dump(invitation)), 200
            
    elif request.method == 'PUT':
        try:
            data = request.get_json()
            if not data or 'statut' not in data:
                return jsonify({'error': 'Statut requis'}), 400

            invitation.statut = data['statut']

            if data['statut'] == 'Acceptée':
                # Vérifier si le membre existe déjà
                existing_membre = Membre.query.filter_by(
                    id_groupe=invitation.id_groupe,
                    id_user=invitation.id_user
                ).first()
                
                if not existing_membre:
                    new_membre = Membre(
                        id_groupe=invitation.id_groupe,
                        id_user=invitation.id_user,
                        role='lecture'
                    )
                    db.session.add(new_membre)

            historique = Historique(
                id_user=user_id,
                action=f"Réponse à l'invitation pour le groupe {invitation.groupe.nom}: {data['statut']}",
                date=datetime.utcnow()
            )
            db.session.add(historique)
            db.session.commit()
            return jsonify(invitation_schema.dump(invitation)), 200
            
        except SQLAlchemyError as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    else:  # DELETE
        try:
            db.session.delete(invitation)
            
            historique = Historique(
                id_user=user_id,
                action=f"Suppression de l'invitation pour le groupe {invitation.groupe.nom}",
                date=datetime.utcnow()
            )
            db.session.add(historique)
            db.session.commit()
            return '', 204
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

@app.route('/users/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
@handle_db_errors
def manage_user(user_id):
    if not validate_id(user_id):
        return jsonify({'error': 'ID invalide'}), 400

    current_user_id = get_jwt_identity()
    user = User.query.get_or_404(user_id)

    # Vérification des permissions
    if current_user_id != user_id and not check_permissions(current_user_id, 'admin'):
        return jsonify({'error': 'Permission refusée'}), 403

    if request.method == 'GET':
        return jsonify(user_schema.dump(user)), 200

    elif request.method == 'PUT':
        data = request.get_json()

        # Validation des données
        if not validate_schema('user_update')(lambda: None)():
            return jsonify({'error': 'Données invalides'}), 400

        # Mise à jour du mot de passe si fourni
        if 'mdp' in data:
            if not validate_password(data['mdp']):
                return jsonify({'error': 'Mot de passe invalide'}), 400
            data['mdp'] = bcrypt.hashpw(
                data['mdp'].encode('utf-8'),
                bcrypt.gensalt()
            ).decode('utf-8')

        # Mise à jour des champs
        for key, value in data.items():
            if hasattr(user, key) and key != 'id_user':
                setattr(user, key, sanitize_input(value))

        historique = Historique(
            id_user=current_user_id,
            action=f"Mise à jour du profil utilisateur {user_id}",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        db.session.commit()

        return jsonify(user_schema.dump(user)), 200

    else:  # DELETE
        if current_user_id != user_id and not check_permissions(current_user_id, 'admin'):
            return jsonify({'error': 'Permission refusée'}), 403

        historique = Historique(
            id_user=current_user_id,
            action=f"Suppression du compte utilisateur {user_id}",
            date=datetime.utcnow()
        )
        db.session.add(historique)

        db.session.delete(user)
        db.session.commit()

        return '', 204

# Fonctions utilitaires
def validate_password(password):
    """Valide la complexité du mot de passe"""
    if len(password) < 8:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    if not any(c in '!@#$%^&*(),.?":{}|<>' for c in password):
        return False
    return True

def log_failed_login_attempt(user_id, reason):
    """Enregistre une tentative de connexion échouée"""
    try:
        historique = Historique(
            id_user=user_id,
            action=f"Tentative de connexion échouée: {reason}",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        db.session.commit()
    except Exception as e:
        logger.error(f"Error logging failed login attempt: {str(e)}")

# Routes pour les groupes
@app.route('/groupes', methods=['GET'])
@jwt_required()
@handle_db_errors
def get_groupes():
    user_id = get_jwt_identity()
    try:
        # Récupérer les groupes dont l'utilisateur est propriétaire
        owned_groups = Groupe.query.filter_by(id_user=user_id).all()

        # Récupérer les groupes dont l'utilisateur est membre
        member_groups = (Groupe.query
                        .join(Membre)
                        .filter(Membre.id_user == user_id)
                        .all())

        # Combiner et dédupliquer les résultats
        all_groups = list(set(owned_groups + member_groups))

        return jsonify(groupes_schema.dump(all_groups)), 200
    except Exception as e:
        logger.error(f"Error fetching groups: {str(e)}")
        return jsonify({'error': 'Erreur lors de la récupération des groupes'}), 500

@app.route('/groupes', methods=['POST'])
@jwt_required()
def create_groupe():
    try:
        user_id = get_jwt_identity()
        if not user_id:
            print("No user_id from token")
            return jsonify({'error': 'Invalid token'}), 401

        if not request.is_json:
            print("Request is not JSON")
            return jsonify({'error': 'Content-Type must be application/json'}), 400

        data = request.get_json()
        print(f"Received data for group creation: {data}")

        if not data or 'nom' not in data:
            print("Missing nom in data")
            return jsonify({'error': 'nom field is required'}), 400

        # Vérifier si un groupe avec le même nom existe déjà
        existing_groupe = Groupe.query.filter_by(
            id_user=user_id,
            nom=data['nom']
        ).first()

        if existing_groupe:
            print(f"Group already exists: {data['nom']}")
            return jsonify({
                'error': 'Un groupe avec ce nom existe déjà'
            }), 400

        new_groupe = Groupe(
            nom=sanitize_input(data['nom']),
            id_user=user_id,
            date_creation=datetime.utcnow()
        )

        print(f"Creating new group: {new_groupe.nom}")
        db.session.add(new_groupe)
        db.session.flush()

        # Créer automatiquement un membre admin pour le créateur
        membre_admin = Membre(
            id_groupe=new_groupe.id_groupe,
            id_user=user_id,
            role='admin'
        )
        db.session.add(membre_admin)

        # Ajouter à l'historique
        historique = Historique(
            id_user=user_id,
            action=f"Création du groupe {new_groupe.nom}",
            date=datetime.utcnow()
        )
        db.session.add(historique)

        db.session.commit()
        print(f"Group created successfully: {new_groupe.id_groupe}")

        return jsonify({
            'id_groupe': new_groupe.id_groupe,
            'nom': new_groupe.nom,
            'date_creation': new_groupe.date_creation.isoformat(),
            'id_user': new_groupe.id_user
        }), 201

    except Exception as e:
        db.session.rollback()
        print(f"Error creating group: {str(e)}")
        print(traceback.format_exc())
        return jsonify({
            'error': 'Une erreur est survenue lors de la création du groupe',
            'details': str(e)
        }), 500

@app.route('/groupes/<int:groupe_id>', methods=['PUT'])
@jwt_required()
def update_groupe(groupe_id):
    try:
        user_id = get_jwt_identity()
        groupe = Groupe.query.get_or_404(groupe_id)

        # Vérification des permissions étendue
        has_permission = False
        if groupe.id_user == user_id:  # Propriétaire du groupe
            has_permission = True
        else:
            membre = Membre.query.filter_by(
                id_groupe=groupe_id,
                id_user=user_id,
                role='admin'
            ).first()
            if membre:
                has_permission = True

        if not has_permission:
            return jsonify({'error': 'Permission refusée'}), 403

        data = request.get_json()
        if not data or 'nom' not in data:
            return jsonify({'error': 'Données invalides'}), 400

        # Sanitize input
        nouveau_nom = sanitize_input(data['nom'])
        if not nouveau_nom:
            return jsonify({'error': 'Nom invalide'}), 400

        # Vérifier si le nouveau nom existe déjà
        existing = Groupe.query.filter(
            Groupe.nom == nouveau_nom,
            Groupe.id_groupe != groupe_id,
            Groupe.id_user == user_id
        ).first()
        if existing:
            return jsonify({'error': 'Un groupe avec ce nom existe déjà'}), 400

        groupe.nom = nouveau_nom
        
        # Ajouter à l'historique
        historique = Historique(
            id_user=user_id,
            action=f"Modification du nom du groupe de {groupe.nom} vers {nouveau_nom}",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        db.session.commit()

        return jsonify(groupe_schema.dump(groupe)), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating group: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/groupes/<int:groupe_id>', methods=['DELETE'])
@jwt_required()
@handle_db_errors
def delete_groupe(groupe_id):
    user_id = get_jwt_identity()
    groupe = Groupe.query.get_or_404(groupe_id)
    
    if groupe.id_user != user_id:
        return jsonify({'error': 'Permission refusée'}), 403
        
    nom = groupe.nom
    
    # La suppression en cascade gérera automatiquement toutes les dépendances
    db.session.delete(groupe)
    
    historique = Historique(
        id_user=user_id,
        action=f"Suppression du groupe {nom}",
        date=datetime.utcnow()
    )
    db.session.add(historique)
    db.session.commit()
    
    return '', 204

@app.route('/dossiers/<int:dossier_id>', methods=['DELETE'])
@jwt_required()
@handle_db_errors
def delete_dossier(dossier_id):
    try:
        user_id = get_jwt_identity()
        dossier = Dossier.query.get_or_404(dossier_id)
        groupe = Groupe.query.get(dossier.id_groupe)

        # Vérification des permissions améliorée
        has_permission = False
        if groupe.id_user == user_id:
            has_permission = True
        else:
            membre = Membre.query.filter_by(
                id_groupe=groupe.id_groupe,
                id_user=user_id,
                role='admin'
            ).first()
            if membre:
                has_permission = True

        if not has_permission:
            return jsonify({'error': 'Permission refusée'}), 403

        # Suppression des tâches associées
        Tache.query.filter_by(id_dossier=dossier_id).delete()

        # Suppression du dossier
        nom = dossier.nom
        db.session.delete(dossier)

        historique = Historique(
            id_user=user_id,
            action=f"Suppression du dossier {nom}",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        db.session.commit()

        return '', 204

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting folder: {str(e)}")
        return jsonify({'error': f"Erreur lors de la suppression du dossier: {str(e)}"}), 500

@app.route('/sous-taches/<int:sous_tache_id>', methods=['DELETE'])
@jwt_required()
@handle_db_errors
def delete_sous_tache(sous_tache_id):
    user_id = get_jwt_identity()
    sous_tache = SousTache.query.get_or_404(sous_tache_id)
    tache = Tache.query.get(sous_tache.id_tache)
    dossier = Dossier.query.get(tache.id_dossier)
    groupe = Groupe.query.get(dossier.id_groupe)

    if groupe.id_user != user_id:
        membre = Membre.query.filter_by(
            id_groupe=groupe.id_groupe,
            id_user=user_id,
            role='admin'
        ).first()
        if not membre:
            return jsonify({'error': 'Permission refusée'}), 403

    titre = sous_tache.titre
    tache_id = sous_tache.id_tache
    
    db.session.delete(sous_tache)

    historique = Historique(
        id_user=user_id,
        id_tache=tache_id,
        action=f"Suppression de la sous-tâche {titre}",
        date=datetime.utcnow()
    )
    db.session.add(historique)
    db.session.commit()

    return '', 204


@app.route('/invitations/<int:invitation_id>', methods=['DELETE'])
@jwt_required()
@handle_db_errors
def delete_invitation(invitation_id):
    user_id = get_jwt_identity()
    invitation = Invitation.query.get_or_404(invitation_id)
    groupe = Groupe.query.get(invitation.id_groupe)

    if groupe.id_user != user_id and invitation.id_user != user_id:
        membre = Membre.query.filter_by(
            id_groupe=invitation.id_groupe,
            id_user=user_id,
            role='admin'
        ).first()
        if not membre:
            return jsonify({'error': 'Permission refusée'}), 403

    db.session.delete(invitation)
    db.session.commit()
    return '', 204

@app.route('/groupes/<int:groupe_id>', methods=['DELETE'])
@jwt_required()
@handle_db_errors
def manage_groupe(groupe_id):
    user_id = get_jwt_identity()
    groupe = Groupe.query.get_or_404(groupe_id)

    if groupe.id_user != user_id:
        return jsonify({'error': 'Permission refusée'}), 403

    nom = groupe.nom
    
    # Suppression simple grâce à ON DELETE CASCADE
    db.session.delete(groupe)

    historique = Historique(
        id_user=user_id,
        action=f"Suppression du groupe {nom}",
        date=datetime.utcnow()
    )
    db.session.add(historique)
    db.session.commit()

    return '', 204

@app.route('/dossiers/<int:dossier_id>/taches', methods=['GET', 'POST'])
@jwt_required()
@handle_db_errors
def get_dossier_taches(dossier_id):
    try:
        user_id = get_jwt_identity()
        dossier = Dossier.query.get_or_404(dossier_id)
        groupe = Groupe.query.get(dossier.id_groupe)

        # Vérification des permissions
        has_permission = False
        if groupe.id_user == user_id:
            has_permission = True
        else:
            membre = Membre.query.filter_by(
                id_groupe=groupe.id_groupe,
                id_user=user_id
            ).first()
            if membre and membre.role in ['admin', 'éditeur']:
                has_permission = True

        if not has_permission:
            return jsonify({'error': 'Permission refusée'}), 403

        if request.method == 'GET':
            page = request.args.get('page', 1, type=int)
            per_page = min(request.args.get('per_page', 10, type=int), 100)
            statut = request.args.get('statut', type=int)
            priorite = request.args.get('priorite', type=int)

            query = Tache.query.filter_by(id_dossier=dossier_id)

            if statut is not None:
                query = query.filter_by(statut=statut)
            if priorite is not None:
                query = query.filter_by(priorite=priorite)

            sort_by = request.args.get('sort_by', 'date_creation')
            sort_order = request.args.get('sort_order', 'desc')

            if hasattr(Tache, sort_by):
                order_attr = getattr(Tache, sort_by)
                if sort_order == 'desc':
                    query = query.order_by(order_attr.desc())
                else:
                    query = query.order_by(order_attr.asc())

            taches_paginated = query.paginate(page=page, per_page=per_page, error_out=False)

            return jsonify({
                'taches': taches_schema.dump(taches_paginated.items),
                'total': taches_paginated.total,
                'pages': taches_paginated.pages,
                'current_page': taches_paginated.page
            }), 200

        else:  # POST
            if not has_permission:
                return jsonify({'error': 'Permission refusée'}), 403

            data = request.get_json()
            if not data or 'titre' not in data:
                return jsonify({'error': 'Titre requis'}), 400

            # Création de la tâche
            new_tache = Tache(
                titre=sanitize_input(data['titre']),
                sous_titre=sanitize_input(data.get('sous_titre')),
                texte=sanitize_input(data.get('texte')),
                date_debut=datetime.utcnow(),
                date_fin=data.get('date_fin'),
                priorite=data.get('priorite', 0),
                statut=data.get('statut', 0),
                id_dossier=dossier_id,
                id_user=user_id
            )

            db.session.add(new_tache)

            # Assignation des étiquettes
            if 'etiquettes' in data:
                for etiquette_id in data['etiquettes']:
                    etiquette = Etiquette.query.get(etiquette_id)
                    if etiquette:
                        new_tache.etiquettes.append(etiquette)

            # Assignation des utilisateurs
            if 'users' in data:
                for assigned_user_id in data['users']:
                    user = User.query.get(assigned_user_id)
                    if user:
                        new_tache.users.append(user)

            historique = Historique(
                id_user=user_id,
                action=f"Création de la tâche {new_tache.titre}",
                date=datetime.utcnow()
            )
            db.session.add(historique)
            db.session.commit()

            return jsonify(tache_schema.dump(new_tache)), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error managing tasks: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
# Routes pour les dossiers
@app.route('/groupes/<int:groupe_id>/dossiers', methods=['GET'])
@jwt_required()
@handle_db_errors
def get_dossiers(groupe_id):
    if not validate_id(groupe_id):
        return jsonify({'error': 'ID invalide'}), 400

    user_id = get_jwt_identity()
    groupe = Groupe.query.get_or_404(groupe_id)

    # Vérification des permissions
    if groupe.id_user != user_id:
        membre = Membre.query.filter_by(
            id_groupe=groupe_id,
            id_user=user_id
        ).first()
        if not membre:
            return jsonify({'error': 'Permission refusée'}), 403

    dossiers = Dossier.query.filter_by(id_groupe=groupe_id).all()
    return jsonify(dossiers_schema.dump(dossiers)), 200

@app.route('/groupes/<int:groupe_id>/dossiers', methods=['POST'])
@jwt_required()
def create_dossier(groupe_id):
    try:
        user_id = get_jwt_identity()

        # Vérifier que le groupe existe
        groupe = Groupe.query.get(groupe_id)
        if not groupe:
            return jsonify({'error': 'Groupe non trouvé'}), 404

        # Vérifier les permissions
        if groupe.id_user != user_id:
            membre = Membre.query.filter_by(
                id_groupe=groupe_id,
                id_user=user_id
            ).first()
            if not membre or membre.role not in ['admin', 'editeur']:
                return jsonify({'error': 'Permission refusée'}), 403

        # Valider les données
        data = request.get_json()
        if not data or 'nom' not in data:
            return jsonify({'error': 'Données invalides'}), 400

        # Créer le dossier
        new_dossier = Dossier(
            nom=sanitize_input(data['nom']),
            id_groupe=groupe_id
        )

        db.session.add(new_dossier)
        db.session.flush()

        # Créer l'historique
        historique = Historique(
            id_user=user_id,
            action=f"Création du dossier {new_dossier.nom}",
            date=datetime.utcnow()
        )
        db.session.add(historique)

        db.session.commit()

        return jsonify({
            'id_dossier': new_dossier.id_dossier,
            'nom': new_dossier.nom,
            'id_groupe': new_dossier.id_groupe
        }), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating folder: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500


@app.route('/dossiers/<int:dossier_id>', methods=['PUT'])
@jwt_required()
@handle_db_errors
def manage_dossier(dossier_id):
    if not validate_id(dossier_id):
        return jsonify({'error': 'ID invalide'}), 400

    user_id = get_jwt_identity()
    dossier = Dossier.query.get_or_404(dossier_id)
    groupe = Groupe.query.get(dossier.id_groupe)

    # Vérification des permissions
    if groupe.id_user != user_id:
        membre = Membre.query.filter_by(
            id_groupe=groupe.id_groupe,
            id_user=user_id,
            role='admin'
        ).first()
        if not membre:
            return jsonify({'error': 'Permission refusée'}), 403

    try:
        data = request.get_json()
        if not data or 'nom' not in data:
            return jsonify({'error': 'Nom du dossier requis'}), 400

        # Sanitize input properly
        new_nom = sanitize_input(data['nom'])
        if not new_nom:
            return jsonify({'error': 'Nom invalide après nettoyage'}), 400

        # Vérifier si le nouveau nom n'existe pas déjà
        existing = Dossier.query.filter(
            Dossier.nom == new_nom,
            Dossier.id_dossier != dossier_id,
            Dossier.id_groupe == dossier.id_groupe
        ).first()
        
        if existing:
            return jsonify({'error': 'Un dossier avec ce nom existe déjà'}), 400

        dossier.nom = new_nom
        db.session.commit()

        return jsonify({
            'id_dossier': dossier.id_dossier,
            'nom': dossier.nom,
            'id_groupe': dossier.id_groupe
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating folder: {str(e)}")
        return jsonify({'error': 'Erreur lors de la mise à jour du dossier'}), 500
    
# Routes pour les tâches
@app.route('/dossiers/<int:dossier_id>/taches', methods=['GET'])
@jwt_required()
@handle_db_errors
def get_taches(dossier_id):
    if not validate_id(dossier_id):
        return jsonify({'error': 'ID invalide'}), 400

    user_id = get_jwt_identity()
    dossier = Dossier.query.get_or_404(dossier_id)
    groupe = Groupe.query.get(dossier.id_groupe)

    # Vérification des permissions
    if groupe.id_user != user_id:
        membre = Membre.query.filter_by(
            id_groupe=groupe.id_groupe,
            id_user=user_id
        ).first()
        if not membre:
            return jsonify({'error': 'Permission refusée'}), 403

    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 10, type=int), 100)

    # Filtres
    statut = request.args.get('statut', type=int)
    priorite = request.args.get('priorite', type=int)

    query = Tache.query.filter_by(id_dossier=dossier_id)

    if statut is not None:
        query = query.filter_by(statut=statut)
    if priorite is not None:
        query = query.filter_by(priorite=priorite)

    # Tri
    sort_by = request.args.get('sort_by', 'date_creation')
    sort_order = request.args.get('sort_order', 'desc')

    if hasattr(Tache, sort_by):
        order_attr = getattr(Tache, sort_by)
        if sort_order == 'desc':
            query = query.order_by(order_attr.desc())
        else:
            query = query.order_by(order_attr.asc())

    taches_paginated = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        'taches': taches_schema.dump(taches_paginated.items),
        'total': taches_paginated.total,
        'pages': taches_paginated.pages,
        'current_page': taches_paginated.page
    }), 200

@app.route('/dossiers/<int:dossier_id>/taches', methods=['POST'])
@jwt_required()
@validate_schema('tache')
@validate_json()
@handle_db_errors
def create_tache(dossier_id):
    if not validate_id(dossier_id):
        return jsonify({'error': 'ID invalide'}), 400

    user_id = get_jwt_identity()
    dossier = Dossier.query.get_or_404(dossier_id)
    groupe = Groupe.query.get(dossier.id_groupe)

    # Vérification des permissions
    if groupe.id_user != user_id:
        membre = Membre.query.filter_by(
            id_groupe=groupe.id_groupe,
            id_user=user_id
        ).first()
        if not membre or membre.role not in ['admin', 'éditeur']:
            return jsonify({'error': 'Permission refusée'}), 403

    data = request.get_json()

    # Validation de la date de fin
    if 'date_fin' in data and data['date_fin']:
        try:
            date_fin = datetime.strptime(data['date_fin'], '%Y-%m-%dT%H:%M:%S')
            if date_fin < datetime.utcnow():
                return jsonify({'error': 'La date de fin ne peut pas être dans le passé'}), 400
        except ValueError:
            return jsonify({'error': 'Format de date invalide'}), 400

    new_tache = Tache(
        titre=sanitize_input(data['titre']),
        sous_titre=sanitize_input(data.get('sous_titre')),
        texte=sanitize_input(data.get('texte')),
        date_debut=datetime.utcnow(),
        date_fin=data.get('date_fin'),
        priorite=data.get('priorite', 0),
        statut=data.get('statut', 0),
        id_dossier=dossier_id,
        id_user=user_id
    )

    db.session.add(new_tache)

    # Assignation des étiquettes si fournies
    if 'etiquettes' in data:
        for etiquette_id in data['etiquettes']:
            etiquette = Etiquette.query.get(etiquette_id)
            if etiquette:
                new_tache.etiquettes.append(etiquette)

    # Assignation des utilisateurs si fournis
    if 'users' in data:
        for assigned_user_id in data['users']:
            user = User.query.get(assigned_user_id)
            if user:
                new_tache.users.append(user)

    historique = Historique(
        id_user=user_id,
        action=f"Création de la tâche {new_tache.titre}",
        date=datetime.utcnow()
    )
    db.session.add(historique)
    db.session.commit()

    return jsonify(tache_schema.dump(new_tache)), 201

# Modifiez cette route dans api.py
@app.route('/taches/<int:tache_id>/etiquettes/<int:etiquette_id>', methods=['POST', 'DELETE'])
@jwt_required()
@handle_db_errors
def manage_tache_etiquette(tache_id, etiquette_id):
    try:
        user_id = get_jwt_identity()
        
        # Récupérer la tâche et l'étiquette
        tache = Tache.query.get_or_404(tache_id)
        etiquette = Etiquette.query.get_or_404(etiquette_id)
        
        # Vérifier les permissions via le dossier et le groupe
        dossier = Dossier.query.get(tache.id_dossier)
        groupe = Groupe.query.get(dossier.id_groupe)
        
        # Vérifier les permissions
        has_permission = False
        if groupe.id_user == user_id:
            has_permission = True
        else:
            membre = Membre.query.filter_by(
                id_groupe=groupe.id_groupe,
                id_user=user_id
            ).first()
            if membre and membre.role in ['admin', 'editeur']:
                has_permission = True
                
        if not has_permission:
            return jsonify({'error': 'Permission refusée'}), 403

        if request.method == 'POST':
            # Vérifier si l'étiquette n'est pas déjà associée
            if etiquette in tache.etiquettes:
                return jsonify({'message': 'Étiquette déjà associée à la tâche'}), 200
                
            tache.etiquettes.append(etiquette)
            action = "Ajout"
            
        else:  # DELETE
            if etiquette not in tache.etiquettes:
                return '', 204
                
            tache.etiquettes.remove(etiquette)
            action = "Suppression"

        # Ajouter à l'historique
        historique = Historique(
            id_user=user_id,
            id_tache=tache_id,
            action=f"{action} de l'étiquette {etiquette.description} de la tâche {tache.titre}",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        
        db.session.commit()
        
        if request.method == 'DELETE':
            return '', 204
            
        return jsonify(tache_schema.dump(tache)), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erreur lors de la gestion de l'étiquette: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/taches/<int:tache_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
@handle_db_errors
def manage_tache(tache_id):
    if not validate_id(tache_id):
        return jsonify({'error': 'ID invalide'}), 400

    user_id = get_jwt_identity()
    tache = Tache.query.get_or_404(tache_id)
    dossier = Dossier.query.get(tache.id_dossier)
    groupe = Groupe.query.get(dossier.id_groupe)

    # Vérification des permissions
    has_permission = False
    if groupe.id_user == user_id:
        has_permission = True
    else:
        membre = Membre.query.filter_by(
            id_groupe=groupe.id_groupe,
            id_user=user_id
        ).first()
        if membre and membre.role in ['admin', 'éditeur']:
            has_permission = True

    if not has_permission:
        return jsonify({'error': 'Permission refusée'}), 403

    if request.method == 'GET':
        return jsonify(tache_schema.dump(tache)), 200

    elif request.method == 'PUT':
        data = request.get_json()
        if not validate_schema('tache')(lambda: None)():
            return jsonify({'error': 'Données invalides'}), 400

        # Validation de la date de fin
        if 'date_fin' in data and data['date_fin']:
            try:
                date_fin = datetime.strptime(data['date_fin'], '%Y-%m-%dT%H:%M:%S')
                if date_fin < datetime.utcnow():
                    return jsonify({'error': 'La date de fin ne peut pas être dans le passé'}), 400
            except ValueError:
                return jsonify({'error': 'Format de date invalide'}), 400

        # Mise à jour des champs standards
        for key, value in data.items():
            if hasattr(tache, key) and key not in ['id_tache', 'id_dossier', 'id_user']:
                if key in ['titre', 'sous_titre', 'texte']:
                    setattr(tache, key, sanitize_input(value))
                else:
                    setattr(tache, key, value)

        # Mise à jour des étiquettes
        if 'etiquettes' in data:
            tache.etiquettes = []
            for etiquette_id in data['etiquettes']:
                etiquette = Etiquette.query.get(etiquette_id)
                if etiquette:
                    tache.etiquettes.append(etiquette)

        # Mise à jour des utilisateurs assignés
        if 'users' in data:
            tache.users = []
            for assigned_user_id in data['users']:
                user = User.query.get(assigned_user_id)
                if user:
                    tache.users.append(user)

        historique = Historique(
            id_user=user_id,
            id_tache=tache_id,
            action=f"Modification de la tâche {tache.titre}",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        db.session.commit()

        return jsonify(tache_schema.dump(tache)), 200

    else:  # DELETE
        titre = tache.titre

        # Suppression des relations
        tache.etiquettes = []
        tache.users = []

        # Suppression des sous-tâches
        SousTache.query.filter_by(id_tache=tache_id).delete()

        # Suppression des commentaires
        Commentaire.query.filter_by(id_tache=tache_id).delete()

        # Suppression des synchronisations Google
        GoogleTache.query.filter_by(local_id_event=tache_id).delete()

        # Suppression de la tâche
        db.session.delete(tache)

        historique = Historique(
            id_user=user_id,
            action=f"Suppression de la tâche {titre}",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        db.session.commit()

        return '', 204

@app.route('/taches/<int:tache_id>/sous-taches', methods=['GET'])
@jwt_required()
def get_sous_taches(tache_id):
    try:
        user_id = get_jwt_identity()
        tache = Tache.query.get_or_404(tache_id)
        dossier = Dossier.query.get(tache.id_dossier)
        groupe = Groupe.query.get(dossier.id_groupe)

        # Vérification des permissions
        has_access = False
        if groupe.id_user == user_id:
            has_access = True
        else:
            membre = Membre.query.filter_by(
                id_groupe=groupe.id_groupe,
                id_user=user_id
            ).first()
            if membre:
                has_access = True

        if not has_access:
            return jsonify({'error': 'Permission refusée'}), 403

        sous_taches = SousTache.query.filter_by(id_tache=tache_id).all()
        result = sous_taches_schema.dump(sous_taches)

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Error fetching subtasks: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/taches/<int:tache_id>/sous-taches', methods=['POST'])
@jwt_required()
@validate_schema('sous_tache')
@validate_json()
@handle_db_errors
def create_sous_tache(tache_id):
    if not validate_id(tache_id):
        return jsonify({'error': 'ID invalide'}), 400

    user_id = get_jwt_identity()
    tache = Tache.query.get_or_404(tache_id)
    dossier = Dossier.query.get(tache.id_dossier)
    groupe = Groupe.query.get(dossier.id_groupe)

    # Vérification des permissions
    if groupe.id_user != user_id:
        membre = Membre.query.filter_by(
            id_groupe=groupe.id_groupe,
            id_user=user_id
        ).first()
        if not membre or membre.role not in ['admin', 'éditeur']:
            return jsonify({'error': 'Permission refusée'}), 403

    data = request.get_json()

    new_sous_tache = SousTache(
        id_tache=tache_id,
        titre=sanitize_input(data['titre']),
        priorite=data.get('priorite'),
        date_fin=data.get('date_fin'),
        statut=data.get('statut', 0)
    )

    db.session.add(new_sous_tache)

    historique = Historique(
        id_user=user_id,
        id_tache=tache_id,
        action=f"Création de la sous-tâche {new_sous_tache.titre}",
        date=datetime.utcnow()
    )
    db.session.add(historique)
    db.session.commit()

    return jsonify(sous_tache_schema.dump(new_sous_tache)), 201

@app.route('/sous-taches/<int:sous_tache_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
@handle_db_errors
def manage_sous_tache(sous_tache_id):
    if not validate_id(sous_tache_id):
        return jsonify({'error': 'ID invalide'}), 400

    user_id = get_jwt_identity()
    sous_tache = SousTache.query.get_or_404(sous_tache_id)
    tache = Tache.query.get(sous_tache.id_tache)
    dossier = Dossier.query.get(tache.id_dossier)
    groupe = Groupe.query.get(dossier.id_groupe)

    if groupe.id_user != user_id:
        membre = Membre.query.filter_by(
            id_groupe=groupe.id_groupe,
            id_user=user_id,
            role='admin'
        ).first()
        if not membre:
            return jsonify({'error': 'Permission refusée'}), 403

    if request.method == 'GET':
        return jsonify(sous_tache_schema.dump(sous_tache)), 200

    elif request.method == 'PUT':
        data = request.get_json()
        if not validate_schema('sous_tache')(lambda: None)():
            return jsonify({'error': 'Données invalides'}), 400

        old_titre = sous_tache.titre

        for key, value in data.items():
            if hasattr(sous_tache, key):
                if key == 'titre':
                    setattr(sous_tache, key, sanitize_input(value))
                else:
                    setattr(sous_tache, key, value)

        historique = Historique(
            id_user=user_id,
            id_tache=sous_tache.id_tache,
            action=f"Modification de la sous-tâche {old_titre}",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        db.session.commit()

        return jsonify(sous_tache_schema.dump(sous_tache)), 200

    else:  # DELETE
        titre = sous_tache.titre
        tache_id = sous_tache.id_tache
        
        # Suppression simple grâce à ON DELETE CASCADE
        db.session.delete(sous_tache)

        historique = Historique(
            id_user=user_id,
            id_tache=tache_id,
            action=f"Suppression de la sous-tâche {titre}",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        db.session.commit()

        return '', 204
    
# Routes pour les droits d'accès aux tâches
@app.route('/droits', methods=['GET'])
@jwt_required()
@handle_db_errors
def get_droits():
    user_id = get_jwt_identity()
    try:
        droits = Droit.query.filter_by(id_user=user_id).all()
        return jsonify(droits_schema.dump(droits)), 200
    except Exception as e:
        logger.error(f"Error fetching rights: {str(e)}")
        return jsonify({'error': 'Erreur lors de la récupération des droits'}), 500

@app.route('/droits', methods=['POST'])
@jwt_required()
@validate_schema('droit')
@validate_json()
def create_droit():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        # Vérifier que la tâche existe
        tache = Tache.query.get_or_404(data['id_tache'])
        
        # Vérifier les permissions sur la tâche
        dossier = Dossier.query.get(tache.id_dossier)
        groupe = Groupe.query.get(dossier.id_groupe)
        
        if groupe.id_user != user_id:
            membre = Membre.query.filter_by(
                id_groupe=groupe.id_groupe,
                id_user=user_id,
                role='admin'
            ).first()
            if not membre:
                return jsonify({'error': 'Permission refusée'}), 403

        # Vérifier si le droit existe déjà
        existing_droit = Droit.query.filter_by(
            id_user=data['id_user'],
            id_tache=data['id_tache']
        ).first()

        if existing_droit:
            return jsonify({'error': 'Droit déjà existant'}), 400

        new_droit = Droit(
            id_user=data['id_user'],
            id_tache=data['id_tache'],
            droit=data['droit']
        )

        db.session.add(new_droit)
        
        historique = Historique(
            id_user=user_id,
            id_tache=data['id_tache'],
            action=f"Attribution de droits à l'utilisateur {data['id_user']}",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        db.session.commit()

        return jsonify(droit_schema.dump(new_droit)), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating right: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/droits/<int:droit_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
@handle_db_errors
def manage_droit(droit_id):
    if not validate_id(droit_id):
        return jsonify({'error': 'ID invalide'}), 400

    user_id = get_jwt_identity()
    droit = Droit.query.get_or_404(droit_id)
    
    # Vérification des permissions via la tâche
    tache = Tache.query.get(droit.id_tache)
    dossier = Dossier.query.get(tache.id_dossier)
    groupe = Groupe.query.get(dossier.id_groupe)

    if groupe.id_user != user_id:
        membre = Membre.query.filter_by(
            id_groupe=groupe.id_groupe,
            id_user=user_id,
            role='admin'
        ).first()
        if not membre:
            return jsonify({'error': 'Permission refusée'}), 403

    if request.method == 'GET':
        return jsonify(droit_schema.dump(droit)), 200

    elif request.method == 'PUT':
        data = request.get_json()
        if not validate_schema('droit')(lambda: None)():
            return jsonify({'error': 'Données invalides'}), 400

        droit.droit = data['droit']

        historique = Historique(
            id_user=user_id,
            id_tache=droit.id_tache,
            action=f"Modification des droits de l'utilisateur {droit.id_user}",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        db.session.commit()

        return jsonify(droit_schema.dump(droit)), 200

    else:  # DELETE
        db.session.delete(droit)
        
        historique = Historique(
            id_user=user_id,
            id_tache=droit.id_tache,
            action=f"Suppression des droits de l'utilisateur {droit.id_user}",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        db.session.commit()

        return '', 204
    
# Route pour obtenir les tâches assignées à un utilisateur
@app.route('/users/<int:user_id>/tasks', methods=['GET'])
@jwt_required()
def get_user_tasks(user_id):
    try:
        current_user_id = get_jwt_identity()
        
        # Un utilisateur peut toujours voir ses propres tâches
        if user_id == current_user_id:
            taches = (Tache.query
                     .join(TacheUser)
                     .filter(TacheUser.id_user == user_id)
                     .all())
            return jsonify(taches_schema.dump(taches)), 200
            
        # Pour voir les tâches d'un autre utilisateur, vérifier s'ils partagent un groupe
        shared_groups = (db.session.query(Groupe)
                        .join(Membre, Groupe.id_groupe == Membre.id_groupe)
                        .filter(Membre.id_user.in_([current_user_id, user_id]))
                        .group_by(Groupe.id_groupe)
                        .having(db.func.count(db.distinct(Membre.id_user)) == 2)
                        .all())
                        
        if shared_groups or db.session.query(Groupe).filter_by(id_user=current_user_id).first():
            taches = (Tache.query
                     .join(TacheUser)
                     .filter(TacheUser.id_user == user_id)
                     .all())
            return jsonify(taches_schema.dump(taches)), 200
            
        return jsonify({'error': 'Permission refusée'}), 403
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des tâches: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/taches/<int:tache_id>/users', methods=['GET'])
@jwt_required()
@handle_db_errors
def get_task_users(tache_id):
    """Récupère tous les utilisateurs assignés à une tâche"""
    try:
        user_id = get_jwt_identity()
        
        # Récupérer la tâche et vérifier son existence
        tache = Tache.query.get_or_404(tache_id)
        dossier = Dossier.query.get(tache.id_dossier)
        groupe = Groupe.query.get(dossier.id_groupe)
        
        # Vérifier les permissions
        if groupe.id_user != user_id:
            membre = Membre.query.filter_by(
                id_groupe=groupe.id_groupe,
                id_user=user_id
            ).first()
            if not membre:
                return jsonify({'error': 'Permission refusée'}), 403

        # Récupérer les utilisateurs assignés
        users = (User.query
                .join(TacheUser)
                .filter(TacheUser.id_tache == tache_id)
                .all())
        
        return jsonify(users_schema.dump(users)), 200
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des utilisateurs de la tâche {tache_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/taches/<int:tache_id>/etiquettes', methods=['GET'])
@jwt_required()
@handle_db_errors
def get_task_labels(tache_id):
    """Récupère toutes les étiquettes associées à une tâche"""
    try:
        user_id = get_jwt_identity()
            
        tache = Tache.query.get_or_404(tache_id)
        return jsonify(etiquettes_schema.dump(tache.etiquettes)), 200
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des étiquettes: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
# Route pour obtenir l'historique d'une tâche
@app.route('/taches/<int:tache_id>/historique', methods=['GET'])
@jwt_required()
@handle_db_errors
def get_task_history(tache_id):
    if not validate_id(tache_id):
        return jsonify({'error': 'ID invalide'}), 400

    user_id = get_jwt_identity()
    tache = Tache.query.get_or_404(tache_id)
    dossier = Dossier.query.get(tache.id_dossier)
    groupe = Groupe.query.get(dossier.id_groupe)

    if groupe.id_user != user_id:
        membre = Membre.query.filter_by(
            id_groupe=groupe.id_groupe,
            id_user=user_id
        ).first()
        if not membre:
            return jsonify({'error': 'Permission refusée'}), 403

    historique = (Historique.query
                 .filter_by(id_tache=tache_id)
                 .order_by(Historique.date.desc())
                 .all())

    return jsonify(historiques_schema.dump(historique)), 200

# Route pour dissocier une tâche d'un utilisateur
@app.route('/taches/<int:tache_id>/unassign/<int:user_id>', methods=['DELETE'])
@jwt_required()
@handle_db_errors
def unassign_user_from_task(tache_id, user_id):
    """Désassigne un utilisateur d'une tâche"""
    try:
        current_user_id = get_jwt_identity()
        
        # Vérifier l'existence de la tâche
        tache = Tache.query.get_or_404(tache_id)
        
        # Trouver l'assignation
        assignment = TacheUser.query.filter_by(
            id_tache=tache_id,
            id_user=user_id
        ).first()
        
        if not assignment:
            return jsonify({'message': 'Utilisateur non assigné à cette tâche'}), 204
            
        # Supprimer l'assignation
        db.session.delete(assignment)
        
        # Ajouter à l'historique
        historique = Historique(
            id_user=current_user_id,
            id_tache=tache_id,
            action=f"Désassignation de l'utilisateur {user_id} de la tâche",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        
        db.session.commit()
        
        return '', 204
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erreur lors de la désassignation: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/google/agendas', methods=['GET'])
@jwt_required()
@handle_db_errors
def get_google_agendas():
    """Récupère toutes les synchronisations Google Agenda"""
    try:
        user_id = get_jwt_identity()
        
        # Récupérer les dossiers auxquels l'utilisateur a accès
        dossiers_autorises = (Dossier.query
            .join(Groupe)
            .outerjoin(Membre, and_(
                Membre.id_groupe == Groupe.id_groupe,
                Membre.id_user == user_id
            ))
            .filter(or_(
                Groupe.id_user == user_id,
                Membre.id_user == user_id
            ))
            .with_entities(Dossier.id_dossier)
            .all())
            
        dossier_ids = [d[0] for d in dossiers_autorises]
        
        # Récupérer les synchronisations pour ces dossiers
        syncs = GoogleAgenda.query.filter(
            GoogleAgenda.local_id_cal.in_(dossier_ids)
        ).all()
        
        return jsonify(google_agendas_schema.dump(syncs)), 200
        
    except Exception as e:
        logger.error(f"Error fetching Google Calendar syncs: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
# Routes pour la gestion des synchronisations Google
@app.route('/google/agendas/<int:id>', methods=['GET'])
@jwt_required()
@handle_db_errors
def get_google_agenda(id):
    if not validate_id(id):
        return jsonify({'error': 'ID invalide'}), 400

    sync = GoogleAgenda.query.get_or_404(id)
    dossier = Dossier.query.get(sync.local_id_cal)
    
    user_id = get_jwt_identity()
    if not check_dossier_permission(dossier, user_id):
        return jsonify({'error': 'Permission refusée'}), 403

    return jsonify(google_agenda_schema.dump(sync)), 200

@app.route('/google/taches', methods=['GET'])
@jwt_required()
@handle_db_errors
def get_google_taches():
    """Récupère toutes les synchronisations Google Tasks"""
    try:
        user_id = get_jwt_identity()
        
        # Récupérer les tâches auxquelles l'utilisateur a accès
        taches_autorisees = (Tache.query
            .join(Dossier)
            .join(Groupe)
            .outerjoin(Membre, and_(
                Membre.id_groupe == Groupe.id_groupe,
                Membre.id_user == user_id
            ))
            .filter(or_(
                Groupe.id_user == user_id,
                Membre.id_user == user_id
            ))
            .with_entities(Tache.id_tache)
            .all())
            
        tache_ids = [t[0] for t in taches_autorisees]
        
        # Récupérer les synchronisations pour ces tâches
        syncs = GoogleTache.query.filter(
            GoogleTache.local_id_event.in_(tache_ids)
        ).all()
        
        return jsonify(google_taches_schema.dump(syncs)), 200
        
    except Exception as e:
        logger.error(f"Error fetching Google Tasks syncs: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/google/agendas/<int:id>', methods=['GET', 'DELETE'])
@jwt_required()
@handle_db_errors
def manage_google_agenda(id):
    if not validate_id(id):
        return jsonify({'error': 'ID invalide'}), 400

    user_id = get_jwt_identity()
    sync = GoogleAgenda.query.get_or_404(id)
    dossier = Dossier.query.get(sync.local_id_cal)
    
    if not check_dossier_permission(dossier, user_id):
        return jsonify({'error': 'Permission refusée'}), 403

    if request.method == 'GET':
        return jsonify(google_agenda_schema.dump(sync)), 200
    else:  # DELETE
        db.session.delete(sync)
        db.session.commit()
        return '', 204



# Fonctions utilitaires pour la vérification des permissions
def check_dossier_permission(dossier, user_id):
    groupe = Groupe.query.get(dossier.id_groupe)
    if groupe.id_user == user_id:
        return True
    membre = Membre.query.filter_by(
        id_groupe=groupe.id_groupe,
        id_user=user_id,
        role='admin'
    ).first()
    return membre is not None

def check_tache_permission(tache, user_id):
    dossier = Dossier.query.get(tache.id_dossier)
    return check_dossier_permission(dossier, user_id)
    
@app.route('/taches/<int:tache_id>/commentaires', methods=['POST'])
@jwt_required()
def create_task_comment(tache_id):
    """Crée un nouveau commentaire pour une tâche"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data or 'commentaire' not in data:
            return jsonify({'error': 'Commentaire requis'}), 400

        # Vérifier l'existence de la tâche
        tache = Tache.query.get_or_404(tache_id)
        
        # Vérifier les permissions via le dossier et le groupe
        dossier = Dossier.query.get(tache.id_dossier)
        groupe = Groupe.query.get(dossier.id_groupe)

        # Vérification des permissions
        if groupe.id_user != user_id:
            membre = Membre.query.filter_by(
                id_groupe=groupe.id_groupe,
                id_user=user_id
            ).first()
            if not membre:
                return jsonify({'error': 'Permission refusée'}), 403

        # Création du commentaire
        new_commentaire = Commentaire(
            id_tache=tache_id,
            id_user=user_id,
            commentaire=sanitize_input(data['commentaire']),
            date_commentaire=datetime.utcnow()
        )

        db.session.add(new_commentaire)
        
        # Ajout historique
        historique = Historique(
            id_user=user_id,
            id_tache=tache_id,
            action=f"Ajout d'un commentaire",
            date=datetime.utcnow()
        )
        
        db.session.add(historique)
        db.session.commit()

        # Retourner le commentaire créé avec les relations chargées
        return jsonify(commentaire_schema.dump(new_commentaire)), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating comment: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/taches/<int:tache_id>/commentaires', methods=['GET'])
@jwt_required()
@handle_db_errors
def get_task_commentaires(tache_id):
    """Récupère tous les commentaires d'une tâche"""
    try:
        user_id = get_jwt_identity()
        tache = Tache.query.get_or_404(tache_id)
        dossier = Dossier.query.get(tache.id_dossier)
        groupe = Groupe.query.get(dossier.id_groupe)
        
        # Vérifier les permissions
        has_access = False
        if groupe.id_user == user_id:
            has_access = True
        else:
            membre = Membre.query.filter_by(
                id_groupe=groupe.id_groupe,
                id_user=user_id
            ).first()
            if membre:
                has_access = True
                
        if not has_access:
            return jsonify({'error': 'Permission refusée'}), 403

        commentaires = Commentaire.query.filter_by(id_tache=tache_id)\
            .order_by(Commentaire.date_commentaire.desc())\
            .all()
            
        return jsonify(commentaires_schema.dump(commentaires)), 200
            
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des commentaires de la tâche {tache_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/commentaires/<int:commentaire_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
@handle_db_errors
def manage_commentaire(commentaire_id):
    """Gère un commentaire spécifique (lecture, modification, suppression)"""
    user_id = get_jwt_identity()
    commentaire = Commentaire.query.get_or_404(commentaire_id)
    
    tache = Tache.query.get(commentaire.id_tache)
    dossier = Dossier.query.get(tache.id_dossier)
    groupe = Groupe.query.get(dossier.id_groupe)
    
    # Vérification des permissions
    if commentaire.id_user != user_id and groupe.id_user != user_id:
        membre_admin = Membre.query.filter_by(
            id_groupe=groupe.id_groupe,
            id_user=user_id,
            role='admin'
        ).first()
        if not membre_admin:
            return jsonify({'error': 'Permission refusée'}), 403

    if request.method == 'GET':
        return jsonify(commentaire_schema.dump(commentaire)), 200
            
    elif request.method == 'PUT':
        # Seul l'auteur peut modifier son commentaire
        if commentaire.id_user != user_id:
            return jsonify({'error': 'Permission refusée'}), 403
                
        data = request.get_json()
        if not data or 'commentaire' not in data:
            return jsonify({'error': 'Contenu du commentaire requis'}), 400
                
        commentaire.commentaire = sanitize_input(data['commentaire'])
        commentaire.date_commentaire = datetime.utcnow()
        
        historique = Historique(
            id_user=user_id,
            id_tache=commentaire.id_tache,
            action=f"Modification d'un commentaire",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        db.session.commit()
        
        return jsonify(commentaire_schema.dump(commentaire)), 200
            
    else:  # DELETE
        # Ajout dans l'historique avant suppression
        historique = Historique(
            id_user=user_id,
            id_tache=commentaire.id_tache,
            action=f"Suppression d'un commentaire",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        
        db.session.delete(commentaire)
        db.session.commit()
        return '', 204

# Routes pour les étiquettes
@app.route('/etiquettes', methods=['GET'])
@jwt_required()
@handle_db_errors
def get_etiquettes():
    try:
        etiquettes = Etiquette.query.all()
        return jsonify(etiquettes_schema.dump(etiquettes)), 200
    except Exception as e:
        logger.error(f"Error fetching labels: {str(e)}")
        return jsonify({'error': 'Erreur lors de la récupération des étiquettes'}), 500

@app.route('/etiquettes', methods=['POST'])
@jwt_required()
@validate_schema('etiquette')
@validate_json()
@handle_db_errors
def create_etiquette():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        # Vérifier si une étiquette avec la même description existe déjà
        existing_etiquette = Etiquette.query.filter_by(
            description=data['description']
        ).first()

        if existing_etiquette:
            return jsonify({
                'error': 'Une étiquette avec cette description existe déjà'
            }), 400

        new_etiquette = Etiquette(
            description=sanitize_input(data['description'])
        )

        db.session.add(new_etiquette)

        historique = Historique(
            id_user=user_id,
            action=f"Création de l'étiquette: {new_etiquette.description}",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        db.session.commit()

        return jsonify(etiquette_schema.dump(new_etiquette)), 201

    except Exception as e:
        logger.error(f"Error creating label: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Erreur lors de la création de l\'étiquette'}), 500

@app.route('/etiquettes/<int:etiquette_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
@handle_db_errors
def manage_etiquette(etiquette_id):
    etiquette = Etiquette.query.get_or_404(etiquette_id)
    user_id = get_jwt_identity()
    
    if request.method == 'GET':
        return jsonify(etiquette_schema.dump(etiquette)), 200
    elif request.method == 'PUT':
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
            
        data = request.get_json()
        if not data or 'description' not in data:
            return jsonify({'error': 'Description requise'}), 400
            
        etiquette.description = sanitize_input(data['description'])
        db.session.commit()
        return jsonify(etiquette_schema.dump(etiquette)), 200
    else:  # DELETE
        # La suppression en cascade s'occupe des relations
        db.session.delete(etiquette)
        db.session.commit()
        return '', 204
    
# Routes pour les invitations
@app.route('/invitations', methods=['GET'])
@jwt_required()
def get_invitations():
    """Récupère toutes les invitations pertinentes pour un utilisateur"""
    try:
        user_id = get_jwt_identity()

        # Inclure toutes les invitations possibles sans restriction
        invitations = db.session.query(Invitation).filter(
            db.or_(
                Invitation.id_user == user_id,                    # Invitations reçues
                Invitation.id_groupe.in_(                         # Invitations envoyées
                    db.session.query(Groupe.id_groupe).filter(
                        db.or_(
                            Groupe.id_user == user_id,           # Propriétaire du groupe
                            Groupe.id_groupe.in_(                 # Membre du groupe
                                db.session.query(Membre.id_groupe)
                                .filter(Membre.id_user == user_id)
                            )
                        )
                    )
                )
            )
        ).all()

        return jsonify(invitations_schema.dump(invitations)), 200

    except Exception as e:
        logger.error(f"Erreur récupération invitations: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/invitations', methods=['POST'])
@jwt_required()
@handle_db_errors
def create_invitation():
    """Crée une nouvelle invitation"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        # Validation des données
        if not data or 'id_groupe' not in data or 'id_user' not in data:
            return jsonify({'error': 'Données manquantes'}), 400

        # Vérification de l'existence du groupe et de l'utilisateur
        groupe = Groupe.query.get_or_404(data['id_groupe'])
        user_to_invite = User.query.get_or_404(data['id_user'])

        # Vérification des droits d'invitation
        has_permission = False
        if groupe.id_user == user_id:  # Propriétaire du groupe
            has_permission = True
        else:
            membre = Membre.query.filter_by(
                id_groupe=data['id_groupe'],
                id_user=user_id
            ).first()
            if membre and membre.role in ['admin']:
                has_permission = True

        if not has_permission:
            return jsonify({'error': 'Permission refusée'}), 403

        # Vérifier si l'utilisateur n'est pas déjà membre
        existing_membre = Membre.query.filter_by(
            id_groupe=data['id_groupe'],
            id_user=data['id_user']
        ).first()
        if existing_membre:
            return jsonify({'error': 'L\'utilisateur est déjà membre du groupe'}), 400

        # Vérifier si une invitation n'est pas déjà en cours
        existing_invitation = Invitation.query.filter_by(
            id_groupe=data['id_groupe'],
            id_user=data['id_user'],
            statut='En attente'
        ).first()
        if existing_invitation:
            return jsonify({'error': 'Une invitation est déjà en cours'}), 400

        # Création de l'invitation
        new_invitation = Invitation(
            id_groupe=data['id_groupe'],
            id_user=data['id_user'],
            statut='En attente'
        )
        db.session.add(new_invitation)

        # Ajout dans l'historique
        historique = Historique(
            id_user=user_id,
            action=f"Invitation envoyée à l'utilisateur {data['id_user']} pour le groupe {groupe.nom}",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        db.session.commit()

        return jsonify(invitation_schema.dump(new_invitation)), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Erreur lors de la création de l'invitation: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/taches/<int:tache_id>/sous-taches', methods=['GET', 'POST'])
@jwt_required()
def handle_sous_taches(tache_id):
    try:
        user_id = get_jwt_identity()
        tache = Tache.query.get_or_404(tache_id)

        if request.method == 'GET':
            sous_taches = SousTache.query.filter_by(id_tache=tache_id).all()
            return jsonify(sous_taches_schema.dump(sous_taches)), 200

        # POST
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Données manquantes'}), 400

        # Permettre la création même avec des données minimales
        new_sous_tache = SousTache(
            id_tache=tache_id,
            titre=data.get('titre', 'Nouvelle sous-tâche'),
            priorite=data.get('priorite', 0),
            statut=data.get('statut', 0)
        )

        db.session.add(new_sous_tache)

        # Ajouter à l'historique
        historique = Historique(
            id_user=user_id,
            id_tache=tache_id,
            action=f"Création de la sous-tâche {new_sous_tache.titre}",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        
        db.session.commit()
        return jsonify(sous_tache_schema.dump(new_sous_tache)), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error managing subtasks: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/groupes/<int:groupe_id>/membres', methods=['POST'])
@jwt_required()
@handle_db_errors
def add_membre(groupe_id):
    """
    Ajoute un membre à un groupe. Vérifie si le membre existe déjà.
    """
    user_id = get_jwt_identity()
    data = request.get_json()

    if not data or 'id_user' not in data:
        return jsonify({'error': 'ID utilisateur requis'}), 400

    member_id = data['id_user']

    try:
        # Vérifier si le groupe existe
        groupe = Groupe.query.get_or_404(groupe_id)

        # Vérifier si l'utilisateur est propriétaire ou admin du groupe
        is_owner = (groupe.id_user == user_id)
        is_admin = Membre.query.filter_by(
            id_groupe=groupe_id,
            id_user=user_id,
            role='admin'
        ).first()

        if not (is_owner or is_admin):
            return jsonify({'error': 'Permission refusée'}), 403

        # Vérifier si le membre est déjà dans le groupe
        existing_member = Membre.query.filter_by(
            id_groupe=groupe_id,
            id_user=member_id
        ).first()
        if existing_member:
            return jsonify({'message': 'Utilisateur déjà membre du groupe'}), 200

        # Ajouter le membre
        new_member = Membre(
            id_groupe=groupe_id,
            id_user=member_id,
            role=data.get('role', 'lecture')  # Par défaut, rôle lecture
        )
        db.session.add(new_member)

        # Historique
        historique = Historique(
            id_user=user_id,
            action=f"Ajout de l'utilisateur {member_id} au groupe {groupe.nom}",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        db.session.commit()

        return jsonify({'message': 'Membre ajouté avec succès'}), 201

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Erreur SQL lors de l'ajout d'un membre : {str(e)}")
        return jsonify({'error': 'Erreur lors de l\'ajout du membre'}), 500

    except Exception as e:
        logger.error(f"Erreur inattendue : {str(e)}")
        return jsonify({'error': 'Erreur inattendue'}), 500


@app.route('/membres', methods=['POST'])
@jwt_required()
def create_membre():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not all(k in data for k in ['id_groupe', 'id_user', 'role']):
            return jsonify({'error': 'Données manquantes'}), 400

        groupe = Groupe.query.get_or_404(data['id_groupe'])
        if groupe.id_user != user_id:
            return jsonify({'error': 'Permission refusée'}), 403

        new_membre = Membre(
            id_groupe=data['id_groupe'],
            id_user=data['id_user'],
            role=data['role']
        )
        db.session.add(new_membre)
        db.session.commit()

        return jsonify(membre_schema.dump(new_membre)), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating member: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/membres/<int:membre_id>', methods=['PUT'])
@jwt_required()
@validate_schema('membre')
@validate_json()
@handle_db_errors
def update_membre(membre_id):
    """
    Met à jour le rôle d'un membre dans un groupe.
    """
    if not validate_id(membre_id):
        return jsonify({'error': 'ID invalide'}), 400

    user_id = get_jwt_identity()

    # Récupérer le membre
    membre = Membre.query.get_or_404(membre_id)

    # Vérifier que le membre appartient à un groupe
    if not membre.id_groupe:
        return jsonify({'error': 'Le membre n\'est associé à aucun groupe'}), 400

    # Récupérer le groupe associé
    groupe = Groupe.query.get(membre.id_groupe)
    if not groupe:
        return jsonify({'error': 'Groupe introuvable'}), 404

    # Seul le propriétaire peut modifier les rôles
    if groupe.id_user != user_id:
        return jsonify({'error': 'Permission refusée'}), 403

    # Récupérer et valider les données de la requête
    data = request.get_json()
    if 'role' not in data or data['role'] not in ['admin', 'lecture', 'éditeur']:
        return jsonify({'error': 'Rôle invalide ou manquant'}), 400

    # Mise à jour du rôle
    membre.role = data['role']

    # Ajouter une entrée dans l'historique
    historique = Historique(
        id_user=user_id,
        action=f"Modification du rôle du membre {membre.user.username} en {data['role']}",
        date=datetime.utcnow()
    )
    db.session.add(historique)

    # Sauvegarder les modifications
    try:
        db.session.commit()
        return jsonify(membre_schema.dump(membre)), 200
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Erreur SQL lors de la mise à jour du membre : {str(e)}")
        return jsonify({'error': 'Erreur lors de la mise à jour du membre'}), 500
    except Exception as e:
        logger.error(f"Erreur inattendue lors de la mise à jour du membre : {str(e)}")
        return jsonify({'error': 'Erreur inattendue'}), 500



@app.route('/groupes/<int:groupe_id>/membres/<int:membre_id>', methods=['DELETE'])
@jwt_required()
@handle_db_errors
def delete_membre(groupe_id, membre_id):
    """
    Supprime un membre d'un groupe, si l'utilisateur connecté est autorisé.
    """
    user_id = get_jwt_identity()  # Récupère l'ID de l'utilisateur à partir du token
    try:
        # Vérifier si le groupe existe
        groupe = Groupe.query.get_or_404(groupe_id)

        # Vérifier si l'utilisateur connecté est le propriétaire ou admin du groupe
        is_owner = (groupe.id_user == user_id)
        is_admin = Membre.query.filter_by(
            id_groupe=groupe_id,
            id_user=user_id,
            role='admin'
        ).first()

        if not (is_owner or is_admin):
            return jsonify({'error': 'Permission refusée'}), 403

        # Vérifier si le membre existe
        membre = Membre.query.filter_by(id_groupe=groupe_id, id_user=membre_id).first()
        if not membre:
            return jsonify({'error': 'Membre introuvable dans ce groupe'}), 404

        # Ne pas permettre de supprimer le propriétaire du groupe
        if membre_id == groupe.id_user:
            return jsonify({'error': 'Impossible de supprimer le propriétaire du groupe'}), 403

        # Supprimer le membre
        db.session.delete(membre)

        # Ajouter une entrée dans l'historique
        historique = Historique(
            id_user=user_id,
            action=f"Suppression du membre {membre_id} du groupe {groupe.nom}",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        db.session.commit()

        return jsonify({'message': 'Membre supprimé avec succès'}), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Erreur lors de la suppression du membre: {str(e)}")
        return jsonify({'error': 'Erreur lors de la suppression du membre'}), 500

    except Exception as e:
        logger.error(f"Erreur inattendue: {str(e)}")
        return jsonify({'error': 'Erreur inattendue'}), 500
    
# Routes pour l'intégration Google
@app.route('/google/agendas', methods=['POST'])
@jwt_required()
@validate_schema('google_agenda')
@validate_json()
@handle_db_errors
def sync_google_agenda():
    user_id = get_jwt_identity()
    data = request.get_json()

    dossier = Dossier.query.get_or_404(data['local_id_cal'])
    groupe = Groupe.query.get(dossier.id_groupe)

    # Vérifier les permissions
    if groupe.id_user != user_id:
        membre = Membre.query.filter_by(
            id_groupe=groupe.id_groupe,
            id_user=user_id
        ).first()
        if not membre or membre.role not in ['admin', 'éditeur']:
            return jsonify({'error': 'Permission refusée'}), 403

    new_sync = GoogleAgenda(
        google_id_cal=sanitize_input(data['google_id_cal']),
        local_id_cal=data['local_id_cal']
    )

    db.session.add(new_sync)

    historique = Historique(
        id_user=user_id,
        action=f"Synchronisation Google Agenda configurée pour {dossier.nom}",
        date=datetime.utcnow()
    )
    db.session.add(historique)
    db.session.commit()

    return jsonify(google_agenda_schema.dump(new_sync)), 201

@app.route('/google/taches', methods=['POST'])
@jwt_required()
@validate_schema('google_tache')
@validate_json()
@handle_db_errors
def sync_google_tache():
    user_id = get_jwt_identity()
    data = request.get_json()

    tache = Tache.query.get_or_404(data['local_id_event'])
    dossier = Dossier.query.get(tache.id_dossier)
    groupe = Groupe.query.get(dossier.id_groupe)

    # Vérifier les permissions
    if groupe.id_user != user_id:
        membre = Membre.query.filter_by(
            id_groupe=groupe.id_groupe,
            id_user=user_id
        ).first()
        if not membre or membre.role not in ['admin', 'éditeur']:
            return jsonify({'error': 'Permission refusée'}), 403

    new_sync = GoogleTache(
        google_id_event=sanitize_input(data['google_id_event']),
        local_id_event=data['local_id_event']
    )

    db.session.add(new_sync)

    historique = Historique(
        id_user=user_id,
        id_tache=tache.id_tache,
        action=f"Synchronisation Google Tasks configurée pour {tache.titre}",
        date=datetime.utcnow()
    )
    db.session.add(historique)
    db.session.commit()

    return jsonify(google_tache_schema.dump(new_sync)), 201

@app.route('/taches/<int:tache_id>/assign', methods=['POST'])
@jwt_required()
@handle_db_errors
def assign_task(tache_id):
    """Assigne une tâche à un utilisateur"""
    try:
        user_id = get_jwt_identity()
        tache = Tache.query.get_or_404(tache_id)
        data = request.get_json()

        if not data or 'user_id' not in data:
            return jsonify({'error': 'ID utilisateur requis'}), 400

        # Vérifier que l'utilisateur à assigner existe
        user_to_assign = User.query.get_or_404(data['user_id'])

        # Vérifier les permissions via le dossier et le groupe
        dossier = Dossier.query.get(tache.id_dossier)
        groupe = Groupe.query.get(dossier.id_groupe)

        # Vérifier les permissions
        has_permission = False
        if groupe.id_user == user_id:
            has_permission = True
        else:
            membre = Membre.query.filter_by(
                id_groupe=groupe.id_groupe,
                id_user=user_id
            ).first()
            if membre and membre.role in ['admin', 'editeur']:
                has_permission = True

        if not has_permission:
            return jsonify({'error': 'Permission refusée'}), 403

        # Vérifier si l'assignation existe déjà
        existing_assignment = TacheUser.query.filter_by(
            id_tache=tache_id,
            id_user=data['user_id']
        ).first()

        if existing_assignment:
            return jsonify({'message': 'Utilisateur déjà assigné à cette tâche'}), 200

        # Créer l'assignation
        new_assignment = TacheUser(
            id_tache=tache_id,
            id_user=data['user_id']
        )
        db.session.add(new_assignment)

        # Ajouter à l'historique
        historique = Historique(
            id_user=user_id,
            id_tache=tache_id,
            action=f"Assignation de l'utilisateur {user_to_assign.username} à la tâche {tache.titre}",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        db.session.commit()

        return jsonify({'message': 'Utilisateur assigné avec succès'}), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Erreur lors de l'assignation de la tâche: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/taches/<int:tache_id>/etiquettes', methods=['POST'])
@jwt_required()
def add_etiquette_to_task(tache_id):
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        tache = Tache.query.get_or_404(tache_id)
        etiquette = Etiquette.query.get_or_404(data['id_etiquettes'])

        # Vérifier si l'étiquette est déjà associée
        if etiquette in tache.etiquettes:
            return jsonify({'error': 'Étiquette déjà associée à la tâche'}), 400

        tache.etiquettes.append(etiquette)

        historique = Historique(
            id_user=user_id,
            id_tache=tache_id,
            action=f"Ajout de l'étiquette {etiquette.description} à la tâche {tache.titre}",
            date=datetime.utcnow()
        )
        db.session.add(historique)
        db.session.add(tache)  # Ajout de cette ligne pour s'assurer que la tâche est bien mise à jour
        db.session.commit()

        return jsonify({'message': 'Étiquette ajoutée avec succès'}), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding label to task: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/historique', methods=['GET'])
@jwt_required()
@handle_db_errors
def get_historique():
    try:
        user_id = get_jwt_identity()
        historique = Historique.query.filter_by(id_user=user_id).order_by(Historique.date.desc()).all()
        return jsonify(historiques_schema.dump(historique)), 200
    except Exception as e:
        logger.error(f"Error fetching historique: {str(e)}")
        return jsonify({'error': 'Erreur lors de la récupération de l\'historique'}), 500

# Modifiez le gestionnaire d'erreurs global
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500

# Implémentation du rate limiting
def rate_limit_exceeded():
    return jsonify({'error': 'Too many requests'}), 429

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": "Too many requests",
        "message": str(e.description)
    }), 429

# Configuration des en-têtes de sécurité globaux
@app.after_request
def add_security_headers(response):
    response.headers.update({
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Content-Security-Policy': "default-src 'self'",
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Feature-Policy': "geolocation 'none'; microphone 'none'; camera 'none'",
        'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0'
    })
    return response

# Gestionnaire d'erreurs global
@app.errorhandler(Exception)
def handle_error(error):
    logger.error(f"Unhandled error: {str(error)}", exc_info=True)

    if isinstance(error, HTTPException):
        return jsonify({
            'error': str(error),
            'type': 'HTTP_EXCEPTION',
            'code': error.code
        }), error.code

    response = {
        'error': "Une erreur interne est survenue",
        'type': error.__class__.__name__
    }

    if app.debug:
        response['detail'] = str(error)
        import traceback
        response['traceback'] = traceback.format_exc()

    return jsonify(response), 500

# Route de healthcheck
@app.route('/health')
@handle_db_errors
def health_check():
    try:
        # Vérifier la connexion à la base de données
        db.session.execute(text('SELECT 1'))

        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '1.0.0'
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

# Ajoutez ces routes à la fin de votre fichier app.py, juste avant le if __name__ == '__main__':

# Routes pour l'export des données de chaque table
@app.route('/api/export/users', methods=['GET'])
@jwt_required()
@handle_db_errors
def export_users():
    """Exporte toutes les données de la table users"""
    try:
        users = User.query.all()
        return jsonify({
            'users': users_schema.dump(users),
            'total': len(users)
        }), 200
    except Exception as e:
        logger.error(f"Error exporting users: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/groupes', methods=['GET'])
@jwt_required()
@handle_db_errors
def export_groupes():
    """Exporte toutes les données de la table groupes"""
    try:
        groupes = Groupe.query.all()
        return jsonify({
            'groupes': groupes_schema.dump(groupes),
            'total': len(groupes)
        }), 200
    except Exception as e:
        logger.error(f"Error exporting groupes: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/dossiers', methods=['GET'])
@jwt_required()
@handle_db_errors
def export_dossiers():
    """Exporte toutes les données de la table dossiers"""
    try:
        dossiers = Dossier.query.all()
        return jsonify({
            'dossiers': dossiers_schema.dump(dossiers),
            'total': len(dossiers)
        }), 200
    except Exception as e:
        logger.error(f"Error exporting dossiers: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/taches', methods=['GET'])
@jwt_required()
@handle_db_errors
def export_taches():
    """Exporte toutes les données de la table taches"""
    try:
        taches = Tache.query.all()
        return jsonify({
            'taches': taches_schema.dump(taches),
            'total': len(taches)
        }), 200
    except Exception as e:
        logger.error(f"Error exporting taches: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/droits', methods=['GET'])
@jwt_required()
@handle_db_errors
def export_droits():
    """Exporte toutes les données de la table droits"""
    try:
        droits = Droit.query.all()
        return jsonify({
            'droits': droits_schema.dump(droits),
            'total': len(droits)
        }), 200
    except Exception as e:
        logger.error(f"Error exporting droits: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/etiquettes', methods=['GET'])
@jwt_required()
@handle_db_errors
def export_etiquettes():
    """Exporte toutes les données de la table etiquettes"""
    try:
        etiquettes = Etiquette.query.all()
        return jsonify({
            'etiquettes': etiquettes_schema.dump(etiquettes),
            'total': len(etiquettes)
        }), 200
    except Exception as e:
        logger.error(f"Error exporting etiquettes: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/tache_etiquette', methods=['GET'])
@jwt_required()
@handle_db_errors
def export_tache_etiquette():
    """Exporte toutes les données de la table de relation tâches-étiquettes"""
    try:
        # Récupération via le modèle Tache et la relation many-to-many
        taches = Tache.query.all()
        result = []
        
        for tache in taches:
            for etiquette in tache.etiquettes:
                result.append({
                    'id_tache': tache.id_tache,
                    'id_etiquettes': etiquette.id_etiquettes
                })
        
        return jsonify({
            'tache_etiquette': result,
            'total': len(result)
        }), 200
        
    except Exception as e:
        logger.error(f"Error exporting tache_etiquette: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/invitations', methods=['GET'])
@jwt_required()
@handle_db_errors
def export_invitations():
    """Exporte toutes les données de la table invitations"""
    try:
        invitations = Invitation.query.all()
        return jsonify({
            'invitations': invitations_schema.dump(invitations),
            'total': len(invitations)
        }), 200
    except Exception as e:
        logger.error(f"Error exporting invitations: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/membres', methods=['GET'])
@jwt_required()
@handle_db_errors
def export_membres():
    """Exporte toutes les données de la table membres"""
    try:
        membres = Membre.query.all()
        return jsonify({
            'membres': membres_schema.dump(membres),
            'total': len(membres)
        }), 200
    except Exception as e:
        logger.error(f"Error exporting membres: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/historique', methods=['GET'])
@jwt_required()
@handle_db_errors
def export_historique():
    """Exporte toutes les données de la table historique"""
    try:
        historique = Historique.query.all()
        return jsonify({
            'historique': historiques_schema.dump(historique),
            'total': len(historique)
        }), 200
    except Exception as e:
        logger.error(f"Error exporting historique: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/sous_taches', methods=['GET'])
@jwt_required()
@handle_db_errors
def export_sous_taches():
    """Exporte toutes les données de la table sous_taches"""
    try:
        sous_taches = SousTache.query.all()
        return jsonify({
            'sous_taches': sous_taches_schema.dump(sous_taches),
            'total': len(sous_taches)
        }), 200
    except Exception as e:
        logger.error(f"Error exporting sous_taches: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/commentaires', methods=['GET'])
@jwt_required()
@handle_db_errors
def export_commentaires():
    """Exporte toutes les données de la table commentaires"""
    try:
        commentaires = Commentaire.query.all()
        return jsonify({
            'commentaires': commentaires_schema.dump(commentaires),
            'total': len(commentaires)
        }), 200
    except Exception as e:
        logger.error(f"Error exporting commentaires: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/google_agenda', methods=['GET'])
@jwt_required()
@handle_db_errors
def export_google_agenda():
    """Exporte toutes les données de la table google_agenda"""
    try:
        google_agenda = GoogleAgenda.query.all()
        return jsonify({
            'google_agenda': google_agendas_schema.dump(google_agenda),
            'total': len(google_agenda)
        }), 200
    except Exception as e:
        logger.error(f"Error exporting google_agenda: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/google_tache', methods=['GET'])
@jwt_required()
@handle_db_errors
def export_google_tache():
    """Exporte toutes les données de la table google_tache"""
    try:
        google_tache = GoogleTache.query.all()
        return jsonify({
            'google_tache': google_taches_schema.dump(google_tache),
            'total': len(google_tache)
        }), 200
    except Exception as e:
        logger.error(f"Error exporting google_tache: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/tache_user', methods=['GET'])
@jwt_required()
@handle_db_errors
def export_tache_user():
    """Exporte toutes les données de la table tache_user"""
    try:
        # Pour la table d'association
        tache_users = db.session.query(db.Table('tache_user')).all()
        
        result = [{
            'id_tache': tu.id_tache,
            'id_user': tu.id_user
        } for tu in tache_users]
        
        return jsonify({
            'tache_user': result,
            'total': len(result)
        }), 200
    except Exception as e:
        logger.error(f"Error exporting tache_user: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Route pour exporter toutes les données en une seule fois
@app.route('/api/export/all', methods=['GET'])
@jwt_required()
@handle_db_errors
def export_all_data():
    """Exporte toutes les données de toutes les tables"""
    try:
        # Récupération des relations tâches-étiquettes
        taches = Tache.query.all()
        tache_etiquette_data = []
        for tache in taches:
            for etiquette in tache.etiquettes:
                tache_etiquette_data.append({
                    'id_tache': tache.id_tache,
                    'id_etiquettes': etiquette.id_etiquettes
                })

        # Récupération des relations tâches-utilisateurs
        tache_user_sql = """
            SELECT t.id_tache, t.id_user 
            FROM tache_user t
        """
        tache_user_result = db.session.execute(text(tache_user_sql)).fetchall()
        tache_user_data = [
            {
                'id_tache': row[0],
                'id_user': row[1]
            }
            for row in tache_user_result
        ]

        # Récupération de toutes les données
        data = {
            'users': users_schema.dump(User.query.all()),
            'groupes': groupes_schema.dump(Groupe.query.all()),
            'dossiers': dossiers_schema.dump(Dossier.query.all()),
            'taches': taches_schema.dump(Tache.query.all()),
            'droits': droits_schema.dump(Droit.query.all()),
            'etiquettes': etiquettes_schema.dump(Etiquette.query.all()),
            'tache_etiquette': tache_etiquette_data,
            'invitations': invitations_schema.dump(Invitation.query.all()),
            'membres': membres_schema.dump(Membre.query.all()),
            'historique': historiques_schema.dump(Historique.query.all()),
            'sous_taches': sous_taches_schema.dump(SousTache.query.all()),
            'commentaires': commentaires_schema.dump(Commentaire.query.all()),
            'google_agenda': google_agendas_schema.dump(GoogleAgenda.query.all()),
            'google_tache': google_taches_schema.dump(GoogleTache.query.all()),
            'tache_user': tache_user_data
        }

        # Ajouter les totaux pour chaque table
        totals = {f"{key}_total": len(value) for key, value in data.items()}
        data.update(totals)

        return jsonify(data), 200

    except Exception as e:
        logger.error(f"Error exporting all data: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Routes pour l'importation des données de chaque table
@app.route('/api/import/users', methods=['POST'])
@jwt_required()
@handle_db_errors
def import_users():
    """Import users from CSV or Excel file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        table_name = 'USER'
        headers = None
        rows = []
        
        if file.filename.endswith('.csv'):
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            reader = csv.reader(stream)
            headers = next(reader)
            rows = list(reader)
        else:
            df = pd.read_excel(file)
            headers = df.columns.tolist()
            rows = df.values.tolist()
        
        result = import_table_data_api(table_name, headers, rows)
        
        if result.get('success'):
            return jsonify({
                'message': 'Users imported successfully',
                'count': len(rows)
            }), 200
        else:
            return jsonify({'error': result.get('error')}), 500
            
    except Exception as e:
        logger.error(f"Error importing users: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/import/groupes', methods=['POST'])
@jwt_required()
@handle_db_errors
def import_groupes():
    """Import groups from CSV or Excel file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        table_name = 'GROUPE'
        headers = None
        rows = []
        
        if file.filename.endswith('.csv'):
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            reader = csv.reader(stream)
            headers = next(reader)
            rows = list(reader)
        else:
            df = pd.read_excel(file)
            headers = df.columns.tolist()
            rows = df.values.tolist()
        
        result = import_table_data_api(table_name, headers, rows)
        
        if result.get('success'):
            return jsonify({
                'message': 'Groups imported successfully',
                'count': len(rows)
            }), 200
        else:
            return jsonify({'error': result.get('error')}), 500
            
    except Exception as e:
        logger.error(f"Error importing groups: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/import/dossiers', methods=['POST'])
@jwt_required()
@handle_db_errors
def import_dossiers():
    """Import folders from CSV or Excel file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        table_name = 'DOSSIER'
        headers = None
        rows = []
        
        if file.filename.endswith('.csv'):
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            reader = csv.reader(stream)
            headers = next(reader)
            rows = list(reader)
        else:
            df = pd.read_excel(file)
            headers = df.columns.tolist()
            rows = df.values.tolist()
        
        result = import_table_data_api(table_name, headers, rows)
        
        if result.get('success'):
            return jsonify({
                'message': 'Folders imported successfully',
                'count': len(rows)
            }), 200
        else:
            return jsonify({'error': result.get('error')}), 500
            
    except Exception as e:
        logger.error(f"Error importing folders: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/import/taches', methods=['POST'])
@jwt_required()
@handle_db_errors
def import_taches():
    """Import tasks from CSV or Excel file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        table_name = 'TACHES'
        headers = None
        rows = []
        
        if file.filename.endswith('.csv'):
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            reader = csv.reader(stream)
            headers = next(reader)
            rows = list(reader)
        else:
            df = pd.read_excel(file)
            headers = df.columns.tolist()
            rows = df.values.tolist()
        
        result = import_table_data_api(table_name, headers, rows)
        
        if result.get('success'):
            return jsonify({
                'message': 'Tasks imported successfully',
                'count': len(rows)
            }), 200
        else:
            return jsonify({'error': result.get('error')}), 500
            
    except Exception as e:
        logger.error(f"Error importing tasks: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/import/droits', methods=['POST'])
@jwt_required()
@handle_db_errors
def import_droits():
    """Import rights from CSV or Excel file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        table_name = 'DROIT'
        headers = None
        rows = []
        
        if file.filename.endswith('.csv'):
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            reader = csv.reader(stream)
            headers = next(reader)
            rows = list(reader)
        else:
            df = pd.read_excel(file)
            headers = df.columns.tolist()
            rows = df.values.tolist()
        
        result = import_table_data_api(table_name, headers, rows)
        
        if result.get('success'):
            return jsonify({
                'message': 'Rights imported successfully',
                'count': len(rows)
            }), 200
        else:
            return jsonify({'error': result.get('error')}), 500
            
    except Exception as e:
        logger.error(f"Error importing rights: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/import/etiquettes', methods=['POST'])
@jwt_required()
@handle_db_errors
def import_etiquettes():
    """Import labels from CSV or Excel file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        table_name = 'ETIQUETTES'
        headers = None
        rows = []
        
        if file.filename.endswith('.csv'):
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            reader = csv.reader(stream)
            headers = next(reader)
            rows = list(reader)
        else:
            df = pd.read_excel(file)
            headers = df.columns.tolist()
            rows = df.values.tolist()
        
        result = import_table_data_api(table_name, headers, rows)
        
        if result.get('success'):
            return jsonify({
                'message': 'Labels imported successfully',
                'count': len(rows)
            }), 200
        else:
            return jsonify({'error': result.get('error')}), 500
            
    except Exception as e:
        logger.error(f"Error importing labels: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/import/tache_etiquette', methods=['POST'])
@jwt_required()
@handle_db_errors
def import_tache_etiquette():
    """Import task-label relations from CSV or Excel file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        table_name = 'TACHE_ETIQUETTE'
        headers = None
        rows = []
        
        if file.filename.endswith('.csv'):
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            reader = csv.reader(stream)
            headers = next(reader)
            rows = list(reader)
        else:
            df = pd.read_excel(file)
            headers = df.columns.tolist()
            rows = df.values.tolist()
        
        result = import_table_data_api(table_name, headers, rows)
        
        if result.get('success'):
            return jsonify({
                'message': 'Task-label relations imported successfully',
                'count': len(rows)
            }), 200
        else:
            return jsonify({'error': result.get('error')}), 500
            
    except Exception as e:
        logger.error(f"Error importing task-label relations: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/import/invitations', methods=['POST'])
@jwt_required()
@handle_db_errors
def import_invitations():
    """Import invitations from CSV or Excel file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        table_name = 'INVITATION'
        headers = None
        rows = []
        
        if file.filename.endswith('.csv'):
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            reader = csv.reader(stream)
            headers = next(reader)
            rows = list(reader)
        else:
            df = pd.read_excel(file)
            headers = df.columns.tolist()
            rows = df.values.tolist()
        
        result = import_table_data_api(table_name, headers, rows)
        
        if result.get('success'):
            return jsonify({
                'message': 'Invitations imported successfully',
                'count': len(rows)
            }), 200
        else:
            return jsonify({'error': result.get('error')}), 500
            
    except Exception as e:
        logger.error(f"Error importing invitations: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/import/membres', methods=['POST'])
@jwt_required()
@handle_db_errors
def import_membres():
    """Import members from CSV or Excel file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        table_name = 'MEMBRE'
        headers = None
        rows = []
        
        if file.filename.endswith('.csv'):
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            reader = csv.reader(stream)
            headers = next(reader)
            rows = list(reader)
        else:
            df = pd.read_excel(file)
            headers = df.columns.tolist()
            rows = df.values.tolist()
        
        result = import_table_data_api(table_name, headers, rows)
        
        if result.get('success'):
            return jsonify({
                'message': 'Members imported successfully',
                'count': len(rows)
            }), 200
        else:
            return jsonify({'error': result.get('error')}), 500
            
    except Exception as e:
        logger.error(f"Error importing members: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/import/historique', methods=['POST'])
@jwt_required()
@handle_db_errors
def import_historique():
    """Import history from CSV or Excel file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        table_name = 'HISTORIQUE'
        headers = None
        rows = []
        
        if file.filename.endswith('.csv'):
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            reader = csv.reader(stream)
            headers = next(reader)
            rows = list(reader)
        else:
            df = pd.read_excel(file)
            headers = df.columns.tolist()
            rows = df.values.tolist()
        
        result = import_table_data_api(table_name, headers, rows)
        
        if result.get('success'):
            return jsonify({
                'message': 'History imported successfully',
                'count': len(rows)
            }), 200
        else:
            return jsonify({'error': result.get('error')}), 500
            
    except Exception as e:
        logger.error(f"Error importing history: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/import/sous_taches', methods=['POST'])
@jwt_required()
@handle_db_errors
def import_sous_taches():
    """Import subtasks from CSV or Excel file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        table_name = 'SOUS_TACHES'
        headers = None
        rows = []
        
        if file.filename.endswith('.csv'):
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            reader = csv.reader(stream)
            headers = next(reader)
            rows = list(reader)
        else:
            df = pd.read_excel(file)
            headers = df.columns.tolist()
            rows = df.values.tolist()
        
        result = import_table_data_api(table_name, headers, rows)
        
        if result.get('success'):
            return jsonify({
                'message': 'Subtasks imported successfully',
                'count': len(rows)
            }), 200
        else:
            return jsonify({'error': result.get('error')}), 500
            
    except Exception as e:
        logger.error(f"Error importing subtasks: {str(e)}")
        return json

@app.route('/api/import/commentaires', methods=['POST'])
@jwt_required()
@handle_db_errors
def import_commentaires():
    """Import comments from CSV or Excel file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        table_name = 'COMMENTAIRES'
        headers = None
        rows = []
        
        if file.filename.endswith('.csv'):
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            reader = csv.reader(stream)
            headers = next(reader)
            rows = list(reader)
        else:
            df = pd.read_excel(file)
            headers = df.columns.tolist()
            rows = df.values.tolist()
        
        result = import_table_data_api(table_name, headers, rows)
        
        if result.get('success'):
            return jsonify({
                'message': 'Comments imported successfully',
                'count': len(rows)
            }), 200
        else:
            return jsonify({'error': result.get('error')}), 500
            
    except Exception as e:
        logger.error(f"Error importing comments: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/import/google_agenda', methods=['POST'])
@jwt_required()
@handle_db_errors
def import_google_agenda():
    """Import Google Calendar synchronization data from CSV or Excel file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        table_name = 'GOOGLE_AGENDA'
        headers = None
        rows = []
        
        if file.filename.endswith('.csv'):
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            reader = csv.reader(stream)
            headers = next(reader)
            rows = list(reader)
        else:
            df = pd.read_excel(file)
            headers = df.columns.tolist()
            rows = df.values.tolist()
        
        result = import_table_data_api(table_name, headers, rows)
        
        if result.get('success'):
            return jsonify({
                'message': 'Google Calendar data imported successfully',
                'count': len(rows)
            }), 200
        else:
            return jsonify({'error': result.get('error')}), 500
            
    except Exception as e:
        logger.error(f"Error importing Google Calendar data: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/import/google_tache', methods=['POST'])
@jwt_required()
@handle_db_errors
def import_google_tache():
    """Import Google Tasks synchronization data from CSV or Excel file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        table_name = 'GOOGLE_TACHE'
        headers = None
        rows = []
        
        if file.filename.endswith('.csv'):
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            reader = csv.reader(stream)
            headers = next(reader)
            rows = list(reader)
        else:
            df = pd.read_excel(file)
            headers = df.columns.tolist()
            rows = df.values.tolist()
        
        result = import_table_data_api(table_name, headers, rows)
        
        if result.get('success'):
            return jsonify({
                'message': 'Google Tasks data imported successfully',
                'count': len(rows)
            }), 200
        else:
            return jsonify({'error': result.get('error')}), 500
            
    except Exception as e:
        logger.error(f"Error importing Google Tasks data: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/import/tache_user', methods=['POST'])
@jwt_required()
@handle_db_errors
def import_tache_user():
    """Import task-user assignments from CSV or Excel file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        table_name = 'TACHE_USER'
        headers = None
        rows = []
        
        if file.filename.endswith('.csv'):
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            reader = csv.reader(stream)
            headers = next(reader)
            rows = list(reader)
        else:
            df = pd.read_excel(file)
            headers = df.columns.tolist()
            rows = df.values.tolist()
        
        result = import_table_data_api(table_name, headers, rows)
        
        if result.get('success'):
            return jsonify({
                'message': 'Task-user assignments imported successfully',
                'count': len(rows)
            }), 200
        else:
            return jsonify({'error': result.get('error')}), 500
            
    except Exception as e:
        logger.error(f"Error importing task-user assignments: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/import/all', methods=['POST'])
@jwt_required()
@handle_db_errors
def import_all_data():
    """Import all data from a single CSV or Excel file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file format'}), 400
        
        imported_data = {}
        
        if file.filename.endswith('.csv'):
            # Process CSV file
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            reader = csv.reader(stream)
            
            current_table = None
            headers = None
            rows = []
            
            for row in reader:
                if not row:  # Skip empty rows
                    continue
                    
                if row[0].startswith("TABLE:"):
                    # If we have data from previous table, import it
                    if current_table and headers and rows:
                        result = import_table_data_api(current_table, headers, rows)
                        imported_data[current_table] = {
                            'success': result.get('success', False),
                            'count': len(rows)
                        }
                    
                    # Start new table
                    current_table = row[0].split(":")[1].strip()
                    headers = next(reader)  # Next row contains headers
                    rows = []
                else:
                    rows.append(row)
            
            # Import last table
            if current_table and headers and rows:
                result = import_table_data_api(current_table, headers, rows)
                imported_data[current_table] = {
                    'success': result.get('success', False),
                    'count': len(rows)
                }
                
        else:
            # Process Excel file
            df_dict = pd.read_excel(file, sheet_name=None)
            
            for sheet_name, df in df_dict.items():
                if not sheet_name.strip():  # Skip empty sheet names
                    continue
                    
                headers = df.columns.tolist()
                rows = df.values.tolist()
                
                result = import_table_data_api(sheet_name, headers, rows)
                imported_data[sheet_name] = {
                    'success': result.get('success', False),
                    'count': len(rows)
                }
        
        return jsonify({
            'message': 'Data import completed',
            'details': imported_data
        }), 200
        
    except Exception as e:
        logger.error(f"Error importing all data: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/')
def index():
    """Page d'accueil avec documentation complète de l'API"""
    return jsonify({
        'name': 'TodoList API',
        'version': '1.0.0',
        'description': 'API de la To Do List collaborative',
        'endpoints': {
            'auth': {
                'register': {
                    'url': '/auth/register',
                    'method': 'POST',
                    'description': 'Inscription d\'un nouvel utilisateur',
                    'required_fields': ['nom', 'prenom', 'mail', 'username', 'mdp']
                },
                'login': {
                    'url': '/auth/login',
                    'method': 'POST',
                    'description': 'Connexion utilisateur',
                    'required_fields': ['username', 'mdp']
                },
                'refresh': {
                    'url': '/auth/refresh',
                    'method': 'POST',
                    'description': 'Rafraîchissement du token JWT'
                },
                'logout': {
                    'url': '/auth/logout',
                    'method': 'POST',
                    'description': 'Déconnexion utilisateur'
                }
            },
            'users': {
                'current': {
                    'url': '/users/me',
                    'method': 'GET',
                    'description': 'Informations sur l\'utilisateur courant'
                },
                'list': {
                    'url': '/users',
                    'method': 'GET',
                    'description': 'Liste des utilisateurs',
                    'query_params': {
                        'page': 'Numéro de page (défaut: 1)',
                        'per_page': 'Nombre d\'éléments par page (défaut: 10, max: 100)'
                    }
                },
                'manage': {
                    'url': '/users/<id>',
                    'methods': ['GET', 'PUT', 'DELETE'],
                    'description': 'Gestion d\'un utilisateur spécifique'
                },
                'assigned_tasks': {
                    'url': '/users/<id>/tasks',
                    'method': 'GET',
                    'description': 'Liste des tâches assignées à l\'utilisateur'
                }
            },
            'groupes': {
                'list': {
                    'url': '/groupes',
                    'method': 'GET',
                    'description': 'Liste des groupes de l\'utilisateur'
                },
                'create': {
                    'url': '/groupes',
                    'method': 'POST',
                    'description': 'Création d\'un nouveau groupe',
                    'required_fields': ['nom']
                },
                'manage': {
                    'url': '/groupes/<id>',
                    'methods': ['GET', 'PUT', 'DELETE'],
                    'description': 'Gestion d\'un groupe spécifique'
                }
            },
            'dossiers': {
                'list': {
                    'url': '/groupes/<id>/dossiers',
                    'method': 'GET',
                    'description': 'Liste des dossiers d\'un groupe'
                },
                'create': {
                    'url': '/groupes/<id>/dossiers',
                    'method': 'POST',
                    'description': 'Création d\'un nouveau dossier',
                    'required_fields': ['nom']
                },
                'manage': {
                    'url': '/dossiers/<id>',
                    'methods': ['GET', 'PUT', 'DELETE'],
                    'description': 'Gestion d\'un dossier spécifique'
                }
            },
            'taches': {
                'list': {
                    'url': '/dossiers/<id>/taches',
                    'method': 'GET',
                    'description': 'Liste des tâches d\'un dossier',
                    'query_params': {
                        'page': 'Numéro de page',
                        'per_page': 'Éléments par page',
                        'statut': 'Filtre par statut',
                        'priorite': 'Filtre par priorité',
                        'sort_by': 'Tri (date_creation, priorite, etc)',
                        'sort_order': 'Ordre de tri (asc/desc)'
                    }
                },
                'create': {
                    'url': '/dossiers/<id>/taches',
                    'method': 'POST',
                    'description': 'Création d\'une nouvelle tâche',
                    'required_fields': ['titre'],
                    'optional_fields': ['sous_titre', 'texte', 'date_fin', 'priorite', 'statut', 'etiquettes', 'users']
                },
                'manage': {
                    'url': '/taches/<id>',
                    'methods': ['GET', 'PUT', 'DELETE'],
                    'description': 'Gestion d\'une tâche spécifique'
                },
                'get_users': {
                    'url': '/taches/<id>/users',
                    'method': 'GET',
                    'description': 'Liste des utilisateurs assignés à une tâche'
                },
                'get_labels': {
                    'url': '/taches/<id>/etiquettes',
                    'method': 'GET',
                    'description': 'Liste des étiquettes d\'une tâche'
                }
            },
            'sous_taches': {
                'list': {
                    'url': '/taches/<id>/sous-taches',
                    'method': 'GET',
                    'description': 'Liste des sous-tâches'
                },
                'create': {
                    'url': '/taches/<id>/sous-taches',
                    'method': 'POST',
                    'description': 'Création d\'une sous-tâche',
                    'required_fields': ['titre'],
                    'optional_fields': ['priorite', 'date_fin', 'statut']
                },
                'manage': {
                    'url': '/sous-taches/<id>',
                    'methods': ['GET', 'PUT', 'DELETE'],
                    'description': 'Gestion d\'une sous-tâche'
                }
            },
            'commentaires': {
                'list': {
                    'url': '/taches/<id>/commentaires',
                    'method': 'GET',
                    'description': 'Liste des commentaires d\'une tâche',
                },
                'create': {
                    'url': '/taches/<id>/commentaires',
                    'method': 'POST',
                    'description': 'Ajout d\'un commentaire',
                    'required_fields': ['commentaire']
                },
                'manage': {
                    'url': '/commentaires/<id>',
                    'methods': ['GET', 'PUT', 'DELETE'],
                    'description': 'Gestion d\'un commentaire'
                }
            },
            'etiquettes': {
                'list': {
                    'url': '/etiquettes',
                    'method': 'GET',
                    'description': 'Liste des étiquettes'
                },
                'create': {
                    'url': '/etiquettes',
                    'method': 'POST',
                    'description': 'Création d\'une étiquette',
                    'required_fields': ['description']
                },
                'manage': {
                    'url': '/etiquettes/<id>',
                    'methods': ['GET', 'PUT', 'DELETE'],
                    'description': 'Gestion d\'une étiquette'
                },
                'assign': {
                    'url': '/taches/<tache_id>/etiquettes/<etiquette_id>',
                    'method': 'POST',
                    'description': 'Assigner une étiquette à une tâche'
                },
                'unassign': {
                    'url': '/taches/<tache_id>/etiquettes/<etiquette_id>',
                    'method': 'DELETE',
                    'description': 'Retirer une étiquette d\'une tâche'
                }
            },
            'membres': {
                'list': {
                    'url': '/groupes/<id>/membres',
                    'method': 'GET',
                    'description': 'Liste des membres d\'un groupe'
                },
                'add': {
                    'url': '/groupes/<id>/membres',
                    'method': 'POST',
                    'description': 'Ajout d\'un membre',
                    'required_fields': ['id_user', 'role']
                },
                'manage': {
                    'url': '/membres/<id>',
                    'methods': ['PUT', 'DELETE'],
                    'description': 'Gestion d\'un membre'
                }
            },
            'invitations': {
                'list': {
                    'url': '/invitations',
                    'method': 'GET',
                    'description': 'Liste des invitations'
                },
                'create': {
                    'url': '/invitations',
                    'method': 'POST',
                    'description': 'Création d\'une invitation',
                    'required_fields': ['id_groupe', 'id_user']
                },
                'respond': {
                    'url': '/invitations/<id>',
                    'method': 'PUT',
                    'description': 'Réponse à une invitation',
                    'required_fields': ['statut']
                }
            },
            'historique': {
                'list': {
                    'url': '/historique',
                    'method': 'GET',
                    'description': 'Historique des actions de l\'utilisateur'
                },
                'task_history': {
                    'url': '/taches/<id>/historique',
                    'method': 'GET',
                    'description': 'Historique d\'une tâche spécifique'
                }
            },
            'google': {
                'agenda': {
                    'list': {
                        'url': '/google/agendas',
                        'method': 'GET',
                        'description': 'Liste des synchronisations Google Calendar'
                    },
                    'sync': {
                        'url': '/google/agendas',
                        'method': 'POST',
                        'description': 'Nouvelle synchronisation Calendar',
                        'required_fields': ['google_id_cal', 'local_id_cal']
                    },
                    'manage': {
                        'url': '/google/agendas/<id>',
                        'methods': ['GET', 'DELETE'],
                        'description': 'Gestion d\'une synchronisation'
                    }
                },
                'taches': {
                    'list': {
                        'url': '/google/taches',
                        'method': 'GET',
                        'description': 'Liste des synchronisations Google Tasks'
                    },
                    'sync': {
                        'url': '/google/taches',
                        'method': 'POST',
                        'description': 'Nouvelle synchronisation Task',
                        'required_fields': ['google_id_event', 'local_id_event']
                    },
                    'manage': {
                        'url': '/google/taches/<id>',
                        'methods': ['GET', 'DELETE'],
                        'description': 'Gestion d\'une synchronisation'
                    }
                }            
            },
            "export": {
                "all_data": {
                    "url": "/api/export/all",
                    "method": "GET",
                    "description": "Exporte toutes les données de toutes les tables"
                },
                "users": {
                    "url": "/api/export/users",
                    "method": "GET",
                    "description": "Exporte toutes les données de la table users"
                },
                "groupes": {
                    "url": "/api/export/groupes",
                    "method": "GET",
                    "description": "Exporte toutes les données de la table groupes"
                },
                "dossiers": {
                    "url": "/api/export/dossiers",
                    "method": "GET",
                    "description": "Exporte toutes les données de la table dossiers"
                },
                "taches": {
                    "url": "/api/export/taches",
                    "method": "GET",
                    "description": "Exporte toutes les données de la table taches"
                },
                "droits": {
                    "url": "/api/export/droits",
                    "method": "GET",
                    "description": "Exporte toutes les données de la table droits"
                },
                "etiquettes": {
                    "url": "/api/export/etiquettes",
                    "method": "GET",
                    "description": "Exporte toutes les données de la table etiquettes"
                },
                "tache_etiquette": {
                    "url": "/api/export/tache_etiquette",
                    "method": "GET",
                    "description": "Exporte toutes les données de la table de relation tâches-étiquettes"
                },
                "invitations": {
                    "url": "/api/export/invitations",
                    "method": "GET",
                    "description": "Exporte toutes les données de la table invitations"
                },
                "membres": {
                    "url": "/api/export/membres",
                    "method": "GET",
                    "description": "Exporte toutes les données de la table membres"
                },
                "historique": {
                    "url": "/api/export/historique",
                    "method": "GET",
                    "description": "Exporte toutes les données de la table historique"
                },
                "sous_taches": {
                    "url": "/api/export/sous_taches",
                    "method": "GET",
                    "description": "Exporte toutes les données de la table sous_taches"
                },
                "commentaires": {
                    "url": "/api/export/commentaires",
                    "method": "GET",
                    "description": "Exporte toutes les données de la table commentaires"
                },
                "google_agenda": {
                    "url": "/api/export/google_agenda",
                    "method": "GET",
                    "description": "Exporte toutes les données de la table google_agenda"
                },
                "google_tache": {
                    "url": "/api/export/google_tache",
                    "method": "GET",
                    "description": "Exporte toutes les données de la table google_tache"
                },
                "tache_user": {
                    "url": "/api/export/tache_user",
                    "method": "GET",
                    "description": "Exporte toutes les données de la table tache_user"
                }
            },
            "task_management": {
                "assign_task": {
                    "url": "/taches/<id>/assign",
                    "method": "POST",
                    "description": "Assigne une tâche à un utilisateur",
                    "required_fields": ["user_id"]
                },
                "unassign_task": {
                    "url": "/taches/<id>/unassign/<user_id>",
                    "method": "DELETE",
                    "description": "Désassigne un utilisateur d'une tâche"
                }
            },
            "droits": {
                "list": {
                    "url": "/droits",
                    "method": "GET",
                    "description": "Liste des droits d'accès"
                },
                "create": {
                    "url": "/droits",
                    "method": "POST",
                    "description": "Création d'un nouveau droit d'accès",
                    "required_fields": ["id_user", "id_tache", "droit"]
                },
                "manage": {
                    "url": "/droits/<id>",
                    "methods": ["GET", "PUT", "DELETE"],
                    "description": "Gestion d'un droit d'accès"
                }
            }
        },
        'authentication': {
            'type': 'JWT Bearer Token',
            'description': 'Utiliser le token dans le header Authorization: Bearer <token>'
        },
        'security': {
            'cors': {
                'origins': ['http://localhost:3000'],
                'methods': ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
                'headers': ['Content-Type', 'Authorization']
            },
            'rate_limiting': {
                'default': '200 per minute',
                'auth': '10 per minute'
            },
            'input_validation': 'Validation des données entrantes avec des schémas',
            'sql_injection': 'Protection contre les injections SQL',
            'xss': 'Protection contre les attaques XSS'
        },
        'error_handling': {
            '400': 'Bad Request - Requête invalide',
            '401': 'Unauthorized - Non authentifié',
            '403': 'Forbidden - Non autorisé',
            '404': 'Not Found - Ressource non trouvée',
            '429': 'Too Many Requests - Trop de requêtes',
            '500': 'Internal Server Error - Erreur serveur'
        },
        'documentation': {
            'health': '/health'
        }
    })

if __name__ == '__main__':
    app.run(ssl_context='adhoc', host='0.0.0.0', port=5000)
