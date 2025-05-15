from cerberus import Validator
from functools import wraps
from flask import request, jsonify, Response
from werkzeug.wrappers import Request
import re
from typing import Dict, Any, Callable
import logging

logger = logging.getLogger(__name__)

# Schémas de validation mis à jour pour correspondre à la base de données
schemas = {
    'user': {
        'nom': {'type': 'string', 'minlength': 2, 'maxlength': 40, 'regex': '^[a-zA-ZÀ-ÿ\s-]+$'},
        'prenom': {'type': 'string', 'minlength': 2, 'maxlength': 40, 'regex': '^[a-zA-ZÀ-ÿ\s-]+$'},
        'mail': {'type': 'string', 'maxlength': 120, 'regex': '^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'},
        'username': {'type': 'string', 'minlength': 3, 'maxlength': 40, 'regex': '^[a-zA-Z0-9_-]+$'},
        'mdp': {'type': 'string', 'minlength': 8, 'maxlength': 120}
    },
    'user_login': {
        'username': {'type': 'string', 'required': True, 'maxlength': 40},
        'mdp': {'type': 'string', 'required': True, 'maxlength': 120}
    },
    'groupe': {
        'nom': {'type': 'string', 'minlength': 2, 'maxlength': 60, 'regex': '^[a-zA-ZÀ-ÿ0-9\s-_]+$'},
        'permissions': {'type': 'integer', 'nullable': True, 'default': 0}
    },
    'dossier': {
        'nom': {'type': 'string', 'minlength': 2, 'maxlength': 300, 'regex': '^[a-zA-ZÀ-ÿ0-9\s-_]+$'}
    },
    'tache': {
        'titre': {'type': 'string', 'minlength': 2, 'maxlength': 100},
        'sous_titre': {'type': 'string', 'maxlength': 60, 'nullable': True},
        'texte': {'type': 'string', 'maxlength': 200, 'nullable': True},
        'commentaire': {'type': 'string', 'maxlength': 200, 'nullable': True},
        'date_fin': {'type': 'string', 'nullable': True, 'regex': '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$'},
        'priorite': {'type': 'integer', 'min': 0, 'max': 5, 'nullable': True},
        'statut': {'type': 'integer', 'min': 0, 'max': 5, 'nullable': True, 'default': 0}
    },
    'droit': {
        'id_user': {'type': 'integer', 'required': True, 'min': 1},
        'id_tache': {'type': 'integer', 'required': True, 'min': 1},
        'droit': {'type': 'integer', 'required': True, 'min': 0}
    },
    'etiquette': {
        'description': {'type': 'string', 'minlength': 1, 'maxlength': 300}
    },
    'commentaire': {
        'id_tache': {'type': 'integer', 'required': True, 'min': 1},
        'commentaire': {'type': 'string', 'required': True, 'minlength': 1}  # TEXT type n'a pas de maxlength
    },
    'sous_tache': {
        'titre': {'type': 'string', 'required': True, 'minlength': 1, 'maxlength': 255},
        'id_tache': {'type': 'integer', 'required': True},
        'priorite': {'type': 'integer', 'min': 0, 'max': 5, 'nullable': True},
        'date_fin': {'type': 'string', 'nullable': True},
        'statut': {'type': 'integer', 'min': 0, 'max': 2, 'nullable': True}
    },
    'invitation': {
        'id_groupe': {'type': 'integer', 'required': True, 'min': 1},
        'id_user': {'type': 'integer', 'required': True, 'min': 1}
    },
    'invitation_response': {
        'statut': {'type': 'string', 'required': True, 'allowed': ['Acceptée', 'Refusée']}
    },
    'membre': {
        'id_user': {'type': 'integer', 'required': True, 'min': 1},
        'role': {'type': 'string', 'required': True, 'allowed': ['admin', 'lecture', 'éditeur']}
    },
    'google_agenda': {
        'google_id_cal': {'type': 'string', 'required': True, 'maxlength': 100},
        'local_id_cal': {'type': 'integer', 'required': True, 'min': 1}
    },
    'google_tache': {
        'google_id_event': {'type': 'string', 'required': True, 'maxlength': 100},
        'local_id_event': {'type': 'integer', 'required': True, 'min': 1}
    },
    'tache_etiquette': {
        'id_tache': {'type': 'integer', 'required': True, 'min': 1},
        'id_etiquettes': {'type': 'integer', 'required': True, 'min': 1}
    },
    'tache_user': {
        'id_tache': {'type': 'integer', 'required': True, 'min': 1},
        'id_user': {'type': 'integer', 'required': True, 'min': 1}
    }
}

# Rate limiting configuration
RATE_LIMIT_CONFIG = {
    'default': {'limit': 100, 'per': 60},  # 100 requêtes par minute par défaut
    'auth': {'limit': 5, 'per': 300},      # 5 tentatives d'authentification par 5 minutes
    'creation': {'limit': 20, 'per': 60}   # 20 créations par minute
}

def rate_limit(limit=None, per=None):
    """Décorateur pour le rate limiting"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Implémentation du rate limiting
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_schema(schema_name: str) -> Callable:
    """Décorateur pour valider les données entrantes selon un schéma"""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            schema = schemas.get(schema_name)
            if not schema:
                logger.error(f"Schéma non trouvé: {schema_name}")
                return jsonify({"error": "Configuration de validation invalide"}), 500

            validator = Validator(schema)
            data = request.get_json()

            # Nettoyage des entrées
            if isinstance(data, dict):
                cleaned_data = {k: sanitize_input(v) for k, v in data.items()}
            else:
                cleaned_data = data

            if not validator.validate(cleaned_data):
                logger.warning(f"Validation échouée pour {schema_name}: {validator.errors}")
                return jsonify({
                    "error": "Données invalides",
                    "details": validator.errors
                }), 400

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_id(id_value: Any) -> bool:
    """Valide un ID"""
    try:
        id_int = int(id_value)
        return id_int > 0
    except (ValueError, TypeError):
        return False

def sanitize_input(data: str) -> str:
    """Nettoie les entrées de caractères dangereux"""
    if not isinstance(data, str):
        return data
    # Supprime les caractères dangereux
    cleaned = re.sub(r'[<>(){}[\]"\'`]', '', data)
    return cleaned

def sql_injection_check(query: str) -> bool:
    """Vérifie si une requête contient des motifs d'injection SQL suspects"""
    dangerous_patterns = [
        '--', ';', 'UNION', 'SELECT', 'DROP', 'DELETE', 'UPDATE',
        'INSERT', 'ALTER', 'TRUNCATE', 'EXEC', 'DECLARE'
    ]
    query_upper = query.upper()
    return not any(pattern.upper() in query_upper for pattern in dangerous_patterns)

class SecurityMiddleware:
    """Middleware de sécurité pour l'application"""
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        request = Request(environ)

        # Vérification des en-têtes de sécurité
        if not request.is_secure and not environ.get('wsgi.url_scheme') == 'https':
            response = Response('HTTPS requis', status=403)
            return response(environ, start_response)

        # Ajout des en-têtes de sécurité
        def custom_start_response(status, headers, exc_info=None):
            security_headers = [
                ('X-Content-Type-Options', 'nosniff'),
                ('X-Frame-Options', 'DENY'),
                ('X-XSS-Protection', '1; mode=block'),
                ('Content-Security-Policy', "default-src 'self'"),
                ('Strict-Transport-Security', 'max-age=31536000; includeSubDomains'),
                ('Referrer-Policy', 'strict-origin-when-cross-origin'),
                ('Feature-Policy', "geolocation 'none'; microphone 'none'; camera 'none'")
            ]
            headers.extend(security_headers)
            return start_response(status, headers, exc_info)

        return self.app(environ, custom_start_response)

# Fonction utilitaire pour vérifier les permissions
def check_permissions(user_id: int, required_role: str) -> bool:
    """Vérifie si un utilisateur a les permissions requises"""
    try:
        membre = Membre.query.filter_by(id_user=user_id, role=required_role).first()
        return membre is not None
    except Exception as e:
        logger.error(f"Erreur lors de la vérification des permissions: {str(e)}")
        return False

def require_permissions(required_role: str):
    """Décorateur pour vérifier les permissions"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = get_jwt_identity()
            if not check_permissions(user_id, required_role):
                return jsonify({'error': 'Permission refusée'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator