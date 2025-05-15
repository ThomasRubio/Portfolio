class AppConfig:
    """
    Configuration globale de l'application.
    
    Cette classe contient toutes les constantes et paramètres
    qui doivent être accessibles dans toute l'application.
    
    Attributes:
        API_BASE_URL (str): URL de base de l'API
        VERIFY_SSL (bool): Vérification des certificats SSL
        API_TIMEOUT (int): Timeout des requêtes API en secondes
        DEFAULT_HEADERS (dict): En-têtes HTTP par défaut
    """
    
    # URL de base de l'API
    API_BASE_URL = "https://ec2-13-39-24-139.eu-west-3.compute.amazonaws.com"
    
    # Configuration SSL
    VERIFY_SSL = False
    
    # Timeout des requêtes (en secondes)
    API_TIMEOUT = 30
    
    # En-têtes par défaut
    DEFAULT_HEADERS = {
        'Content-Type': 'application/json'
    }
    
    # Points d'entrée de l'API
    API_ENDPOINTS = {
        'login': '/auth/login',
        'register': '/auth/register',
        'user_info': '/users/me',
        'refresh_token': '/auth/refresh',
        'logout': '/auth/logout'
    }
    
    @classmethod
    def get_full_url(cls, endpoint):
        """
        Construit l'URL complète pour un point d'entrée donné.
        
        Args:
            endpoint (str): Point d'entrée de l'API
            
        Returns:
            str: URL complète
        """
        return f"{cls.API_BASE_URL}{endpoint}"
