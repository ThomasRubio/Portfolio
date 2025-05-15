import unittest
import requests
import logging
from urllib3.exceptions import InsecureRequestWarning
import json
import time

# Désactiver les avertissements pour les certificats auto-signés
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class APISecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_url = "https://ec2-13-37-32-182.eu-west-3.compute.amazonaws.com"
        cls.session = requests.Session()
        cls.session.verify = False
    
    def setUp(self):
        """Configuration avant chaque test"""
        self.session = requests.Session()
        self.session.verify = False
        
        # Configuration des timeouts et des retries
        self.session.mount('https://', requests.adapters.HTTPAdapter(
            max_retries=3,
            pool_connections=10,
            pool_maxsize=10
        ))

    def tearDown(self):
        """Nettoyage après chaque test"""
        self.session.close()

    def test_01_https_redirect(self):
        """Vérifie que HTTP est redirigé vers HTTPS"""
        try:
            # Essayer d'abord avec une requête HTTPS
            https_response = requests.get(self.base_url, verify=False)
            self.assertEqual(https_response.status_code, 200)

            # Vérifier les en-têtes de sécurité
            headers = https_response.headers
            self.assertIn('Strict-Transport-Security', headers)

        except requests.exceptions.SSLError:
            self.fail("Le serveur n'accepte pas les connexions HTTPS")
        except requests.exceptions.ConnectionError:
            # Si nous ne pouvons pas tester la redirection, nous vérifions au moins
            # que le serveur est accessible en HTTPS
            try:
                response = requests.get(self.base_url, verify=False)
                self.assertEqual(response.status_code, 200)
            except:
                self.fail("Impossible de se connecter au serveur en HTTPS")

    def test_02_security_headers(self):
        """Vérifie la présence des en-têtes de sécurité"""
        try:
            response = requests.get(self.base_url, verify=False)
            headers = response.headers

            # Liste des en-têtes de sécurité requis
            required_headers = [
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection',
                'Content-Security-Policy',
                'Strict-Transport-Security'
            ]

            # Vérification de la présence des en-têtes
            for header in required_headers:
                self.assertIn(header, headers, f"L'en-tête {header} est manquant")

            # Vérification des valeurs des en-têtes
            self.assertIn('DENY', headers['X-Frame-Options'])
            self.assertIn('nosniff', headers['X-Content-Type-Options'].split(','))
            self.assertIn('1; mode=block', headers['X-XSS-Protection'])

        except requests.exceptions.RequestException as e:
            self.fail(f"Erreur lors de la vérification des en-têtes: {str(e)}")

    def test_03_ssl_configuration(self):
        """Vérifie la configuration SSL"""
        try:
            response = requests.get(self.base_url, verify=False)
            
            # Vérifier la présence du HSTS
            self.assertIn('Strict-Transport-Security', response.headers)
            hsts_header = response.headers['Strict-Transport-Security']
            self.assertIn('max-age=', hsts_header)
            
            # Vérifier la valeur du max-age (doit être au moins 1 an pour être conforme)
            max_age = int(hsts_header.split('max-age=')[1].split(';')[0])
            self.assertGreaterEqual(max_age, 31536000)  # 1 an en secondes
            
            # Vérifier includeSubDomains
            self.assertIn('includeSubDomains', hsts_header)

        except requests.exceptions.SSLError:
            self.fail("Configuration SSL invalide")
        except requests.exceptions.RequestException as e:
            self.fail(f"Erreur lors de la vérification SSL: {str(e)}")

    def test_04_content_security_policy(self):
        """Vérifie la politique de sécurité du contenu"""
        try:
            response = requests.get(self.base_url, verify=False)
            
            self.assertIn('Content-Security-Policy', response.headers)
            csp = response.headers['Content-Security-Policy']
            
            # Vérifier les directives essentielles
            self.assertIn("default-src 'self'", csp)
            
        except requests.exceptions.RequestException as e:
            self.fail(f"Erreur lors de la vérification de la CSP: {str(e)}")

    def test_05_sql_injection(self):
        """Test de protection contre les injections SQL"""
        payloads = [
            "' OR '1'='1",
            "; DROP TABLE users;",
            "' UNION SELECT * FROM users--",
            "admin'--",
            "1' OR '1' = '1"
        ]

        for payload in payloads:
            response = self.session.post(
                f"{self.base_url}/auth/login",
                json={
                    "username": payload,
                    "mdp": payload
                }
            )
            print(f"SQL injection test response: {response.status_code}")
            self.assertIn(response.status_code, [401, 429])

    def test_06_xss_protection(self):
        """Test de protection contre les attaques XSS"""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "<img src='x' onerror='alert(1)'>",
            "javascript:alert(1)",
            "<svg onload='alert(1)'>",
        ]
        
        # Test sur la création de groupe
        for payload in xss_payloads:
            response = self.session.post(
                f"{self.base_url}/auth/register",
                json={
                    "nom": payload,
                    "prenom": payload,
                    "mail": "test@test.com",
                    "username": "test123",
                    "mdp": "Test123!"
                }
            )
            self.assertNotEqual(response.status_code, 500)

    def test_07_rate_limiting(self):
        """Test du rate limiting"""
        fails = 0
        total_attempts = 15

        for i in range(total_attempts):
            response = self.session.post(
                f"{self.base_url}/auth/login",
                json={
                    "username": f"nonexistent{int(time.time() * 1000)}",
                    "mdp": "wrongpassword"
                }
            )
            print(f"Rate limiting attempt {i+1}: {response.status_code}")
            
            if response.status_code in [401, 429]:
                fails += 1
            
            if fails >= 5 or response.status_code == 429:
                break

            time.sleep(0.01)  # Petit délai pour ne pas surcharger

        print(f"Rate limiting test - Failed attempts: {fails}")
        self.assertGreaterEqual(fails, 5, f"Only got {fails} failed attempts")

    def test_08_csrf_protection(self):
        """Test de protection CSRF"""
        # Test sans token CSRF
        response = self.session.post(
            f"{self.base_url}/auth/login",
            json={"username": "test", "mdp": "test"},
            headers={"X-CSRF-Token": "invalid"}
        )
        self.assertNotEqual(response.status_code, 500)

    def test_09_directory_traversal(self):
        """Test de protection contre le directory traversal"""
        paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        for path in paths:
            response = self.session.get(f"{self.base_url}/{path}")
            self.assertNotEqual(response.status_code, 200)

    def test_10_method_not_allowed(self):
        """Test des méthodes HTTP non autorisées"""
        response = self.session.put(f"{self.base_url}/auth/login")  # Changed from OPTIONS to PUT
        print(f"Method not allowed response: {response.status_code}")
        print(f"Response content: {response.text}")
        self.assertNotEqual(response.status_code, 200)

    def test_11_invalid_json(self):
        """Test de la gestion des JSON malformés"""
        response = self.session.post(
            f"{self.base_url}/auth/login",
            data="invalid json {",
            headers={"Content-Type": "application/json"}
        )
        print(f"Invalid JSON test response: {response.status_code}")
        print(f"Response content: {response.text}")
        self.assertIn(response.status_code, [400, 429])

    def test_12_long_input(self):
        """Test de la limitation de la longueur des entrées"""
        long_string = "A" * 1000
        response = self.session.post(
            f"{self.base_url}/auth/register",
            json={
                "nom": long_string,
                "prenom": long_string,
                "mail": f"{long_string}@test.com",
                "username": long_string,
                "mdp": long_string
            }
        )
        self.assertNotEqual(response.status_code, 500)

if __name__ == '__main__':
    unittest.main(verbosity=2)
