# TodoList API Documentation

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/Python-3.8%2B-brightgreen.svg)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-green.svg)
![Coverage](https://img.shields.io/badge/coverage-99%25-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Table des matières

1. [Vue d'ensemble](#vue-densemble)
2. [Architecture](#architecture)
3. [Modèle de données](#modèle-de-données)
4. [Sécurité et Authentification](#sécurité-et-authentification)
5. [API Reference](#api-reference)
6. [Déploiement](#déploiement)
7. [Tests](#tests)
8. [Monitoring](#monitoring)
9. [Maintenance](#maintenance)

## Vue d'ensemble

TodoList API est une solution complète de gestion de tâches collaborative offrant :
- Gestion hiérarchique des tâches (Groupes > Dossiers > Tâches)
- Système de permissions avancé
- Intégration avec Google Calendar
- Historique complet des actions
- API RESTful sécurisée

### Prérequis techniques
- Python 3.8+
- MySQL 5.7+
- Redis (optionnel)
- Serveur HTTPS
- AWS (EC2, RDS, ELB)

## Architecture

### Vue d'ensemble du système

```mermaid
%%{init: {'theme': 'neutral'}}%%
graph TD
    subgraph Infrastructure
        Client[Client Applications]
        LB[AWS Load Balancer]
        EC2[EC2 Instance]
        RDS[(AWS RDS MySQL)]
        Cache[(Redis Cache)]
    end
    
    subgraph Application Components
        HTTPD[Apache HTTPD]
        Gunicorn[Gunicorn WSGI]
        Flask[Flask API]
        Auth[JWT Auth]
        ORM[SQLAlchemy]
    end

    Client -->|HTTPS| LB
    LB -->|HTTP| EC2
    EC2 --> HTTPD
    HTTPD -->|Proxy| Gunicorn
    Gunicorn --> Flask
    Flask --> Auth
    Flask --> ORM
    ORM --> RDS
    Flask -->|Optional| Cache

classDef aws fill:#FF9900,stroke:#232F3E,stroke-width:2px;
classDef app fill:#00A4EF,stroke:#232F3E,stroke-width:2px,color:white;
classDef db fill:#3B48CC,stroke:#232F3E,stroke-width:2px,color:white;

class LB,EC2,RDS aws;
class Flask,Auth,ORM app;
class Cache db;
```

### Composants principaux

1. **Frontend Proxy (Apache)**
   - Gestion SSL/TLS
   - Reverse proxy
   - Compression gzip
   - Cache statique

2. **Application Server (Gunicorn)**
   - 3 workers
   - 2 threads par worker
   - Timeout de 120s
   - Keepalive de 5s

3. **API Layer (Flask)**
   - Routing
   - Middleware
   - Validation
   - Sérialisation

4. **Database (MySQL)**
   - Tables relationnelles
   - Indexation optimisée
   - Contraintes d'intégrité
   - Backup automatisé

## Modèle de données

### Schéma relationnel

```mermaid
erDiagram
    USER ||--o{ GROUPE : "owns"
    USER ||--o{ TACHES : "creates"
    USER ||--o{ MEMBRE : "is"
    USER ||--o{ COMMENTAIRE : "writes"
    GROUPE ||--o{ DOSSIER : "contains"
    GROUPE ||--o{ MEMBRE : "has"
    GROUPE ||--o{ INVITATION : "has"
    DOSSIER ||--o{ TACHES : "contains"
    TACHES ||--o{ SOUS_TACHES : "has"
    TACHES ||--o{ COMMENTAIRE : "has"
    TACHES ||--o{ DROIT : "has"
    TACHES }|--|| GOOGLE_TACHE : "syncs"
    DOSSIER }|--|| GOOGLE_AGENDA : "syncs"
    TACHES ||--o{ HISTORIQUE : "tracks"
    
    USER {
        integer id_user PK
        string nom
        string prenom
        string mail
        string username
        string mdp
    }
    
    GROUPE {
        integer id_groupe PK
        string nom
        timestamp synchro
        integer id_user FK
        datetime date_creation
    }
    
    DOSSIER {
        integer id_dossier PK
        string nom
        integer id_groupe FK
    }
    
    TACHES {
        integer id_tache PK
        string titre
        string sous_titre
        string texte
        datetime date_debut
        datetime date_fin
        integer priorite
        integer statut
    }
    
    HISTORIQUE {
        integer id_historique PK
        integer id_tache FK
        integer id_user FK
        string action
        timestamp date
    }
```

### Entités principales

1. **User**
```typescript
interface User {
    id_user: number;
    nom: string;
    prenom: string;
    mail: string;
    username: string;
    mdp: string;
    otp_enabled: boolean;
    otp_secret?: string;
}
```

2. **Groupe**
```typescript
interface Groupe {
    id_groupe: number;
    nom: string;
    synchro: Date;
    id_user: number;
    date_creation: Date;
    permissions: number;
}
```

3. **Tache**
```typescript
interface Tache {
    id_tache: number;
    titre: string;
    sous_titre?: string;
    texte?: string;
    date_debut: Date;
    date_fin?: Date;
    priorite: number;
    statut: number;
    id_dossier: number;
    id_user: number;
}
```

## Sécurité et Authentification

### Flux d'authentification

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant Auth
    participant DB
    
    Client->>API: POST /auth/register
    API->>Auth: Validate credentials
    Auth->>DB: Create user
    DB-->>Auth: User created
    Auth-->>API: Generate JWT
    API-->>Client: Return token
    
    Client->>API: POST /auth/login
    API->>Auth: Verify credentials
    Auth->>DB: Check user
    DB-->>Auth: User found
    Auth-->>API: Generate JWT
    API-->>Client: Return token
    
    Client->>API: API Request with JWT
    API->>Auth: Validate token
    Auth-->>API: Token valid
    API->>DB: Process request
    DB-->>API: Return data
    API-->>Client: Return response
```

### Sécurité implémentée

1. **Authentification**
   - JWT avec rotation des tokens
   - Rate limiting
   - Validation des sessions
   - 2FA (optionnel)

2. **Transport**
   - HTTPS obligatoire
   - HSTS enabled
   - En-têtes de sécurité

3. **Data**
   - Validation des entrées
   - Échappement des caractères spéciaux
   - Protection XSS/CSRF
   - Sanitization des inputs

### En-têtes de sécurité
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
```

## API Reference

### Authentification

#### Login
```http
POST /auth/login
Content-Type: application/json

{
    "username": "user@example.com",
    "mdp": "password123"
}

Response 200:
{
    "token": "eyJhbGciOiJIUzI1...",
    "user": {
        "id": 1,
        "username": "user@example.com"
    }
}
```

### Gestion des groupes

#### Créer un groupe
```http
POST /groupes
Authorization: Bearer {token}
Content-Type: application/json

{
    "nom": "Mon Groupe",
    "permissions": 0
}

Response 201:
{
    "id_groupe": 1,
    "nom": "Mon Groupe",
    "date_creation": "2024-12-08T10:00:00Z"
}
```

### Gestion des tâches

#### Créer une tâche
```http
POST /dossiers/{dossier_id}/taches
Authorization: Bearer {token}
Content-Type: application/json

{
    "titre": "Ma tâche",
    "priorite": 1,
    "date_fin": "2024-12-31T23:59:59Z"
}
```

### Pagination et filtrage

Tous les endpoints supportent la pagination et le filtrage :

```http
GET /taches?page=1&per_page=10&statut=0&priorite=1&sort_by=date_creation&sort_order=desc
```

### Codes d'erreur

| Code | Description | Solution |
|------|-------------|----------|
| 400  | Requête invalide | Vérifier les données envoyées |
| 401  | Non authentifié | Renouveler le token |
| 403  | Non autorisé | Vérifier les permissions |
| 404  | Non trouvé | Vérifier l'ID de la ressource |
| 429  | Trop de requêtes | Respecter le rate limiting |

## Déploiement

### Configuration serveur

1. **Gunicorn**
```python
# gunicorn_config.py
bind = "0.0.0.0:5000"
workers = 3
threads = 2
worker_class = 'sync'
timeout = 120
keepalive = 5
```

2. **Apache**
```apache
<VirtualHost *:443>
    ServerName https://ec2-13-39-24-139.eu-west-3.compute.amazonaws.com/
    SSLEngine on
    ProxyPass / http://localhost:5000/
</VirtualHost>
```

### Variables d'environnement

```bash
# Required
DATABASE_URL=mysql+pymysql://user:password@host:port/db
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret

# Optional
REDIS_URL=redis://localhost:6379/0
```

## Tests

### Structure

```plaintext
tests/
├── test_api.py           # Tests fonctionnels
├── test_api_security.py  # Tests de sécurité
└── run_tests.py         # Script d'exécution
```

### Types de tests

1. **Tests fonctionnels**
   - CRUD des entités
   - Workflows métier
   - Validations
   - Permissions

2. **Tests de sécurité**
   - Authentification
   - Injection SQL
   - XSS
   - CSRF
   - Rate limiting

### Exécution

```bash
# Tests complets avec couverture
python run_tests.py

# Tests spécifiques
python -m unittest test_api.py
python -m unittest test_api_security.py
```

## Monitoring

### Métriques clés

1. **Performance**
   - Temps de réponse
   - Taux d'erreur
   - Utilisation CPU/RAM
   - Connexions DB

2. **Sécurité**
   - Tentatives de connexion
   - Violations CORS
   - Rate limiting
   - Erreurs JWT

### Logs

```plaintext
/var/log/todolist/
├── access.log
├── error.log
├── security.log
└── app.log
```

### Alertes

Configuration CloudWatch :
```json
{
    "MetricFilters": [
        {
            "FilterPattern": "[timestamp, status_code=5*]",
            "MetricName": "ServerErrors",
            "MetricNamespace": "TodoList"
        }
    ]
}
```

## Maintenance

### Backups

1. **Database**
   - Snapshots RDS quotidiens
   - Rétention 7 jours
   - Backup manuel avant migrations

2. **Logs**
   - Rotation quotidienne
   - Compression après 7 jours
   - Archivage après 30 jours

### Mises à jour

```bash
# 1. Backup
mysqldump -u user -p todolist > backup.sql

# 2. Update code
git pull origin main

# 3. Dependencies
pip install -r requirements.txt

# 4. Migrations
flask db upgrade

# 5. Restart
sudo systemctl restart gunicorn
```


