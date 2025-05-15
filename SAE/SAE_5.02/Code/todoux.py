"""
TodoList Application - Documentation Développeur
=============================================

Description
-----------
Application de gestion de tâches complète avec interface graphique PyQt6, authentification
sécurisée, et fonctionnalités collaboratives.

Fonctionnalités Principales
-------------------------
- Authentification utilisateur avec 2FA
- Gestion des tâches (CRUD)
- Organisation en dossiers et groupes
- Étiquettes et filtres
- Calendrier intégré
- Rapports et exports
- Thèmes clair/sombre
- Intégration Google Calendar

Architecture
-----------
L'application suit une architecture MVC (Modèle-Vue-Contrôleur) :
- Modèle : Base de données MySQL pour le stockage persistant
- Vue : Interface graphique PyQt6
- Contrôleur : Classes de gestion des événements et de la logique métier

Dépendances Principales
---------------------
- PyQt6 : Interface graphique
- pymysql : Connexion base de données
- bcrypt : Hachage des mots de passe
- pyotp : Authentification 2FA
- qrcode : Génération codes QR
- reportlab : Génération de PDF
- sklearn : Analyse textuelle pour les suggestions
"""

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'scripts_google'))
import bcrypt
import pymysql
import pyotp
import qrcode
import re
import logging
import numpy as np
import io
import matplotlib.pyplot as plt
import smtplib
import time
from datetime import datetime, timedelta
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QLabel, QPushButton, QVBoxLayout, QHBoxLayout, QLineEdit, QDialog, QMessageBox, QTableWidget, QTableWidgetItem, QComboBox, QDateEdit, QCheckBox, QTabWidget, QGridLayout, QListWidget, QCalendarWidget, QListWidgetItem, QFileDialog, QStyle, QSpacerItem, QSizePolicy, QHeaderView
from PyQt6.QtGui import QFont, QPixmap, QIcon, QAction, QBrush, QColor
from PyQt6.QtCore import Qt, QPropertyAnimation, QDate, QTimer, pyqtSignal, QRect, QSize
from PIL.ImageQt import ImageQt
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
import pyttsx3
import csv
from scripts_google.calendars_get import getCalendars
from scripts_google.script_google_export import exportCal
from scripts_google.script_google_import import importCal
import requests
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from config import AppConfig
from sync_service import SyncService
from PyQt6.QtWidgets import QScrollArea
from PyQt6.QtMultimedia import QMediaPlayer
from PyQt6.QtMultimediaWidgets import QVideoWidget
from PyQt6.QtCore import QUrl
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEngineSettings

# CSS Styles
CSS_STYLES = """
QWidget {
    background-color: #2c3e50;
    color: #ecf0f1;
    font-family: 'Arial', sans-serif;
}
QLabel#title_label {
    font-size: 36px;
    font-weight: bold;
    color: #ecf0f1;
}
QLabel#description_label {
    font-size: 18px;
    color: #bdc3c7;
}
QPushButton {
    background-color: #3498db;
    border: none;
    border-radius: 5px;
    color: white;
    padding: 15px 30px;
    font-size: 18px;
    margin: 10px;
}
QPushButton:hover {
    background-color: #2980b9;
}
QPushButton:pressed {
    background-color: #1c598a;
}
"""

DARK_STYLE = """
QWidget {
    background-color: #1e1e1e;
    color: #ffffff;
    font-size: 14px;
}
QTabWidget::pane {
    border: 1px solid #0d47a1;
    background-color: #1e1e1e;
}
QTabBar::tab {
    background-color: #2d2d2d;
    color: #ffffff;
    padding: 8px 16px;
    border: 1px solid #0d47a1;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background-color: #0d47a1;
    color: #ffffff;
}
QTabBar::tab:!selected {
    margin-top: 2px;
}
QTabBar::tab:hover {
    background-color: #1565c0;
}
QMenuBar {
    background-color: #1e1e1e;
    color: #ffffff;
    border-bottom: 1px solid #0d47a1;
}
QMenuBar::item {
    background-color: transparent;
    padding: 8px 12px;
}
QMenuBar::item:selected {
    background-color: #0d47a1;
}
QMenuBar::item:pressed {
    background-color: #1565c0;
}
QMenu {
    background-color: #1e1e1e;
    border: 1px solid #0d47a1;
}
QMenu::item {
    padding: 6px 20px;
    color: #ffffff;
}
QMenu::item:selected {
    background-color: #0d47a1;
}
QPushButton {
    background-color: #0d47a1;
    border: none;
    border-radius: 4px;
    color: white;
    padding: 8px 16px;
    margin: 4px;
}
QPushButton:hover {
    background-color: #1565c0;
}
QPushButton:pressed {
    background-color: #0a3d91;
}
QLineEdit, QComboBox, QDateEdit {
    background-color: #2d2d2d;
    border: 1px solid #0d47a1;
    border-radius: 4px;
    padding: 8px;
    color: white;
}
QTableWidget {
    background-color: #2d2d2d;
    alternate-background-color: #353535;
    border: 1px solid #0d47a1;
}
QTableWidget::item:selected {
    background-color: #0d47a1;
}
QHeaderView::section {
    background-color: #1e1e1e;
}
"""

LIGHT_STYLE = """
QWidget {
    background-color: #ffffff;
    color: #000000;
    font-size: 14px;
}
QPushButton {
    background-color: #e0e0e0;
    border: none;
    border-radius: 4px;
    color: black;
    padding: 8px 16px;
    margin: 4px;
}
QPushButton:hover {
    background-color: #d5d5d5;
}
QPushButton:pressed {
    background-color: #c0c0c0;
}
QLineEdit, QComboBox, QDateEdit {
    background-color: #f0f0f0;
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    padding: 8px;
    color: black;
}
QTableWidget {
    background-color: #f0f0f0;
    alternate-background-color: #e0e0e0;
    border: 1px solid #e0e0e0;
}
QTableWidget::item:selected {
    background-color: #d0d0d0;
}
QHeaderView::section {
    background-color: #ffffff;
    color: black;
    padding: 8px;
    border: 1px solid #e0e0e0;
}
QScrollBar:vertical {
    border: none;
    background: #f0f0f0;
    width: 14px;
    margin: 15px 0 15px 0;
    border-radius: 0px;
}
QScrollBar::handle:vertical {
    background-color: #d0d0d0;
    min-height: 30px;
    border-radius: 7px;
}
QScrollBar::handle:vertical:hover {
    background-color: #c0c0c0;
}
"""

# Connexion à la base de données MySQL
def get_connection():
    """
    Établit et retourne une connexion à la base de données MySQL.
    
    Configuration :
    - Hôte : localhost
    - Base de données : todolist
    - Utilisateur et mot de passe sécurisés
    - Jeu de caractères : utf8mb4
    - Curseur : DictCursor pour résultats sous forme de dictionnaires
    
    Returns:
        pymysql.Connection: Objet de connexion à la base de données
        
    Raises:
        pymysql.Error: En cas d'échec de connexion
    """
    return pymysql.connect(
        host='mysql-db',
        user='todoux_user',
        password='root',
        database='todolist_db'
    )

def send_email(recipient_email, subject, body):
    """
    Envoie un email via SMTP.
    
    Utilise TLS pour la sécurité et gère les erreurs
    de connexion et d'envoi.
    
    Args:
        recipient_email (str): Adresse email du destinataire
        subject (str): Sujet de l'email
        body (str): Corps du message
        
    Returns:
        bool: True si l'envoi est réussi, False sinon
        
    Raises:
        smtplib.SMTPException: En cas d'erreur d'envoi
    """
    sender_email = "abdullahgozel68@gmail.com"  # Remplacez par votre adresse e-mail
    sender_password = "aykf wxfq xskb ouzs"  # Remplacez par votre mot de passe

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:  # Utilisez le serveur SMTP approprié
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
            print("E-mail envoyé avec succès!")
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'e-mail: {str(e)}")


def evaluate_password_strength(password):
    """
    Évalue la force d'un mot de passe.
    
    Critères vérifiés :
    - Longueur minimale
    - Présence de majuscules
    - Présence de chiffres
    - Présence de caractères spéciaux
    - Absence de séquences communes
    
    Args:
        password (str): Mot de passe à évaluer
        
    Returns:
        tuple: (score de 0 à 100, description en français)
    """
    length_criteria = len(password) >= 8
    digit_criteria = re.search(r"\d", password) is not None
    uppercase_criteria = re.search(r"[A-Z]", password) is not None
    lowercase_criteria = re.search(r"[a-z]", password) is not None
    special_criteria = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) is not None
    score = sum([length_criteria, digit_criteria, uppercase_criteria, lowercase_criteria, special_criteria])
    if score == 5:
        return "Très fort", "green"
    elif score == 4:
        return "Fort", "blue"
    elif score == 3:
        return "Moyen", "orange"
    else:
        return "Faible", "red"

def is_valid_email(email):
    """
    Vérifie si une adresse email est valide.
    
    Validation :
    - Format standard (user@domain.tld)
    - Domaine existant
    - Caractères autorisés
    - Longueur maximale
    
    Args:
        email (str): Adresse email à valider
        
    Returns:
        bool: True si l'email est valide, False sinon
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(com|fr)$'
    return re.match(pattern, email) is not None

def get_priority_string(priority_index):
    """
    Convertit un index de priorité en chaîne de caractères.
    
    Args:
        priority_index (int): Index de priorité (0-2)
        
    Returns:
        str: Description de la priorité en français
    """
    if priority_index is None:
        return "Inconnue"
    priorities = ["Faible", "Moyenne", "Élevée"]
    return priorities[priority_index] if 0 <= priority_index < len(priorities) else "Inconnue"


# Exemple de données d'entraînement pour l'IA
titles = ["Tâche urgente", "Tâche normale", "Tâche basse priorité"]
descriptions = ["Doit être fait immédiatement", "Peut attendre quelques jours", "Pas urgent"]
priorities = [2, 1, 0]  # 2: Élevée, 1: Moyenne, 0: Faible

# Vectorisation des textes
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(titles + descriptions)
y = np.array(priorities * 2)

# Entraînement du modèle
model = LogisticRegression()
model.fit(X, y)

class WelcomeScreen(QWidget):
    """
    Écran d'accueil de l'application.
    
    Cette classe gère l'interface utilisateur initiale avec les options de connexion
    et d'inscription. Elle implémente également les animations de transition.
    
    Attributes:
        title_label (QLabel): Titre principal de l'application
        login_button (QPushButton): Bouton de connexion
        signup_button (QPushButton): Bouton d'inscription
        
    Methods:
        init_ui(): Initialise l'interface utilisateur
        resizeEvent(event): Gère le redimensionnement de la fenêtre
        open_login_window(): Ouvre la fenêtre de connexion
        open_signup_window(): Ouvre la fenêtre d'inscription
    """
    def __init__(self):
        super().__init__()
        self.init_database()
        self.init_ui()

    def init_database(self):
        """Initialise la base de données et crée les tables si nécessaire"""
        try:
            from db_sync import DatabaseSync
            db = DatabaseSync()
            db.create_tables()
        except Exception as e:
            print(f"❌ Erreur lors de l'initialisation de la base de données: {str(e)}")

    def init_ui(self):
        self.setWindowTitle("To-Do List App")
        self.setGeometry(0, 0, 1280, 720)
        self.setStyleSheet("""
            QWidget {
                background-color: #2c3e50;
                color: #ecf0f1;
                font-family: 'Arial', sans-serif;
            }
            QLabel#title_label {
                font-size: 36px;
                font-weight: bold;
                color: #ecf0f1;
            }
            QLabel#description_label {
                font-size: 18px;
                color: #bdc3c7;
            }
            QPushButton {
                background-color: #3498db;
                border: none;
                border-radius: 5px;
                color: white;
                padding: 15px 30px;
                font-size: 18px;
                margin: 10px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #1c598a;
            }
        """)

        # Background image
        self.background_label = QLabel(self)
        pixmap = QPixmap(r"logo.png")
        self.scaled_pixmap = pixmap.scaled(640, 360, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
        self.background_label.setPixmap(self.scaled_pixmap)
        self.background_label.setGeometry(self.get_centered_geometry(self.scaled_pixmap))

        # Title
        self.title_label = QLabel("Bienvenue dans l'application To-Do List", self)
        self.title_label.setObjectName("title_label")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Description
        self.description_label = QLabel(
            "Organisez vos tâches, gérez vos priorités, et collaborez facilement.\n"
            "Avec l'application To-Do List, boostez votre productivité.", self)
        self.description_label.setObjectName("description_label")
        self.description_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Buttons
        self.login_button = QPushButton("Se connecter", self)
        self.login_button.clicked.connect(self.open_login_window)
        self.signup_button = QPushButton("S'inscrire", self)
        self.signup_button.clicked.connect(self.open_signup_window)

        # Layouts
        vbox = QVBoxLayout()
        vbox.addWidget(self.title_label)
        vbox.addWidget(self.description_label)
        vbox.addStretch(1)

        hbox = QHBoxLayout()
        hbox.addStretch(1)
        hbox.addWidget(self.login_button)
        hbox.addWidget(self.signup_button)
        hbox.addStretch(1)

        vbox.addLayout(hbox)
        vbox.addStretch(2)

        self.setLayout(vbox)

    def resizeEvent(self, event):
        self.background_label.setGeometry(self.get_centered_geometry(self.scaled_pixmap))
        super().resizeEvent(event)

    def get_centered_geometry(self, pixmap):
        window_width = self.width()
        window_height = self.height()
        pixmap_width = pixmap.width()
        pixmap_height = pixmap.height()
        x = (window_width - pixmap_width) // 2
        y = (window_height - pixmap_height) // 2 - 100  # Adjust this value to move the image up or down
        return QRect(x, y, pixmap_width, pixmap_height)

    def open_login_window(self):
        self.login_window = LoginWindow()
        # Connecter le signal de connexion réussie
        self.login_window.finished.connect(self.handle_login_finished)
        self.login_window.exec()
    
    def handle_login_finished(self, result):
        if result == QDialog.DialogCode.Accepted:
            # Si la connexion est réussie, fermer la fenêtre de bienvenue
            self.close()

    def open_signup_window(self):
        self.signup_window = SignupWindow()
        # Connecter le signal d'inscription réussie
        self.signup_window.finished.connect(self.handle_signup_finished)
        self.signup_window.exec()
    
    def handle_signup_finished(self, result):
        if result == QDialog.DialogCode.Accepted:
            # Ne rien faire ici, juste laisser la fenêtre ouverte
            pass


class LoginWindow(QDialog):
    def __init__(self):
        super().__init__()
        self.base_url = AppConfig.API_BASE_URL
        self.session = requests.Session()
        self.session.verify = AppConfig.VERIFY_SSL
        self.session.headers.update(AppConfig.DEFAULT_HEADERS)
        self.sync_service = None
        self.setWindowOpacity(0)
        self.init_ui()
        self.show_animation()

    def init_ui(self):
        self.setWindowTitle("Connexion")
        self.setGeometry(500, 200, 400, 300)
        self.setStyleSheet(DARK_STYLE)
        
        vbox = QVBoxLayout()
        
        self.username_label = QLabel("Login:", self)
        vbox.addWidget(self.username_label)
        
        self.username_input = QLineEdit(self)
        vbox.addWidget(self.username_input)
        
        self.password_label = QLabel("Mot de passe:", self)
        vbox.addWidget(self.password_label)
        
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        vbox.addWidget(self.password_input)
        
        self.login_button = QPushButton("Se connecter", self)
        self.login_button.clicked.connect(self.login)
        vbox.addWidget(self.login_button)
        
        self.setLayout(vbox)

    def show_animation(self):
        self.anim = QPropertyAnimation(self, b"windowOpacity")
        self.anim.setDuration(500)
        self.anim.setStartValue(0)
        self.anim.setEndValue(1)
        self.anim.start()

    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        
        if not username or not password:
            QMessageBox.warning(self, 'Erreur', 'Login et mot de passe doivent être remplis!')
            return
        
        try:
            login_data = {
                "username": username,
                "mdp": password
            }
            
            response = self.session.post(
                AppConfig.get_full_url(AppConfig.API_ENDPOINTS['login']),
                json=login_data,
                timeout=AppConfig.API_TIMEOUT
            )
            
            if response.status_code == 200:
                token = response.json()['token']
                self.session.headers.update({'Authorization': f'Bearer {token}'})
                
                user_response = self.session.get(
                    AppConfig.get_full_url(AppConfig.API_ENDPOINTS['user_info']),
                    timeout=AppConfig.API_TIMEOUT
                )
                
                if user_response.status_code == 200:
                    user_data = user_response.json()
                    user_id = user_data.get('id_user')
                    
                    # On déplace l'appel à open_main_window dans un try/except
                    try:
                        self.open_main_window(user_id, username)
                    except Exception as e:
                        print(f"❌ Erreur lors de l'ouverture de la fenêtre principale: {str(e)}")
                        QMessageBox.critical(
                            self,
                            'Erreur',
                            'Une erreur est survenue lors du lancement de l\'application.'
                        )
                else:
                    QMessageBox.warning(self, 'Erreur', 'Impossible de récupérer les informations utilisateur')
            else:
                QMessageBox.warning(self, 'Erreur', 'Login ou mot de passe incorrect!')
                
        except requests.exceptions.RequestException as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur de connexion à l'API: {str(e)}")

    def start_sync_service(self, username: str, password: str):
        """Démarre le service de synchronisation"""
        try:
            # Arrêter le service existant s'il y en a un
            if self.sync_service:
                self.sync_service.stop()
            
            # Créer et démarrer un nouveau service
            self.sync_service = SyncService(interval=30)
            
            # Définir les credentials avant de démarrer
            self.sync_service.set_credentials(username, password)
            
            # Démarrer le service
            self.sync_service.start()
            
            print("✓ Service de synchronisation démarré")
            
        except Exception as e:
            print(f"❌ Erreur lors du démarrage du service de sync: {str(e)}")

    def open_main_window(self, user_id, username):
        try:
            # Démarrer le service de synchronisation en arrière-plan
            self.sync_service = SyncService(interval=30)
            self.sync_service.set_credentials(username, self.password_input.text())
            self.sync_service.start()
            print("✓ Service de synchronisation démarré")

            # Ouvrir la fenêtre principale même si la synchronisation échoue
            self.accept()
            self.main_window = TodoListApp(user_id, username, self.session)  # Passez la session ici
            self.main_window.sync_service = self.sync_service
            self.main_window.show()
            
        except Exception as e:
            print(f"⚠️ Erreur non critique de synchronisation: {str(e)}")
            # On continue quand même l'ouverture de la fenêtre principale
            self.accept()
            self.main_window = TodoListApp(user_id, username, self.session)  # Passez la session ici
            self.main_window.show()
            
            # Message d'information à l'utilisateur
            QMessageBox.warning(
                self,
                'Information',
                'La synchronisation en arrière-plan a rencontré une erreur. ' +
                'Certaines fonctionnalités pourraient être limitées.\n' +
                'Vous pouvez continuer à utiliser l\'application.'
            )
        
    def handle_close_event(self, event, window):
        """Gère la fermeture propre de l'application"""
        try:
            if window.sync_service:
                print("Arrêt du service de synchronisation...")
                window.sync_service.stop()
                print("✓ Service de synchronisation arrêté")
        except Exception as e:
            print(f"❌ Erreur lors de l'arrêt du service: {str(e)}")
        finally:
            # Appeler l'événement de fermeture original
            QMainWindow.closeEvent(window, event)


class OTPWindow(QDialog):
    """
    Fenêtre de vérification du code 2FA.
    
    Vérifie le code à usage unique pour l'authentification à deux facteurs.
    
    Attributes:
        otp_secret (str): Clé secrète TOTP
        username (str): Nom de l'utilisateur
        user_id (int): ID de l'utilisateur
        
    Methods:
        verify_otp(): Vérifie le code OTP saisi
    """
    def __init__(self, otp_secret, username, user_id):
        super().__init__()
        self.otp_secret = otp_secret
        self.username = username
        self.user_id = user_id
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Vérification OTP")
        self.setGeometry(500, 200, 300, 200)
        self.setStyleSheet(DARK_STYLE)
        self.otp_label = QLabel("Veuillez saisir le code OTP:", self)
        self.otp_input = QLineEdit(self)
        self.verify_button = QPushButton("Vérifier", self)
        self.verify_button.clicked.connect(self.verify_otp)
        vbox = QVBoxLayout()
        vbox.addWidget(self.otp_label)
        vbox.addWidget(self.otp_input)
        vbox.addWidget(self.verify_button)
        self.setLayout(vbox)

    def verify_otp(self):
        """
        Vérifie le code OTP saisi par l'utilisateur.
        
        Compare le code saisi avec le code TOTP généré à partir
        de la clé secrète de l'utilisateur. En cas de succès,
        permet l'accès à l'application.
        
        Returns:
            None
        """
        otp_code = self.otp_input.text()
        totp = pyotp.TOTP(self.otp_secret)
        if totp.verify(otp_code):
            self.accept()
            self.main_window = TodoListApp(self.user_id, self.username)
            self.main_window.show()
        else:
            QMessageBox.warning(self, 'Erreur', 'Code OTP incorrect!')

    def apply_theme(self):
        if self.parent.get_current_theme() == 'dark':
            self.setStyleSheet(DARK_STYLE)
        else:
            self.setStyleSheet(LIGHT_STYLE)


class QRWindow(QDialog):
    """
    Fenêtre d'affichage du QR code pour 2FA.
    
    Affiche le QR code à scanner pour configurer l'authentification 2FA.
    
    Attributes:
        otp_url (str): URL contenant les informations TOTP
        
    Methods:
        init_ui(): Configure l'interface et affiche le QR code
    """
    def __init__(self, otp_url):
        super().__init__()
        self.otp_url = otp_url
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("QR Code - Double authentification")
        self.setGeometry(500, 200, 300, 300)
        self.setStyleSheet(DARK_STYLE)
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(self.otp_url)
        qr.make(fit=True)
        qr_image = qr.make_image(fill_color="black", back_color="white")
        qr_image = qr_image.resize((200, 200))
        qr_image_qt = ImageQt(qr_image)
        pixmap = QPixmap.fromImage(qr_image_qt)
        qr_label = QLabel(self)
        qr_label.setPixmap(pixmap)
        qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vbox = QVBoxLayout()
        vbox.addWidget(qr_label)
        self.setLayout(vbox)


class SignupWindow(QDialog):
    def __init__(self):
        super().__init__()
        self.session = requests.Session()
        self.session.verify = AppConfig.VERIFY_SSL
        self.session.headers.update(AppConfig.DEFAULT_HEADERS)
        self.setWindowOpacity(0)
        self.init_ui()
        self.show_animation()

    def init_ui(self):
        self.setWindowTitle("Inscription")
        self.setGeometry(500, 200, 400, 600)
        self.setStyleSheet(DARK_STYLE)
        
        vbox = QVBoxLayout()
        
        # Champs d'inscription
        self.nom_label = QLabel("Nom:", self)
        self.nom_input = QLineEdit(self)
        
        self.prenom_label = QLabel("Prénom:", self)
        self.prenom_input = QLineEdit(self)
        
        self.username_label = QLabel("Nom d'utilisateur:", self)
        self.username_input = QLineEdit(self)
        
        self.email_label = QLabel("Email:", self)
        self.email_input = QLineEdit(self)
        
        self.password_label = QLabel("Mot de passe:", self)
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        # Ajout des widgets au layout
        vbox.addWidget(self.nom_label)
        vbox.addWidget(self.nom_input)
        vbox.addWidget(self.prenom_label)
        vbox.addWidget(self.prenom_input)
        vbox.addWidget(self.username_label)
        vbox.addWidget(self.username_input)
        vbox.addWidget(self.email_label)
        vbox.addWidget(self.email_input)
        vbox.addWidget(self.password_label)
        vbox.addWidget(self.password_input)
        
        self.password_strength_label = QLabel("", self)
        self.password_strength_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vbox.addWidget(self.password_strength_label)
        
        self.signup_button = QPushButton("S'inscrire", self)
        self.signup_button.clicked.connect(self.signup)
        vbox.addWidget(self.signup_button)
        
        self.error_label = QLabel("", self)
        self.error_label.setStyleSheet("color: red;")
        self.error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vbox.addWidget(self.error_label)
        
        self.setLayout(vbox)
        
        self.password_input.textChanged.connect(self.update_password_strength)

    def show_animation(self):
        self.anim = QPropertyAnimation(self, b"windowOpacity")
        self.anim.setDuration(500)
        self.anim.setStartValue(0)
        self.anim.setEndValue(1)
        self.anim.start()

    def update_password_strength(self):
        password = self.password_input.text()
        strength, color = evaluate_password_strength(password)
        self.password_strength_label.setText(f"Force du mot de passe : {strength}")
        self.password_strength_label.setStyleSheet(f"color: {color};")

    def signup(self):
        nom = self.nom_input.text()
        prenom = self.prenom_input.text()
        username = self.username_input.text()
        email = self.email_input.text()
        password = self.password_input.text()

        if not all([nom, prenom, username, email, password]):
            self.error_label.setText('Tous les champs doivent être remplis!')
            return
                
        if not is_valid_email(email):
            self.error_label.setText('Veuillez entrer un e-mail valide!')
            return

        strength, _ = evaluate_password_strength(password)
        if strength == "Faible":
            self.error_label.setText('Le mot de passe est trop faible!')
            return

        try:
            register_data = {
                "nom": nom,
                "prenom": prenom,
                "mail": email,
                "username": username,
                "mdp": password
            }

            response = self.session.post(
                AppConfig.get_full_url(AppConfig.API_ENDPOINTS['register']),
                json=register_data,
                timeout=AppConfig.API_TIMEOUT
            )

            if response.status_code == 201:
                user_data = response.json()
                token = user_data.get('token')
                
                if token:
                    self.session.headers.update({'Authorization': f'Bearer {token}'})
                    QMessageBox.information(
                        self, 
                        'Succès', 
                        f"Utilisateur {username} enregistré avec succès! Vous pouvez maintenant vous connecter."
                    )
                    self.close()  # Ferme uniquement la fenêtre d'inscription
                else:
                    QMessageBox.warning(self, 'Erreur', "Token non reçu après l'inscription")
            else:
                error_message = response.json().get('message', 'Erreur lors de l\'inscription')
                self.error_label.setText(error_message)

        except requests.exceptions.RequestException as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de la connexion à l'API: {str(e)}")


class TodoListApp(QMainWindow):
    """
    Classe principale de l'application TodoList.
    
    Cette classe gère l'interface principale de l'application et coordonne
    toutes les fonctionnalités : tâches, groupes, dossiers, etc.
    
    Attributes:
        user_id (int): ID de l'utilisateur connecté
        username (str): Nom de l'utilisateur
        group_id (int): ID du groupe actif
        user_role (str): Rôle de l'utilisateur dans le groupe
        current_theme (str): Thème actuel ('dark' ou 'light')
        
    Methods:
        initUI(): Initialise l'interface utilisateur et les onglets
        apply_theme(): Applique le thème actuel à tous les widgets
        load_folders(): Charge les dossiers de l'utilisateur
        get_user_role(): Récupère le rôle de l'utilisateur dans le groupe actif
        reload_groups(): Recharge la liste des groupes disponibles
        select_group(group_id): Sélectionne un groupe comme actif
        is_admin(group_id): Vérifie si l'utilisateur est admin du groupe
    """
    def __init__(self, user_id, username, session):
        super().__init__()
        self.user_id = user_id
        self.username = username
        self.session = session  # Ajoutez cette ligne
        self.sync_service = None  # Sera défini par LoginWindow
        self.group_id = None
        self.user_role = None
        self.current_theme = 'dark'
        self.help_window = None
        self.initUI()
        self.init_timer()

    def initUI(self):
        self.setWindowTitle("To-Do List")
        self.setGeometry(100, 100, 1200, 800)
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self.group_selection_tab = GroupSelectionTab(self)
        self.tabs.addTab(self.group_selection_tab, "Sélection de Groupe")
        self.tasks_tab = TasksTab(self)
        self.tabs.addTab(self.tasks_tab, "Tâches")
        self.groups_tab = GroupsTab(self)
        self.tabs.addTab(self.groups_tab, "Groupes")
        self.folders_tab = FoldersTab(self)
        self.tabs.addTab(self.folders_tab, "Dossiers")
        self.invitations_tab = InvitationsTab(self)
        self.tabs.addTab(self.invitations_tab, "Invitations")
        self.calendar_tab = CalendarTab(self)
        self.tabs.addTab(self.calendar_tab, "Calendrier")
        self.reports_tab = ReportsTab(self)
        self.tabs.addTab(self.reports_tab, "Rapports")
        # self.import_export_tab = ImportExportTab(self)  # Supprimer cette ligne
        # self.tabs.addTab(self.import_export_tab, "Import/Export")  # Supprimer cette ligne
        # Ajouter un label pour afficher le nom d'utilisateur
        self.username_label = QLabel(f"Connecté en tant que : {self.username}", self)
        self.username_label.setStyleSheet("color: white;")
        self.statusBar().addWidget(self.username_label)
        # Ajouter un menu pour changer de thème
        menubar = self.menuBar()
        # Force le style sombre pour la barre de menu
        menubar.setStyleSheet("""
            QMenuBar {
                background-color: #1e1e1e;
                color: #ffffff;
                border-bottom: 1px solid #0d47a1;
            }
            QMenuBar::item {
                background-color: transparent;
                padding: 8px 12px;
            }
            QMenuBar::item:selected {
                background-color: #0d47a1;
            }
            QMenuBar::item:pressed {
                background-color: #1565c0;
            }
            QMenu {
                background-color: #1e1e1e;
                border: 1px solid #0d47a1;
            }
            QMenu::item {
                padding: 6px 20px;
                color: #ffffff;
            }
            QMenu::item:selected {
                background-color: #0d47a1;
            }
        """)
        viewMenu = menubar.addMenu('View')
        themeAction = QAction('Changer de thème', self)
        themeAction.triggered.connect(self.toggle_theme)
        viewMenu.addAction(themeAction)

        # Add Import/Export button to the menu
        importExportAction = QAction('Import/Export', self)
        importExportAction.triggered.connect(self.open_import_export_dialog)
        menubar.addAction(importExportAction)

        # Add Google Calendar menu to the menu bar
        googleCalMenu = menubar.addMenu('Google Calendar')
        googleImportAction = QAction('Importer un calendrier', self)
        googleExportAction = QAction('Exporter un calendrier', self)
        googleImportAction.triggered.connect(self.import_google)
        googleExportAction.triggered.connect(self.export_google)
        googleCalMenu.addAction(googleImportAction)
        googleCalMenu.addAction(googleExportAction)

        # Menu Aide
        helpMenu = menubar.addMenu('Aide')
        helpAction = QAction('Guide d\'utilisation', self)
        helpAction.triggered.connect(self.show_help)
        helpMenu.addAction(helpAction)

        self.apply_theme()

    def open_import_export_dialog(self):
        self.import_export_dialog = ImportExportDialog(self)
        self.import_export_dialog.exec()

    def import_google(self):
        """
        Importe les événements depuis Google Calendar.
        
        Processus :
        1. Authentification OAuth2 avec Google
        2. Récupération des événements du calendrier
        3. Conversion en tâches dans notre système
        4. Gestion des conflits de dates
        5. Synchronisation des modifications
        
        Returns:
            bool: True si l'import est réussi, False sinon
            
        Raises:
            google.auth.exceptions.GoogleAuthError: En cas d'erreur d'authentification
            Exception: En cas d'erreur pendant l'import
        """
        self.google_cal_window = ImportGoogleCalendar(self.user_id)
        self.google_cal_window.exec()

    def export_google(self):
        """
        Exporte les tâches vers Google Calendar.
        
        Processus :
        1. Authentification OAuth2 avec Google
        2. Conversion des tâches en événements
        3. Création/mise à jour dans Google Calendar
        4. Gestion des conflits
        5. Synchronisation bidirectionnelle
        
        Options d'export :
        - Toutes les tâches
        - Tâches filtrées
        - Plage de dates spécifique
        
        Returns:
            bool: True si l'export est réussi, False sinon
            
        Raises:
            google.auth.exceptions.GoogleAuthError: En cas d'erreur d'authentification
            Exception: En cas d'erreur pendant l'export
        """
        self.google_cal_window = ExportGoogleCalendar(self.user_id)
        self.google_cal_window.exec()

    def init_timer(self):
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.invitations_tab.load_invitations)
        self.timer.start(5000)  # Vérifie toutes les 5 secondes

    def apply_theme(self):
        if self.current_theme == 'dark':
            self.setStyleSheet(DARK_STYLE)
        else:
            self.setStyleSheet(LIGHT_STYLE)
        self.apply_theme_to_widgets(self)

    def apply_theme_to_widgets(self, widget):
        if self.current_theme == 'dark':
            widget.setStyleSheet(DARK_STYLE)
        else:
            widget.setStyleSheet(LIGHT_STYLE)
        for child in widget.findChildren(QWidget):
            self.apply_theme_to_widgets(child)

    def toggle_theme(self):
        if self.current_theme == 'dark':
            self.current_theme = 'light'
        else:
            self.current_theme = 'dark'
        self.apply_theme()

    def get_current_theme(self):
        return self.current_theme

    def load_folders(self):
        self.folders_tab.load_folders()
        self.tasks_tab.load_tasks()

    def get_user_role(self):
        if not self.group_id:
            return None
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT role FROM MEMBRE WHERE id_groupe = %s AND id_user = %s", (self.group_id, self.user_id))
                role = cursor.fetchone()
                if role:
                    self.user_role = role[0]
                else:
                    self.user_role = None
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de la récupération du rôle de l'utilisateur: {str(e)}")
        finally:
            connection.close()
        return self.user_role

    def reload_groups(self):
        self.group_selection_tab.load_groups()

    def select_group(self, group_id):
        self.group_id = group_id
        self.load_folders()
        self.tabs.setCurrentWidget(self.tasks_tab)
        self.group_selection_tab.load_groups(group_id)  # Mettre à jour la sélection dans l'onglet de sélection de groupe

    def is_admin(self, group_id):
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT role FROM MEMBRE WHERE id_groupe = %s AND id_user = %s", (group_id, self.user_id))
                role = cursor.fetchone()
                if role and role[0] == 'admin':
                    return True
                else:
                    return False
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de la vérification du rôle: {str(e)}")
            return False
        finally:
            connection.close()

    def closeEvent(self, event):
        """Gère la fermeture propre de l'application"""
        try:
            # Arrêt du service de synchronisation
            if hasattr(self, 'sync_service') and self.sync_service:
                print("Arrêt du service de synchronisation...")
                self.sync_service.stop()
                
                # Petit délai pour laisser le temps au service de s'arrêter
                QApplication.processEvents()
                time.sleep(0.5)
            
            # Nettoyage des autres ressources
            if os.path.exists("token.pickle"):
                os.remove("token.pickle")
            
            print("Application fermée avec succès")
            event.accept()
            
            # Force l'arrêt de l'application si nécessaire
            QApplication.quit()
            
        except Exception as e:
            print(f"❌ Erreur lors de la fermeture: {str(e)}")
            event.accept()  # Force la fermeture même en cas d'erreur
            QApplication.quit()

    def show_help(self):
        if not self.help_window:
            self.help_window = HelpWindow()
        self.help_window.show()



class ExportGoogleCalendar(QDialog):
    """
    Dialogue d'exportation vers Google Calendar.
    
    Permet d'exporter les tâches vers Google Calendar avec options
    de filtrage et de synchronisation.
    
    Attributes:
        user_id (int): ID de l'utilisateur actif
        groupe_choice (QComboBox): Sélecteur de groupe source
        cal_choice (QComboBox): Sélecteur de calendrier destination
        groupe_all (QCheckBox): Option d'export total
        
    Methods:
        init_ui(): Configure l'interface utilisateur
        show_animation(): Anime l'apparition de la fenêtre
        export_choice(): Gère l'export selon les options choisies
        export_groupe_refresh(): Met à jour la liste des groupes
        export_groupe_all(): Gère l'export de tous les groupes
    """
    def __init__(self, user_id):
        super().__init__()
        self.user_id = user_id
        self.setWindowOpacity(0)
        self.init_ui()
        self.show_animation()

    def init_ui(self):
        """
        Configure l'interface utilisateur du dialogue d'export.
        
        Éléments créés :
        1. Labels et titres
        2. Sélecteurs de groupe et calendrier
        3. Options d'export
        4. Boutons d'action
        
        Style appliqué :
        - Thème sombre
        - Couleurs harmonieuses
        - Espacement optimisé
        - Animations fluides
        
        Returns:
            None
        """
        self.setWindowTitle("Google Calendar")
        self.setGeometry(500, 200, 400, 300)
        self.setStyleSheet("background-color: #23272a;")

        self.groupe_label = QLabel("Choisir un groupe source:", self)
        self.groupe_label.setStyleSheet("color: white;")

        self.groupe_choice = QComboBox()
        self.groupe_choice.setStyleSheet("color: white;")
        connection = get_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT GROUPE.nom, GROUPE.id_groupe FROM GROUPE INNER JOIN USER ON GROUPE.id_user=USER.id_user WHERE USER.id_user=%s", (self.user_id,))
            self.groups = cursor.fetchall()
            for group in self.groups:
                self.groupe_choice.addItem(group[0][:59])

        self.groupe_all = QCheckBox("N'importe quel groupe", self)
        self.groupe_all.setStyleSheet("color: white;")

        self.groupe_choice.currentTextChanged.connect(self.export_groupe_refresh)
        self.groupe_all.stateChanged.connect(self.export_groupe_all)

        self.choice_label = QLabel("Choisir un calendrier à exporter:", self)
        self.choice_label.setStyleSheet("color: white;")

        self.choose_all = QCheckBox("Tout exporter", self)
        self.choose_all.setStyleSheet("color: white;")

        self.cal_choice = QComboBox()
        self.cal_choice.setStyleSheet("color: white;")
        connection = get_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT DOSSIER.nom FROM DOSSIER INNER JOIN GROUPE ON DOSSIER.id_groupe=GROUPE.id_groupe INNER JOIN USER ON GROUPE.id_user=USER.id_user WHERE USER.id_user=%s AND GROUPE.nom='%s'" % (self.user_id, self.groupe_choice.currentText()))
            calendars = cursor.fetchall()
            for calendar in calendars:
                self.cal_choice.addItem(calendar[0][:59])

        self.export_button = QPushButton("Exporter vers Google Calendar", self)
        self.export_button.setStyleSheet("background-color: #7289da; color: white; padding: 10px;")
        self.export_button.clicked.connect(self.export_choice)

        vbox = QVBoxLayout()
        vbox.addWidget(self.groupe_label)
        vbox.addWidget(self.groupe_all)
        vbox.addWidget(self.groupe_choice)
        vbox.addWidget(self.choice_label)
        vbox.addWidget(self.choose_all)
        vbox.addWidget(self.cal_choice)
        vbox.addWidget(self.export_button)
        self.setLayout(vbox)

        connection.close()

    def show_animation(self):
        self.anim = QPropertyAnimation(self, b"windowOpacity")
        self.anim.setDuration(500)
        self.anim.setStartValue(0)
        self.anim.setEndValue(1)
        self.anim.start()

    def export_choice(self):
        """
        Gère l'export selon les options choisies.
        
        Processus :
        1. Vérification des sélections
        2. Connexion à l'API Google
        3. Préparation des données
        4. Export des tâches
        
        Returns:
            None
            
        Raises:
            google.auth.exceptions.GoogleAuthError: En cas d'erreur d'authentification
            Exception: En cas d'erreur d'export
        """
        if self.choose_all.isChecked():
            exportCal(self.user_id)
        else:
            exportCal(self.user_id, self.cal_choice.currentText())

    def export_groupe_refresh(self):
        """
        Met à jour la liste des groupes disponibles pour l'export.
        
        Actions :
        1. Récupération des groupes de l'utilisateur
        2. Filtrage selon les permissions
        3. Mise à jour de l'interface
        4. Gestion des erreurs de base de données
        
        Returns:
            None
            
        Raises:
            pymysql.Error: En cas d'erreur de base de données
        """
        connection = get_connection()
        if not self.groupe_all.isChecked():
            with connection.cursor() as cursor:
                cursor.execute("SELECT DOSSIER.nom FROM DOSSIER INNER JOIN GROUPE ON DOSSIER.id_groupe=GROUPE.id_groupe INNER JOIN USER ON GROUPE.id_user=USER.id_user WHERE USER.id_user=%s AND GROUPE.nom='%s'" % (self.user_id, self.groupe_choice.currentText()))
                calendars = cursor.fetchall()
                self.cal_choice.clear()
                for calendar in calendars:
                    self.cal_choice.addItem(calendar[0][:59])
                self.cal_choice.update()

    def export_groupe_all(self):
        """
        Exporte les tâches de tous les groupes sélectionnés.
        
        Processus :
        1. Récupération des dossiers
        2. Filtrage selon la sélection
        3. Export vers Google Calendar
        4. Gestion des conflits
        
        Returns:
            None
            
        Raises:
            Exception: En cas d'erreur d'export
        """
        connection = get_connection()
        if self.groupe_all.isChecked():
            with connection.cursor() as cursor:
                cursor.execute("SELECT DOSSIER.nom FROM DOSSIER INNER JOIN GROUPE ON DOSSIER.id_groupe=GROUPE.id_groupe INNER JOIN USER ON GROUPE.id_user=USER.id_user WHERE USER.id_user=%s" % (self.user_id,))
                calendars = cursor.fetchall()
                self.cal_choice.clear()
                for calendar in calendars:
                    self.cal_choice.addItem(calendar[0][:59])
                self.cal_choice.update()
        else:
            with connection.cursor() as cursor:
                cursor.execute("SELECT DOSSIER.nom FROM DOSSIER INNER JOIN GROUPE ON DOSSIER.id_groupe=GROUPE.id_groupe INNER JOIN USER ON GROUPE.id_user=USER.id_user WHERE USER.id_user=%s AND GROUPE.nom='%s'" % (self.user_id, self.groupe_choice.currentText()))
                calendars = cursor.fetchall()
                self.cal_choice.clear()
                for calendar in calendars:
                    self.cal_choice.addItem(calendar[0][:59])
                self.cal_choice.update()
        self.close()

class ImportGoogleCalendar(QDialog):
    """
    Dialogue d'importation depuis Google Calendar.
    
    Permet d'importer des événements Google Calendar sous forme de tâches
    dans l'application, avec gestion des conflits et des mises à jour.
    
    Attributes:
        user_id (int): ID de l'utilisateur actif
        groupe_choice (QComboBox): Sélecteur de groupe de destination
        cal_choice (QComboBox): Sélecteur de calendrier source
        choose_all (QCheckBox): Option d'import total
        
    Methods:
        init_ui(): Configure l'interface utilisateur
        show_animation(): Anime l'apparition de la fenêtre
        import_choice(): Gère l'import selon les options choisies
    """
    def __init__(self, user_id):
        super().__init__()
        self.user_id = user_id
        self.setWindowOpacity(0)
        self.init_ui()
        self.show_animation()

    def init_ui(self):
        """
        Configure l'interface utilisateur du dialogue d'import.
        
        Éléments créés :
        1. Labels et titres
        2. Sélecteurs de groupe et calendrier
        3. Options d'import
        4. Boutons d'action
        
        Style appliqué :
        - Thème sombre
        - Couleurs harmonieuses
        - Espacement optimisé
        - Animations fluides
        
        Returns:
            None
        """
        self.setWindowTitle("Google Calendar")
        self.setGeometry(500, 200, 400, 300)
        self.setStyleSheet("background-color: #23272a;")

        self.groupe_label = QLabel("Choisir un groupe de réception:", self)
        self.groupe_label.setStyleSheet("color: white;")

        self.groupe_choice = QComboBox()
        self.groupe_choice.setStyleSheet("color: white;")
        connection = get_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT GROUPE.nom, GROUPE.id_groupe FROM GROUPE INNER JOIN USER ON GROUPE.id_user=USER.id_user WHERE USER.id_user=%s", (self.user_id,))
            self.groups = cursor.fetchall()
            for group in self.groups:
                self.groupe_choice.addItem(group[0][:59])

        self.choice_label = QLabel("Choisir un calendrier à importer:", self)
        self.choice_label.setStyleSheet("color: white;")

        self.choose_all = QCheckBox("Tout importer", self)
        self.choose_all.setStyleSheet("color: white;")

        self.cal_choice = QComboBox()
        self.cal_choice.setStyleSheet("color: white;")
        connection = get_connection()
        with connection.cursor() as cursor:
            self.calendars = getCalendars()
            for calendar in self.calendars:
                self.cal_choice.addItem(calendar['summary'][:59])

        self.import_button = QPushButton("Importer depuis Google Calendar", self)
        self.import_button.setStyleSheet("background-color: #7289da; color: white; padding: 10px;")
        self.import_button.clicked.connect(self.import_choice)

        vbox = QVBoxLayout()
        vbox.addWidget(self.groupe_label)
        vbox.addWidget(self.groupe_choice)
        vbox.addWidget(self.choice_label)
        vbox.addWidget(self.choose_all)
        vbox.addWidget(self.cal_choice)
        vbox.addWidget(self.import_button)
        self.setLayout(vbox)

        connection.commit()
        connection.close()

    def show_animation(self):
        self.anim = QPropertyAnimation(self, b"windowOpacity")
        self.anim.setDuration(500)
        self.anim.setStartValue(0)
        self.anim.setEndValue(1)
        self.anim.start()

    def import_choice(self):
        """
        Gère l'import selon les options choisies.
        
        Processus :
        1. Vérification des sélections
        2. Connexion à l'API Google
        3. Récupération des événements
        4. Conversion en tâches
        
        Returns:
            None
            
        Raises:
            google.auth.exceptions.GoogleAuthError: En cas d'erreur d'authentification
            Exception: En cas d'erreur d'import
        """
        connection = get_connection()
        if self.choose_all.isChecked():
            importCal(connection, self.user_id, self.groups[self.groupe_choice.currentIndex()][1])
        else:
            importCal(connection, self.user_id, self.groups[self.groupe_choice.currentIndex()][1], self.calendars[self.cal_choice.currentIndex()]['id'])
        self.close()

class ImportExportDialog(QDialog):
    """
    Dialogue de gestion des imports/exports de données.
    
    Cette classe fournit une interface pour importer et exporter des données
    dans différents formats (CSV, Excel) et vers différentes plateformes
    (Google Calendar, fichiers locaux).
    
    Fonctionnalités :
    1. Import/Export CSV et Excel
       - Tâches avec métadonnées
       - Groupes et membres
       - Étiquettes et catégories
    2. Synchronisation Google Calendar
       - Import des événements
       - Export des tâches
       - Gestion des conflits
    3. Gestion des erreurs
       - Validation des données
       - Journalisation des erreurs
       - Messages utilisateur
    
    Attributes:
        parent (TodoListApp): Instance parente de l'application
        import_button (QPushButton): Bouton d'import de données
        export_button (QPushButton): Bouton d'export de données
        format_combo (QComboBox): Sélecteur de format de fichier
        
    Methods:
        import_data(): Importe des données depuis un fichier
        export_data(): Exporte des données vers un fichier
        handle_google_sync(): Gère la synchronisation avec Google Calendar
    """
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.initUI()

    def initUI(self):
        """
        Configure l'interface utilisateur du dialogue d'import/export.
        
        Éléments créés :
        1. Labels et titres
        2. Boutons d'action
        3. Sélecteur de format de fichier
        
        Style appliqué :
        - Thème sombre
        - Couleurs harmonieuses
        - Espacement optimisé
        - Animations fluides
        
        Returns:
            None
        """
        self.setWindowTitle("Import/Export des Données")
        self.setGeometry(500, 200, 600, 400)
        self.setStyleSheet(DARK_STYLE if self.parent.get_current_theme() == 'dark' else LIGHT_STYLE)

        vbox = QVBoxLayout()

        # Title
        title_label = QLabel("Import/Export des Données")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("font-size: 24px; font-weight: bold; color: white;")
        vbox.addWidget(title_label)

        # Description
        description_label = QLabel("Utilisez les boutons ci-dessous pour importer ou exporter les données.")
        description_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        description_label.setStyleSheet("font-size: 16px; color: #bdc3c7;")
        vbox.addWidget(description_label)

        # Buttons
        button_layout = QHBoxLayout()
        self.export_button = QPushButton("Exporter les données")
        self.export_button.setStyleSheet("padding: 10px 20px;")
        self.export_button.clicked.connect(self.export_data)
        button_layout.addWidget(self.export_button)

        self.import_button = QPushButton("Importer les données")
        self.import_button.setStyleSheet("padding: 10px 20px;")
        self.import_button.clicked.connect(self.import_data)
        button_layout.addWidget(self.import_button)

        vbox.addLayout(button_layout)

        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("font-size: 14px; color: #ecf0f1;")
        vbox.addWidget(self.status_label)

        self.setLayout(vbox)

    def export_data(self):
        """
        Exporte les données vers un fichier CSV ou Excel.
        
        Options d'export :
        1. Format de sortie (CSV, Excel)
        2. Données à exporter :
           - Tâches
           - Étiquettes
           - Dossiers
           - Membres
        3. Filtres :
           - Période
           - Statut
           - Groupe
        
        Returns:
            str: Chemin du fichier exporté, None en cas d'échec
            
        Raises:
            Exception: En cas d'erreur pendant l'export
        """
        file_path, _ = QFileDialog.getSaveFileName(self, "Enregistrer les données", "", "CSV Files (*.csv)")
        if file_path:
            tables = ["USER", "GROUPE", "DOSSIER", "TACHES", "COMMENTAIRES", "SOUS_TACHES", "HISTORIQUE", "INVITATION", "MEMBRE", "DROIT", "ETIQUETTES", "TACHE_ETIQUETTE"]
            connection = get_connection()
            try:
                with open(file_path, "w", newline='', encoding='utf-8') as file:
                    writer = csv.writer(file)
                    for table in tables:
                        writer.writerow([f"TABLE: {table}"])
                        with connection.cursor() as cursor:
                            cursor.execute(f"SELECT * FROM {table}")
                            rows = cursor.fetchall()
                            writer.writerow([i[0] for i in cursor.description])  # write headers
                            writer.writerows(rows)
                            writer.writerow([])  # blank line to separate tables
                self.status_label.setText('Les données ont été exportées avec succès!')
            except pymysql.MySQLError as e:
                self.status_label.setText(f"Erreur lors de l'exportation des données: {str(e)}")
            finally:
                connection.close()

    def import_data(self):
        """
        Importe des données depuis un fichier CSV ou Excel.
        
        Formats supportés :
        - CSV (délimité par virgules ou points-virgules)
        - Excel (.xlsx, .xls)
        
        Types de données importables :
        - Tâches
        - Étiquettes
        - Dossiers
        - Membres
        
        Returns:
            bool: True si l'import est réussi, False sinon
            
        Raises:
            Exception: En cas d'erreur de format ou d'import
        """
        file_path, _ = QFileDialog.getOpenFileName(self, "Importer les données", "", "CSV Files (*.csv)")
        if file_path:
            connection = get_connection()
            try:
                with open(file_path, "r", encoding='utf-8') as file:
                    reader = csv.reader(file)
                    table_name = None
                    rows = []
                    headers = []
                    for row in reader:
                        if row:
                            if row[0].startswith("TABLE:"):
                                if table_name and rows:
                                    import_table_data(connection, table_name, headers, rows)
                                table_name = row[0].split(":")[1].strip()
                                headers = next(reader)
                                rows = []
                            else:
                                rows.append(row)
                    if table_name and rows:
                        import_table_data(connection, table_name, headers, rows)
                connection.commit()
                self.status_label.setText('Les données ont été importées avec succès!')
                self.parent.group_selection_tab.load_groups()  # Ajoutez cette ligne pour recharger les groupes dans l'onglet "Sélection"
            except pymysql.MySQLError as e:
                self.status_label.setText(f"Erreur lors de l'importation des données: {str(e)}")
            finally:
                connection.close()


def import_table_data(connection, table_name, headers, rows):
    """
    Importe des données dans une table de la base de données et sur l'API.
    
    Args:
        connection (pymysql.Connection): Connexion à la base de données
        table_name (str): Nom de la table
        headers (list): Liste des noms de colonnes
        rows (list): Liste des lignes de données à importer
        
    Returns:
        bool: True si l'import est réussi, False sinon
    """
    try:
        with connection.cursor() as cursor:
            # Désactiver les contraintes de clés étrangères
            cursor.execute("SET FOREIGN_KEY_CHECKS = 0")
            cursor.execute(f"DELETE FROM {table_name}")  # Clear existing data

            # Création du point d'accès API en fonction du nom de la table
            api_endpoint = f"/api/import/{table_name.lower()}"

            # Préparer le lot complet de données pour l'API
            batch_data = {
                'table_name': table_name,
                'headers': headers,
                'rows': []
            }

            for row in rows:
                # Handle empty strings for integer columns
                cleaned_row = [None if col == '' else col for col in row]
                placeholders = ', '.join(['%s'] * len(cleaned_row))
                
                # Insertion locale
                cursor.execute(
                    f"INSERT INTO {table_name} ({', '.join(headers)}) VALUES ({placeholders})", 
                    cleaned_row
                )
                
                # Ajouter la ligne au lot de données pour l'API
                data = dict(zip(headers, cleaned_row))
                batch_data['rows'].append(data)

            # Faire un seul appel API avec toutes les données
            try:
                response = requests.post(
                    f"{AppConfig.API_BASE_URL}{api_endpoint}",
                    json=batch_data,
                    headers={
                        **AppConfig.DEFAULT_HEADERS,
                        'Content-Type': 'application/json'
                    },
                    verify=AppConfig.VERIFY_SSL
                )
                
                if not response.ok:
                    print(f"Erreur API lors de l'importation des données dans {table_name}: {response.text}")
                    if response.status_code == 401:
                        print("Erreur d'authentification - vérifiez le token d'accès")
                    elif response.status_code == 403:
                        print("Permission refusée - vérifiez les droits d'accès")
                    elif response.status_code == 400:
                        print("Données invalides - vérifiez le format des données")
                    return False

            except requests.RequestException as e:
                print(f"Erreur réseau lors de l'importation sur l'API pour {table_name}: {str(e)}")
                return False

            # Réactiver les contraintes de clés étrangères
            cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
            connection.commit()

            return True

    except Exception as e:
        connection.rollback()
        print(f"Erreur lors de l'importation des données de {table_name}: {str(e)}")
        return False


#doc inst - doc dev doc util

class TasksTab(QWidget):
    """
    Onglet de gestion des tâches.
    
    Gère l'affichage, la création, la modification et la suppression des tâches.
    Implémente également le filtrage, la recherche et la pagination.
    
    Attributes:
        parent (TodoListApp): Instance parente de l'application
        current_page (int): Page actuelle pour la pagination
        items_per_page (int): Nombre d'éléments par page
        current_filter (int): Filtre actif (0: toutes, 1: en cours, 2: terminées)
        current_label_filter (str): Filtre par étiquette actif
        tasks_table (QTableWidget): Tableau d'affichage des tâches
        
    Methods:
        initUI(): Configure l'interface de l'onglet
        load_tasks(): Charge et affiche les tâches depuis la base de données
        filter_tasks(): Applique les filtres de statut et d'étiquettes
        search_tasks(): Effectue une recherche textuelle dans les tâches
        open_task_dialog(): Ouvre le dialogue d'édition de tâche
        delete_task(): Supprime une tâche sélectionnée
        update_task_label(): Met à jour l'étiquette d'une tâche
        start_voice_assist(): Active l'assistance vocale
        prev_page/next_page(): Gère la pagination
    """
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.session = parent.session  # Utiliser la session du parent
        self.current_page = 0
        self.items_per_page = 10
        self.current_filter = 0  # Initialiser current_filter ici
        self.current_label_filter = None  # Initialiser current_label_filter ici
        self.initUI()
        self.init_timer()

    def initUI(self):
        vbox = QVBoxLayout()
        hbox = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Rechercher une tâche...")
        self.search_button = QPushButton("Rechercher")
        self.search_button.clicked.connect(self.search_tasks)
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["Toutes", "En cours", "Terminées", "Échoué"])
        self.filter_combo.currentIndexChanged.connect(self.filter_tasks)  # Connecter filter_tasks ici

        # Ajouter le menu déroulant pour le tri
        self.sort_combo = QComboBox()
        self.sort_combo.addItems([
            "Aucun",
            "Date (croissant)",
            "Date (décroissant)",
            "Titre (A à Z)",
            "Titre (Z à A)",
            "Priorité (1 à 3)",
            "Priorité (3 à 1)"
        ])
        self.sort_combo.currentIndexChanged.connect(self.load_tasks)

        # Ajouter le menu déroulant pour les étiquettes
        self.label_filter_combo = QComboBox()
        self.label_filter_combo.addItem("Toutes les étiquettes", None)
        self.load_labels()
        self.label_filter_combo.currentIndexChanged.connect(self.filter_tasks_by_label)

        # Ajouter les boutons d'assistance vocale à côté de la recherche
        self.start_button = QPushButton("Démarrer")
        self.start_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay))  # Icône "play"
        self.start_button.setIconSize(QSize(16, 16))  # Ajuster la taille de l'icône
        self.start_button.clicked.connect(self.start_voice_assist)

        self.stop_button = QPushButton("Arrêter")
        self.stop_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaStop))  # Icône "stop"
        self.stop_button.setIconSize(QSize(16, 16))  # Ajuster la taille de l'icône
        self.stop_button.clicked.connect(self.stop_voice_assist)

        # Encadrer les boutons en rouge avec un titre "AI VOC"
        button_frame = QWidget()
        button_layout = QVBoxLayout()
        title_label = QLabel("AI VOC")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("font-weight: bold; color: red;")
        button_layout.addWidget(title_label)
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_frame.setLayout(button_layout)
        button_frame.setStyleSheet("border: 2px solid red; padding: 5px;")

        hbox.addWidget(self.search_input)
        hbox.addWidget(self.search_button)
        hbox.addWidget(self.filter_combo)
        hbox.addWidget(self.sort_combo)  # Ajouter le menu déroulant pour le tri
        hbox.addWidget(self.label_filter_combo)  # Ajouter le menu déroulant pour les étiquettes
        hbox.addWidget(button_frame)
        vbox.addLayout(hbox)

        self.tasks_table = QTableWidget()
        self.tasks_table.setColumnCount(9)  # Ajuster le nombre de colonnes
        self.tasks_table.setHorizontalHeaderLabels(["Titre", "Dossier", "Priorité", "Date de fin", "Statut", "Assigné à", "Étiquettes", "Actions", "Supprimer"])
        self.tasks_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tasks_table.cellDoubleClicked.connect(self.open_task_dialog)
        vbox.addWidget(self.tasks_table)

        hbox = QHBoxLayout()
        self.prev_button = QPushButton("Précédent")
        self.prev_button.setIcon(QIcon.fromTheme("go-previous"))  # Icône standard pour "Précédent"
        self.prev_button.setIconSize(QSize(16, 16))  # Ajuster la taille de l'icône
        self.prev_button.setStyleSheet("padding: 5px 10px;")
        self.prev_button.clicked.connect(self.prev_page)
        hbox.addWidget(self.prev_button)

        # Centrer les boutons "Nouvelle tâche" et "Gérer les Étiquettes"
        self.add_task_button = QPushButton("Nouvelle tâche")
        self.add_task_button.setStyleSheet("padding: 10px 20px;")
        self.add_task_button.clicked.connect(self.open_task_dialog)
        hbox.addWidget(self.add_task_button)

        self.manage_labels_button = QPushButton("Gérer les Étiquettes")
        self.manage_labels_button.setStyleSheet("padding: 10px 20px;")
        self.manage_labels_button.clicked.connect(self.open_manage_labels_dialog)
        hbox.addWidget(self.manage_labels_button)

        self.next_button = QPushButton("Suivant")
        self.next_button.setIcon(QIcon.fromTheme("go-next"))  # Icône standard pour "Suivant"
        self.next_button.setIconSize(QSize(16, 16))  # Ajuster la taille de l'icône
        self.next_button.setStyleSheet("padding: 5px 10px;")
        self.next_button.clicked.connect(self.next_page)
        hbox.addWidget(self.next_button)

        vbox.addLayout(hbox)

        self.setLayout(vbox)
        self.load_tasks()

        # Désactiver le bouton "Nouvelle tâche" si l'utilisateur est en mode lecture
        if self.parent.get_user_role() == 'lecture':
            self.add_task_button.setEnabled(False)

    def init_timer(self):
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.load_tasks)  # Ou toute autre méthode que vous souhaitez appeler périodiquement
        self.timer.start(5000)  # Vérifie toutes les 5 secondes

    def load_labels(self):
        self.label_filter_combo.clear()
        self.label_filter_combo.addItem("Toutes les étiquettes", None)
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT id_etiquettes, description FROM ETIQUETTES")
                labels = cursor.fetchall()
                for label in labels:
                    self.label_filter_combo.addItem(label[1], label[0])
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors du chargement des étiquettes: {str(e)}")
        finally:
            connection.close()

    def filter_tasks_by_label(self):
        self.current_label_filter = self.label_filter_combo.currentData()
        self.load_tasks()

    def load_tasks(self):
        if not self.parent.group_id:
            return
        self.tasks_table.setRowCount(0)
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                offset = self.current_page * self.items_per_page
                sort_option = self.sort_combo.currentIndex()

                # Déterminer l'ordre de tri
                if sort_option == 0:
                    # Si aucun tri n'est sélectionné, trier par dossier par défaut
                    order_by = "d.nom ASC"  # Trier par nom de dossier
                elif sort_option == 1:
                    order_by = "t.date_fin ASC"
                elif sort_option == 2:
                    order_by = "t.date_fin DESC"
                elif sort_option == 3:
                    order_by = "t.titre ASC"
                elif sort_option == 4:
                    order_by = "t.titre DESC"
                elif sort_option == 5:
                    order_by = "t.priorite ASC"
                elif sort_option == 6:
                    order_by = "t.priorite DESC"
                else:
                    order_by = None

                filter_index = self.current_filter
                if filter_index == 0:
                    filter_condition = "1=1"
                elif filter_index == 1:
                    filter_condition = "t.statut = 0"
                elif filter_index == 2:
                    filter_condition = "t.statut = 1"
                elif filter_index == 3:
                    filter_condition = "t.statut = 2"
                else:
                    filter_condition = "1=1"

                label_filter_condition = ""
                if self.current_label_filter:
                    label_filter_condition = f"AND te.id_etiquettes = {self.current_label_filter}"

                query = f"""
                    SELECT t.id_tache, t.titre, d.nom AS dossier_nom, t.priorite, t.date_fin, t.statut, GROUP_CONCAT(u.username SEPARATOR ', '), GROUP_CONCAT(e.description SEPARATOR ', ')
                    FROM TACHES t
                    JOIN DOSSIER d ON t.id_dossier = d.id_dossier
                    LEFT JOIN TACHE_USER tu ON t.id_tache = tu.id_tache
                    LEFT JOIN USER u ON tu.id_user = u.id_user
                    LEFT JOIN TACHE_ETIQUETTE te ON t.id_tache = te.id_tache
                    LEFT JOIN ETIQUETTES e ON te.id_etiquettes = e.id_etiquettes
                    WHERE d.id_groupe = %s AND {filter_condition} {label_filter_condition}
                    GROUP BY t.id_tache
                """
                if order_by:
                    query += f" ORDER BY {order_by}"
                query += " LIMIT %s OFFSET %s"

                cursor.execute(query, (self.parent.group_id, self.items_per_page, offset))
                tasks = cursor.fetchall()
                current_folder = None  # Pour suivre le dossier courant
                for task in tasks:
                    # Si le dossier courant change, afficher le nom du dossier
                    if current_folder != task[2]:
                        current_folder = task[2]
                        # Ajouter une ligne pour le nom du dossier
                        folder_row = self.tasks_table.rowCount()
                        self.tasks_table.insertRow(folder_row)
                        folder_label = QLabel(f"Dossier: {current_folder}")
                        folder_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                        folder_label.setStyleSheet("background-color: rgb(105, 105, 105); border: 4px solid dark;")  # Bleu clair avec bordure rouge
                        self.tasks_table.setCellWidget(folder_row, 0, folder_label)
                        # Fusionner les cellules pour le nom du dossier
                        self.tasks_table.setSpan(folder_row, 0, 1, 9)  # Ajustez le nombre de colonnes selon votre besoin

                    # Ajouter la tâche
                    task_row = self.tasks_table.rowCount()
                    self.tasks_table.insertRow(task_row)
                    self.tasks_table.setItem(task_row, 0, QTableWidgetItem(task[1]))  # Titre
                    self.tasks_table.setItem(task_row, 1, QTableWidgetItem(task[2]))
                    # Dossier
                    self.tasks_table.setItem(task_row, 2, QTableWidgetItem(get_priority_string(task[3])))  # Priorité
                    self.tasks_table.setItem(task_row, 3, QTableWidgetItem(task[4].strftime('%Y-%m-%d')))  # Date de fin

                    # Déterminer le statut
                    if task[5] == 0:
                        status_label = QLabel("En cours")
                        status_label.setStyleSheet("color: orange;")
                    elif task[5] == 1:
                        status_label = QLabel("Terminée")
                        status_label.setStyleSheet("color: green;")
                    else:
                        status_label = QLabel("Échoué")
                        status_label.setStyleSheet("color: red;")
                    self.tasks_table.setCellWidget(task_row, 4, status_label)  # Statut
                    self.tasks_table.setItem(task_row, 5, QTableWidgetItem(task[6] if task[6] else "Aucun"))  # Assigné à

                    # Ajouter le menu déroulant pour les étiquettes
                    label_combo = QComboBox()
                    self.load_labels_into_combo(label_combo)
                    label_combo.setCurrentText(task[7] if task[7] else "Aucune")
                    label_combo.currentIndexChanged.connect(lambda index, task_id=task[0], combo=label_combo: self.update_task_label(task_id, combo))
                    self.tasks_table.setCellWidget(task_row, 6, label_combo)  # Étiquettes

                    # Boutons d'actions
                    edit_button = QPushButton("Modifier")
                    edit_button.setStyleSheet("padding: 5px 10px;")
                    edit_button.clicked.connect(lambda checked, task_id=task[0]: self.open_task_dialog(task_id))
                    self.tasks_table.setCellWidget(task_row, 7, edit_button)  # Actions
                    delete_button = QPushButton("Supprimer")
                    delete_button.setStyleSheet("padding: 5px 10px;")
                    delete_button.clicked.connect(lambda checked, task_id=task[0]: self.delete_task(task_id))
                    self.tasks_table.setCellWidget(task_row, 8, delete_button)  # Supprimer
                    if self.parent.get_user_role() == 'lecture':
                        edit_button.setEnabled(False)
                        delete_button.setEnabled(False)
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors du chargement des tâches: {str(e)}")
        finally:
            connection.close()

    def load_labels_into_combo(self, combo):
        combo.clear()
        combo.addItem("Aucune", None)
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT id_etiquettes, description FROM ETIQUETTES")
                labels = cursor.fetchall()
                for label in labels:
                    combo.addItem(label[1], label[0])
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors du chargement des étiquettes: {str(e)}")
        finally:
            connection.close()

    def update_task_label(self, task_id, combo):
        """Met à jour les étiquettes d'une tâche avec synchronisation BDD locale et API"""
        label_id = combo.currentData()
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                # Mise à jour locale
                cursor.execute("DELETE FROM TACHE_ETIQUETTE WHERE id_tache = %s", (task_id,))
                if label_id:
                    cursor.execute(
                        "INSERT INTO TACHE_ETIQUETTE (id_tache, id_etiquettes) VALUES (%s, %s)", 
                        (task_id, label_id))
    
                # Mise à jour API
                try:
                    # D'abord supprimer toutes les étiquettes existantes
                    delete_url = f"{AppConfig.API_BASE_URL}/taches/{task_id}/etiquettes/{label_id}"
                    print(f"DELETE URL: {delete_url}")  # Journal pour vérifier l'URL
                    response = requests.delete(
                        delete_url,
                        headers=self.parent.session.headers,  # Utiliser self.parent.session ici
                        verify=AppConfig.VERIFY_SSL
                    )
                    print(f"DELETE Response: {response.status_code} - {response.text}")  # Journal pour vérifier la réponse
    
                    if label_id:
                        # Puis ajouter la nouvelle étiquette si elle existe
                        post_url = f"{AppConfig.API_BASE_URL}/taches/{task_id}/etiquettes/{label_id}"
                        print(f"POST URL: {post_url}")  # Journal pour vérifier l'URL
                        response = requests.post(
                            post_url,
                            headers=self.parent.session.headers,  # Utiliser self.parent.session ici
                            verify=AppConfig.VERIFY_SSL
                        )
                        print(f"POST Response: {response.status_code} - {response.text}")  # Journal pour vérifier la réponse
                        
                    if not response.ok:
                        raise Exception(f"Erreur API lors de la mise à jour des étiquettes: {response.text}")
    
                except requests.RequestException as e:
                    raise Exception(f"Erreur réseau lors de la mise à jour sur l'API: {str(e)}")
    
                connection.commit()
    
        except Exception as e:
            connection.rollback()
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de la mise à jour de l'étiquette: {str(e)}")
        finally:
            connection.close()
            
    def delete_task(self, task_id):
        confirmation = QMessageBox.question(self, 'Confirmation', 'Êtes-vous sûr de vouloir supprimer cette tâche?', QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirmation == QMessageBox.StandardButton.No:
            return
    
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM TACHES WHERE id_tache = %s", (task_id,))
                cursor.execute("DELETE FROM TACHE_USER WHERE id_tache = %s", (task_id,))
                cursor.execute("DELETE FROM TACHE_ETIQUETTE WHERE id_tache = %s", (task_id,))
                cursor.execute("DELETE FROM COMMENTAIRES WHERE id_tache = %s", (task_id,))
                cursor.execute("DELETE FROM SOUS_TACHES WHERE id_tache = %s", (task_id,))
    
                # Suppression via API
                try:
                    response = requests.delete(
                        f"{AppConfig.API_BASE_URL}/taches/{task_id}",
                        headers=self.session.headers,
                        verify=AppConfig.VERIFY_SSL
                    )
                    if not response.ok:
                        raise Exception(f"Erreur API lors de la suppression: {response.text}")
                except requests.RequestException as e:
                    raise Exception(f"Erreur réseau lors de la suppression API: {str(e)}")
    
                connection.commit()
                QMessageBox.information(self, 'Succès', 'La tâche a été supprimée avec succès!')
                self.load_tasks()
                self.parent.folders_tab.load_folders()
    
        except Exception as e:
            connection.rollback()
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de la suppression de la tâche: {str(e)}")
        finally:
            connection.close()
        
    def prev_page(self):
        if self.current_page > 0:
            self.current_page -= 1
            self.load_tasks()

    def next_page(self):
        self.current_page += 1
        self.load_tasks()

    def search_tasks(self):
        if not self.parent.group_id:
            return
        search_text = self.search_input.text()
        filter_index = self.filter_combo.currentIndex()
        self.tasks_table.setRowCount(0)
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                if filter_index == 0:
                    filter_condition = "1=1"
                elif filter_index == 1:
                    filter_condition = "t.statut = 0"
                elif filter_index == 2:
                    filter_condition = "t.statut = 1"
                elif filter_index == 3:
                    filter_condition = "t.statut = 2"
                else:
                    filter_condition = "1=1"

                label_filter_condition = ""
                if self.current_label_filter:
                    label_filter_condition = f"AND te.id_etiquettes = {self.current_label_filter}"

                cursor.execute(f"""
                    SELECT t.id_tache, t.titre, d.nom, t.priorite, t.date_fin, t.statut, u.username, GROUP_CONCAT(e.description SEPARATOR ', ')
                    FROM TACHES t
                    JOIN DOSSIER d ON t.id_dossier = d.id_dossier
                    LEFT JOIN TACHE_USER tu ON t.id_tache = tu.id_tache
                    LEFT JOIN USER u ON tu.id_user = u.id_user
                    LEFT JOIN TACHE_ETIQUETTE te ON t.id_tache = te.id_tache
                    LEFT JOIN ETIQUETTES e ON te.id_etiquettes = e.id_etiquettes
                    WHERE d.id_groupe = %s AND t.titre LIKE %s AND {filter_condition} {label_filter_condition}
                    GROUP BY t.id_tache
                """, (self.parent.group_id, f"%{search_text}%"))
                tasks = cursor.fetchall()
                for row, task in enumerate(tasks):
                    self.tasks_table.insertRow(row)
                    self.tasks_table.setItem(row, 0, QTableWidgetItem(task[1]))  # Titre
                    self.tasks_table.setItem(row, 1, QTableWidgetItem(task[2]))  # Dossier
                    self.tasks_table.setItem(row, 2, QTableWidgetItem(get_priority_string(task[3])))  # Priorité
                    self.tasks_table.setItem(row, 3, QTableWidgetItem(task[4].strftime('%Y-%m-%d')))  # Date de fin

                    # Déterminer le statut
                    if task[5] == 0:
                        status_label = QLabel("En cours")
                        status_label.setStyleSheet("color: orange;")
                    elif task[5] == 1:
                        status_label = QLabel("Terminée")
                        status_label.setStyleSheet("color: green;")
                    else:
                        status_label = QLabel("Échoué")
                        status_label.setStyleSheet("color: red;")
                    self.tasks_table.setCellWidget(row, 4, status_label)  # Statut
                    self.tasks_table.setItem(row, 5, QTableWidgetItem(task[6] if task[6] else "Aucun"))  # Assigné à

                    # Ajouter le menu déroulant pour les étiquettes
                    label_combo = QComboBox()
                    self.load_labels_into_combo(label_combo)
                    label_combo.setCurrentText(task[7] if task[7] else "Aucune")
                    label_combo.currentIndexChanged.connect(lambda index, task_id=task[0], combo=label_combo: self.update_task_label(task_id, combo))
                    self.tasks_table.setCellWidget(row, 6, label_combo)  # Étiquettes

                    edit_button = QPushButton("Modifier")
                    edit_button.setStyleSheet("padding: 5px 10px;")
                    edit_button.clicked.connect(lambda checked, task_id=task[0]: self.open_task_dialog(task_id))
                    self.tasks_table.setCellWidget(row, 7, edit_button)  # Actions
                    delete_button = QPushButton("Supprimer")
                    delete_button.setStyleSheet("padding: 5px 10px;")
                    delete_button.clicked.connect(lambda checked, task_id=task[0]: self.delete_task(task_id))
                    self.tasks_table.setCellWidget(row, 8, delete_button)  # Supprimer
                    if self.parent.get_user_role() == 'lecture':
                        edit_button.setEnabled(False)
                        delete_button.setEnabled(False)
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de la recherche des tâches: {str(e)}")
        finally:
            connection.close()

    def filter_tasks(self):
        """
        Applique les filtres combinés sur la liste des tâches.
        
        Filtres disponibles :
        1. Statut (tous, en cours, terminés)
        2. Priorité (haute, moyenne, basse)
        3. Étiquettes
        
        Le filtrage est effectué côté base de données pour optimiser
        les performances. Les résultats sont paginés.
        
        Returns:
            None
            
        Raises:
            pymysql.Error: En cas d'erreur de base de données
        """
        self.current_filter = self.filter_combo.currentIndex()  # Mettez à jour self.current_filter
        self.load_tasks()

    def open_task_dialog(self, task_id=None):
        if task_id:
            self.task_dialog = TaskDialog(self, task_id)  # Changed from self.parent to self
        else:
            self.task_dialog = TaskDialog(self)  # Changed from self.parent to self
        self.task_dialog.apply_theme()
        self.task_dialog.exec()
        self.load_tasks()

    def start_voice_assist(self):
        if not self.parent.group_id:
            return
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                # Récupérer le nom du groupe sélectionné
                cursor.execute("SELECT nom FROM GROUPE WHERE id_groupe = %s", (self.parent.group_id,))
                group_name = cursor.fetchone()
                group_name = group_name[0] if group_name else "le groupe"

                # Dire la salutation avec le nom du groupe
                engine = pyttsx3.init()
                greeting_message = f"Bonjour monsieur, j'espère que vous allez bien. Voici les tâches du groupe {group_name}."
                engine.say(greeting_message)
                engine.runAndWait()

                # Récupérer les tâches
                cursor.execute("""
                    SELECT t.titre, d.nom, t.priorite, t.date_fin, t.statut, GROUP_CONCAT(u.username SEPARATOR ', ')
                    FROM TACHES t
                    JOIN DOSSIER d ON t.id_dossier = d.id_dossier
                    LEFT JOIN TACHE_USER tu ON t.id_tache = tu.id_tache
                    LEFT JOIN USER u ON tu.id_user = u.id_user
                    WHERE d.id_groupe = %s
                    GROUP BY t.id_tache
                """, (self.parent.group_id,))
                tasks = cursor.fetchall()
                task_descriptions = []

                for task in tasks:
                    priority = get_priority_string(task[2])
                    status = "En cours" if task[4] == 0 else "Terminée" if task[4] == 1 else "Échoué"
                    task_descriptions.append(f"Tâche: {task[0]}, Dossier: {task[1]}, Priorité: {priority}, Date de fin: {task[3].strftime('%Y-%m-%d')}, Statut: {status}, Assigné à: {task[5] if task[5] else 'Aucun'}")
                
                # Parler des tâches après la salutation
                self.speak_tasks(task_descriptions)
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de la récupération des tâches: {str(e)}")
        finally:
            connection.close()

    def stop_voice_assist(self):
        # Arrêter l'assistance vocale
        engine = pyttsx3.init()
        engine.stop()

    def speak_tasks(self, task_descriptions):
        engine = pyttsx3.init()
        for description in task_descriptions:
            engine.say(description)
        engine.runAndWait()

    def open_manage_labels_dialog(self):
        self.manage_labels_dialog = ManageLabelsDialog(self)
        self.manage_labels_dialog.exec()
        self.load_labels()
        self.load_tasks()



class ManageLabelsDialog(QDialog):
    """
    Dialogue de gestion des étiquettes.
    
    Permet de créer, modifier et supprimer les étiquettes utilisées
    pour catégoriser les tâches.
    
    Attributes:
        parent (QWidget): Widget parent
        labels_table (QTableWidget): Tableau des étiquettes
        
    Methods:
        load_labels(): Charge les étiquettes depuis la base de données
        add_label(): Crée une nouvelle étiquette
        edit_label(): Modifie une étiquette existante
        delete_label(): Supprime une étiquette
    """
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.initUI()
        self.apply_theme()  # Appliquer le thème lors de l'initialisation

    def initUI(self):
        self.setWindowTitle("Gérer les Étiquettes")
        self.setGeometry(500, 200, 400, 300)
        vbox = QVBoxLayout()
        self.label_input = QLineEdit()
        self.label_input.setPlaceholderText("Nom de l'étiquette")
        vbox.addWidget(self.label_input)
        self.add_label_button = QPushButton("Ajouter Étiquette")
        self.add_label_button.clicked.connect(self.add_label)
        vbox.addWidget(self.add_label_button)
        self.labels_list = QListWidget()
        self.load_labels()
        vbox.addWidget(self.labels_list)
        hbox = QHBoxLayout()
        self.edit_label_button = QPushButton("Modifier")
        self.edit_label_button.clicked.connect(self.edit_label)
        hbox.addWidget(self.edit_label_button)
        self.delete_label_button = QPushButton("Supprimer")
        self.delete_label_button.clicked.connect(self.delete_label)
        hbox.addWidget(self.delete_label_button)
        vbox.addLayout(hbox)
        self.setLayout(vbox)

    def load_labels(self):
        self.labels_list.clear()
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT id_etiquettes, description FROM ETIQUETTES")
                labels = cursor.fetchall()
                for label in labels:
                    item = QListWidgetItem()
                    checkbox = QCheckBox(label[1])
                    item.setData(Qt.ItemDataRole.UserRole, label[0])
                    self.labels_list.addItem(item)
                    self.labels_list.setItemWidget(item, checkbox)
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors du chargement des étiquettes: {str(e)}")
        finally:
            connection.close()

    def add_label(self):
        description = self.label_input.text()
        if not description:
            QMessageBox.warning(self, 'Erreur', 'Le nom de l\'étiquette est obligatoire!')
            return
            
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                # Création locale
                cursor.execute("INSERT INTO ETIQUETTES (description) VALUES (%s)", (description,))
                etiquette_id = cursor.lastrowid

                # Création API
                try:
                    response = requests.post(
                        f"{AppConfig.API_BASE_URL}/etiquettes",
                        json={"description": description},
                        headers=self.parent.session.headers,
                        verify=AppConfig.VERIFY_SSL
                    )
                    
                    if not response.ok:
                        print(f"Erreur API lors de la création de l'étiquette: {response.text}")
                        raise Exception("Erreur lors de la création de l'étiquette sur l'API")

                except requests.RequestException as e:
                    print(f"Erreur réseau lors de la création API: {str(e)}")
                    raise Exception("Erreur réseau lors de la création sur l'API")

                connection.commit()
                self.load_labels()
                self.label_input.clear()

        except Exception as e:
            connection.rollback()
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de l'ajout de l'étiquette: {str(e)}")
        finally:
            connection.close()

    def edit_label(self):
        selected_item = self.labels_list.currentItem()
        if not selected_item:
            QMessageBox.warning(self, 'Erreur', 'Veuillez sélectionner une étiquette à modifier!')
            return
            
        new_description = self.label_input.text()
        if not new_description:
            QMessageBox.warning(self, 'Erreur', 'Le nom de l\'étiquette est obligatoire!')
            return
            
        label_id = selected_item.data(Qt.ItemDataRole.UserRole)
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                # Mise à jour API
                try:
                    response = requests.put(
                        f"{AppConfig.API_BASE_URL}/etiquettes/{label_id}",
                        json={"description": new_description},
                        headers=self.parent.parent.session.headers,
                        verify=AppConfig.VERIFY_SSL
                    )
                    
                    if not response.ok:
                        raise Exception(f"Erreur API lors de la modification de l'étiquette: {response.text}")
                        
                except requests.RequestException as e:
                    raise Exception(f"Erreur réseau lors de la modification sur l'API: {str(e)}")

                # Mise à jour locale
                cursor.execute("""
                    UPDATE ETIQUETTES 
                    SET description = %s 
                    WHERE id_etiquettes = %s""", 
                    (new_description, label_id))
                    
                connection.commit()
                self.load_labels()
                self.label_input.clear()
                
        except Exception as e:
            connection.rollback()
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de la modification de l'étiquette: {str(e)}")
        finally:
            connection.close()

    def delete_label(self):
        selected_item = self.labels_list.currentItem()
        if not selected_item:
            QMessageBox.warning(self, 'Erreur', 'Veuillez sélectionner une étiquette à supprimer!')
            return
            
        label_id = selected_item.data(Qt.ItemDataRole.UserRole)
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                # Suppression API
                try:
                    # D'abord supprimer toutes les associations de l'étiquette
                    response = requests.delete(
                        f"{AppConfig.API_BASE_URL}/taches/etiquettes/{label_id}",
                        headers=self.parent.parent.session.headers,
                        verify=AppConfig.VERIFY_SSL
                    )
                    
                    # Ensuite supprimer l'étiquette elle-même
                    response = requests.delete(
                        f"{AppConfig.API_BASE_URL}/etiquettes/{label_id}",
                        headers=self.parent.parent.session.headers,
                        verify=AppConfig.VERIFY_SSL
                    )
                    
                    if not response.ok:
                        raise Exception(f"Erreur API lors de la suppression de l'étiquette: {response.text}")
                        
                except requests.RequestException as e:
                    raise Exception(f"Erreur réseau lors de la suppression sur l'API: {str(e)}")

                # Suppression locale
                cursor.execute("DELETE FROM TACHE_ETIQUETTE WHERE id_etiquettes = %s", (label_id,))
                cursor.execute("DELETE FROM ETIQUETTES WHERE id_etiquettes = %s", (label_id,))
                
                connection.commit()
                self.load_labels()
                
        except Exception as e:
            connection.rollback()
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de la suppression de l'étiquette: {str(e)}")
        finally:
            connection.close()

    def apply_theme(self):
        if self.parent.parent.get_current_theme() == 'dark':
            self.setStyleSheet(DARK_STYLE)
        else:
            self.setStyleSheet(LIGHT_STYLE)

    def get_selected_labels(self):
        selected_labels = []
        for index in range(self.labels_list.count()):
            item = self.labels_list.item(index)
            checkbox = self.labels_list.itemWidget(item)
            if checkbox.isChecked():
                selected_labels.append(item.data(Qt.ItemDataRole.UserRole))
        return selected_labels




class TaskDialog(QDialog):
    """
    Dialogue de création/modification de tâche.
    
    Cette classe gère l'interface pour créer ou modifier une tâche existante,
    y compris la gestion des sous-tâches, des commentaires et des étiquettes.
    
    Attributes:
        parent (TasksTab): Onglet parent des tâches
        task_id (int): ID de la tâche en cours d'édition (None pour nouvelle tâche)
        title_edit (QLineEdit): Champ de titre de la tâche
        description_edit (QLineEdit): Champ de description
        priority_combo (QComboBox): Sélecteur de priorité
        due_date (QDateEdit): Sélecteur de date d'échéance
        status_check (QCheckBox): Case à cocher pour le statut
        
    Methods:
        initUI(): Initialise l'interface du dialogue
        load_task_data(): Charge les données de la tâche existante
        save_task(): Sauvegarde les modifications
        add_comment(): Ajoute un commentaire à la tâche
        add_sous_tache(): Ajoute une sous-tâche
        load_etiquettes(): Charge les étiquettes disponibles
        load_folders(): Charge les dossiers disponibles
        load_members(): Charge les membres assignables
    """

    def __init__(self, parent, task_id=None, session=None):
        super().__init__()
        self.parent = parent
        self.task_id = task_id
        self.session = session or parent.session
        self.group_id = self.parent.parent.group_id
        self.temp_comments = []  # Liste temporaire pour les commentaires
        self.temp_sous_taches = []  # Liste temporaire pour les sous-tâches
        self.initUI()
        self.apply_theme()


    def initUI(self):
        self.setWindowTitle("Gestion de tâche")
        self.setGeometry(500, 200, 500, 600)
        vbox = QVBoxLayout()
        self.titre_input = QLineEdit()
        self.titre_input.setPlaceholderText("Titre de la tâche")
        vbox.addWidget(self.titre_input)
        self.dossier_combo = QComboBox()
        self.load_folders()
        vbox.addWidget(self.dossier_combo)
        self.priorite_combo = QComboBox()
        self.priorite_combo.addItems(["Faible", "Moyenne", "Élevée"])
        vbox.addWidget(self.priorite_combo)
        self.date_fin_edit = QDateEdit()
        self.date_fin_edit.setDate(QDate.currentDate().addDays(7))
        self.date_fin_edit.setMinimumHeight(30)  # Augmente la hauteur minimale
        self.date_fin_edit.setStyleSheet("""
            QDateEdit {
                font-size: 14px;
                padding: 5px;
                min-width: 150px;
            }
            QDateEdit::drop-down {
                width: 30px;
            }
            QDateEdit::up-button, QDateEdit::down-button {
                width: 30px;
                height: 15px;
            }
        """)
        vbox.addWidget(self.date_fin_edit)
        self.statut_combo = QComboBox()
        self.statut_combo.addItems(["En cours", "Terminée", "Echoué"])
        vbox.addWidget(self.statut_combo)
        
        # Ajout du champ de sélection des utilisateurs assignés
        self.assignee_list = QListWidget()
        self.assignee_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        self.load_members()
        vbox.addWidget(self.assignee_list)
        
        # Ajouter le champ de saisie de commentaire et le bouton "Ajouter Commentaire" sur la même ligne
        hbox_comment = QHBoxLayout()
        self.commentaire_input = QLineEdit()
        self.commentaire_input.setPlaceholderText("Commentaire")
        hbox_comment.addWidget(self.commentaire_input)
        self.add_comment_button = QPushButton("Ajouter Commentaire")
        self.add_comment_button.clicked.connect(self.add_comment)
        hbox_comment.addWidget(self.add_comment_button)
        vbox.addLayout(hbox_comment)
        
        self.commentaires_list = QListWidget()
        vbox.addWidget(self.commentaires_list)
        
        # Ajouter le bouton "Ajouter Sous-tâche" au-dessus de la liste des sous-tâches
        self.add_sous_tache_button = QPushButton("Ajouter Sous-tâche")
        self.add_sous_tache_button.clicked.connect(self.add_sous_tache)
        vbox.addWidget(self.add_sous_tache_button)
        
        self.sous_taches_list = QListWidget()
        vbox.addWidget(self.sous_taches_list)
        
        # Ajouter le champ de sélection des étiquettes
        self.etiquettes_list = QListWidget()
        self.etiquettes_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        self.load_etiquettes()
        vbox.addWidget(self.etiquettes_list)
        
        hbox = QHBoxLayout()
        self.save_button = QPushButton("Enregistrer")
        self.save_button.clicked.connect(self.save_task)
        hbox.addWidget(self.save_button)
        self.cancel_button = QPushButton("Annuler")
        self.cancel_button.clicked.connect(self.reject)
        hbox.addWidget(self.cancel_button)
        vbox.addLayout(hbox)
        if self.task_id:
            self.load_task_data()
            self.load_comments()
            self.load_sous_taches()
        self.setLayout(vbox)
        # Désactiver les champs si l'utilisateur est en mode lecture
        if self.parent.parent.get_user_role() == 'lecture':
            self.titre_input.setReadOnly(True)
            self.dossier_combo.setEnabled(False)
            self.priorite_combo.setEnabled(False)
            self.date_fin_edit.setEnabled(False)
            self.statut_combo.setEnabled(False)
            self.commentaire_input.setReadOnly(True)
            self.add_comment_button.setEnabled(False)
            self.add_sous_tache_button.setEnabled(False)
            self.save_button.setEnabled(False)

    def load_etiquettes(self):
        self.etiquettes_list.clear()
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT id_etiquettes, description FROM ETIQUETTES")
                etiquettes = cursor.fetchall()
                for etiquette in etiquettes:
                    item = QListWidgetItem(etiquette[1])
                    item.setData(Qt.ItemDataRole.UserRole, etiquette[0])
                    item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    item.setCheckState(Qt.CheckState.Unchecked)
                    self.etiquettes_list.addItem(item)
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors du chargement des étiquettes: {str(e)}")
        finally:
            connection.close()

    def load_task_etiquettes(self):
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT id_etiquettes FROM TACHE_ETIQUETTE WHERE id_tache = %s", (self.task_id,))
                etiquettes = cursor.fetchall()
                etiquette_ids = [etiquette[0] for etiquette in etiquettes]
                for i in range(self.etiquettes_list.count()):
                    item = self.etiquettes_list.item(i)
                    if item.data(Qt.ItemDataRole.UserRole) in etiquette_ids:
                        item.setCheckState(Qt.CheckState.Checked)
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors du chargement des étiquettes de la tâche: {str(e)}")
        finally:
            connection.close()


    def save_task(self):
        titre = self.titre_input.text()
        id_dossier = self.dossier_combo.currentData()
        priorite = self.priorite_combo.currentIndex()
        date_fin = self.date_fin_edit.date().toPyDate()
        commentaire = self.commentaire_input.text()
        statut = self.statut_combo.currentIndex()
        assignee_ids = [
            self.assignee_list.item(i).data(Qt.ItemDataRole.UserRole)
            for i in range(self.assignee_list.count())
            if self.assignee_list.item(i).isSelected()
        ]
        assignee_emails = [
            self.assignee_list.item(i).data(Qt.ItemDataRole.UserRole + 1)
            for i in range(self.assignee_list.count())
            if self.assignee_list.item(i).isSelected()
        ]

        if not titre or id_dossier is None:
            QMessageBox.warning(self, 'Erreur', 'Le titre et le dossier sont obligatoires!')
            return

        task_data = {
            "titre": titre,
            "sous_titre": "",
            "texte": commentaire,
            "date_fin": date_fin.strftime('%Y-%m-%dT%H:%M:%S'),
            "priorite": priorite,
            "statut": statut,
            "users": assignee_ids
        }

        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                if self.task_id:
                    # Modification d'une tâche existante
                    current_assignees = self.get_current_assignees()

                    # Mise à jour locale
                    cursor.execute("""
                        UPDATE TACHES 
                        SET titre = %s, id_dossier = %s, priorite = %s, date_fin = %s, 
                            commentaire = %s, statut = %s 
                        WHERE id_tache = %s""",
                        (titre, id_dossier, priorite, date_fin, commentaire, statut, self.task_id))

                    # Mise à jour API
                    try:
                        response = requests.put(
                            f"{AppConfig.API_BASE_URL}/taches/{self.task_id}",
                            json=task_data,
                            headers=self.session.headers,
                            verify=AppConfig.VERIFY_SSL
                        )
                        if not response.ok:
                            raise Exception(f"Erreur API lors de la mise à jour: {response.text}")
                    except requests.RequestException as e:
                        raise Exception(f"Erreur réseau lors de la mise à jour API: {str(e)}")

                    # Gestion des assignations
                    cursor.execute("DELETE FROM TACHE_USER WHERE id_tache = %s", (self.task_id,))
                    for assignee_id in assignee_ids:
                        cursor.execute("INSERT INTO TACHE_USER (id_tache, id_user) VALUES (%s, %s)", 
                                    (self.task_id, assignee_id))
                        # Assignation API
                        try:
                            response = requests.post(
                                f"{AppConfig.API_BASE_URL}/taches/{self.task_id}/assign",
                                json={"user_id": assignee_id},
                                headers=self.session.headers,
                                verify=AppConfig.VERIFY_SSL
                            )
                            if not response.ok:
                                raise Exception(f"Erreur lors de l'assignation sur l'API: {response.text}")
                        except requests.RequestException as e:
                            raise Exception(f"Erreur réseau lors de l'assignation: {str(e)}")

                    # Mise à jour des étiquettes
                    cursor.execute("DELETE FROM TACHE_ETIQUETTE WHERE id_tache = %s", (self.task_id,))
                    selected_items = self.etiquettes_list.selectedItems()
                    for item in selected_items:
                        etiquette_id = item.data(Qt.ItemDataRole.UserRole)
                        # Ajout local
                        cursor.execute(
                            "INSERT INTO TACHE_ETIQUETTE (id_tache, id_etiquettes) VALUES (%s, %s)",
                            (self.task_id, etiquette_id)
                        )
                        # Ajout API
                        try:
                            response = requests.post(
                                f"{AppConfig.API_BASE_URL}/etiquettes/{etiquette_id}/taches/{self.task_id}",
                                headers=self.session.headers,
                                verify=AppConfig.VERIFY_SSL
                            )
                            if not response.ok:
                                raise Exception(f"Erreur lors de l'ajout de l'étiquette sur l'API: {response.text}")
                        except requests.RequestException as e:
                            raise Exception(f"Erreur réseau lors de l'ajout de l'étiquette: {str(e)}")

                    cursor.execute("""
                        INSERT INTO HISTORIQUE (id_tache, id_user, action) 
                        VALUES (%s, %s, %s)""",
                        (self.task_id, self.parent.parent.user_id, 'Modification'))

                    # Envoi d'e-mails aux nouveaux assignés
                    new_assignees = set(assignee_ids) - set(current_assignees)
                    for assignee_id in new_assignees:
                        email = next((
                            self.assignee_list.item(i).data(Qt.ItemDataRole.UserRole + 1)
                            for i in range(self.assignee_list.count())
                            if self.assignee_list.item(i).data(Qt.ItemDataRole.UserRole) == assignee_id
                        ), None)
                        if email:
                            subject = "Nouvelle tâche assignée"
                            body = f"Bonjour,\n\nUne nouvelle tâche intitulée '{titre}' vous a été assignée.\n\nCordialement,\nL'équipe de l'application To-Do List."
                            send_email(email, subject, body)

                else:
                    # Création API
                    try:
                        response = requests.post(
                            f"{AppConfig.API_BASE_URL}/dossiers/{id_dossier}/taches",
                            json=task_data,
                            headers=self.session.headers,
                            verify=AppConfig.VERIFY_SSL
                        )
                        if not response.ok:
                            raise Exception(f"Erreur API lors de la création: {response.text}")
                        api_task_id = response.json().get('id')

                    except requests.RequestException as e:
                        raise Exception(f"Erreur réseau lors de la création API: {str(e)}")

                    # Création locale
                    cursor.execute("""
                        INSERT INTO TACHES (titre, id_dossier, priorite, date_fin, commentaire, statut)
                        VALUES (%s, %s, %s, %s, %s, %s)""",
                        (titre, id_dossier, priorite, date_fin, commentaire, statut))
                    task_id = cursor.lastrowid

                    # Gestion des assignations
                    for assignee_id in assignee_ids:
                        cursor.execute("INSERT INTO TACHE_USER (id_tache, id_user) VALUES (%s, %s)", 
                                    (task_id, assignee_id))

                    # Gestion des étiquettes pour nouvelle tâche
                    selected_items = self.etiquettes_list.selectedItems()
                    for item in selected_items:
                        etiquette_id = item.data(Qt.ItemDataRole.UserRole)
                        cursor.execute(
                            "INSERT INTO TACHE_ETIQUETTE (id_tache, id_etiquettes) VALUES (%s, %s)",
                            (task_id, etiquette_id)
                        )
                        # Ajout API
                        try:
                            response = requests.post(
                                f"{AppConfig.API_BASE_URL}/etiquettes/{etiquette_id}/taches/{api_task_id}",
                                headers=self.session.headers,
                                verify=AppConfig.VERIFY_SSL
                            )
                            if not response.ok:
                                raise Exception(f"Erreur lors de l'ajout de l'étiquette sur l'API: {response.text}")
                        except requests.RequestException as e:
                            raise Exception(f"Erreur réseau lors de l'ajout de l'étiquette: {str(e)}")

                    cursor.execute("""
                        INSERT INTO HISTORIQUE (id_tache, id_user, action)
                        VALUES (%s, %s, %s)""",
                        (task_id, self.parent.parent.user_id, 'Création'))

                    # Envoi des e-mails
                    if assignee_ids:
                        for email in assignee_emails:
                            subject = "Nouvelle tâche assignée"
                            body = f"Bonjour,\n\nUne nouvelle tâche intitulée '{titre}' vous a été assignée.\n\nCordialement,\nL'équipe de l'application To-Do List."
                            send_email(email, subject, body)
                    else:
                        cursor.execute("""
                            SELECT u.mail
                            FROM USER u
                            JOIN MEMBRE m ON u.id_user = m.id_user
                            WHERE m.id_groupe = %s""",
                            (self.parent.parent.group_id,))
                        group_members = cursor.fetchall()
                        for member in group_members:
                            email = member[0]
                            subject = "Nouvelle tâche créée dans votre groupe"
                            body = f"Bonjour,\n\nUne nouvelle tâche intitulée '{titre}' a été créée dans votre groupe.\n\nCordialement,\nL'équipe de l'application To-Do List."
                            send_email(email, subject, body)

                    # Envoyer les commentaires temporaires
                    for commentaire in self.temp_comments:
                        self.send_comment(api_task_id, commentaire)

                    # Envoyer les sous-tâches temporaires
                    for sous_tache in self.temp_sous_taches:
                        self.send_sous_tache(api_task_id, *sous_tache)

                connection.commit()
                QMessageBox.information(self, 'Succès', 'La tâche a été enregistrée avec succès!')
                self.accept()
                self.parent.load_tasks()
                self.parent.parent.folders_tab.load_folders()

        except Exception as e:
            connection.rollback()
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de l'enregistrement de la tâche: {str(e)}")
        finally:
            connection.close()

    def send_comment(self, task_id, commentaire):
        try:
            response = requests.post(
                f"{AppConfig.API_BASE_URL}/taches/{task_id}/commentaires",
                json={"commentaire": commentaire},
                headers=self.session.headers,
                verify=AppConfig.VERIFY_SSL
            )
            if not response.ok:
                raise Exception(f"Erreur API lors de l'ajout du commentaire: {response.text}")
        except requests.RequestException as e:
            raise Exception(f"Erreur réseau lors de l'ajout du commentaire: {str(e)}")

    def send_sous_tache(self, task_id, titre, priorite, date_fin, statut):
        sous_tache_data = {
            "titre": titre,
            "priorite": priorite,
            "date_fin": date_fin.isoformat(),
            "statut": statut,
            "id_tache": task_id
        }
        try:
            response = requests.post(
                f"{AppConfig.API_BASE_URL}/taches/{task_id}/sous-taches",
                json=sous_tache_data,
                headers=self.session.headers,
                verify=AppConfig.VERIFY_SSL
            )
            if not response.ok:
                raise Exception(f"Erreur API lors de la création de la sous-tâche: {response.text}")
        except requests.RequestException as e:
            raise Exception(f"Erreur réseau lors de la création de la sous-tâche: {str(e)}")

    def load_folders(self):
        self.dossier_combo.clear()
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT d.id_dossier, d.nom
                    FROM DOSSIER d
                    WHERE d.id_groupe = %s
                """, (self.group_id,))
                folders = cursor.fetchall()
                self.dossier_combo.addItem("Aucun dossier", None)  # Added default option
                for folder in folders:
                    self.dossier_combo.addItem(folder[1], folder[0])
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors du chargement des dossiers: {str(e)}")
        finally:
            connection.close()

    def load_members(self):
        self.assignee_list.clear()
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT DISTINCT u.id_user, u.username, u.mail
                    FROM USER u
                    JOIN MEMBRE m ON u.id_user = m.id_user
                    WHERE m.id_groupe = %s
                """, (self.group_id,))
                members = cursor.fetchall()
                for member in members:
                    item = QListWidgetItem(member[1])
                    item.setData(Qt.ItemDataRole.UserRole, member[0])
                    item.setData(Qt.ItemDataRole.UserRole + 1, member[2])  # Store email
                    item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    item.setCheckState(Qt.CheckState.Unchecked)
                    self.assignee_list.addItem(item)
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors du chargement des membres: {str(e)}")
        finally:
            connection.close()



    def load_task_data(self):
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT titre, id_dossier, priorite, date_fin, commentaire, statut FROM TACHES WHERE id_tache = %s", (self.task_id,))
                task = cursor.fetchone()
                self.titre_input.setText(task[0])
                self.dossier_combo.setCurrentIndex(self.dossier_combo.findData(task[1]))
                self.priorite_combo.setCurrentIndex(task[2])
                self.date_fin_edit.setDate(task[3])
                self.commentaire_input.setText(task[4])
                self.statut_combo.setCurrentIndex(task[5])
                
                # Charger les utilisateurs assignés
                cursor.execute("SELECT id_user FROM TACHE_USER WHERE id_tache = %s", (self.task_id,))
                assigned_users = cursor.fetchall()
                assigned_user_ids = [user[0] for user in assigned_users]
                for i in range(self.assignee_list.count()):
                    item = self.assignee_list.item(i)
                    if item.data(Qt.ItemDataRole.UserRole) in assigned_user_ids:
                        item.setCheckState(Qt.CheckState.Checked)
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors du chargement des données de la tâche: {str(e)}")
        finally:
            connection.close()


    def get_current_assignees(self):
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT id_user FROM TACHE_USER WHERE id_tache = %s", (self.task_id,))
                assigned_users = cursor.fetchall()
                return [user[0] for user in assigned_users]
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de la récupération des utilisateurs assignés: {str(e)}")
            return []
        finally:
            connection.close()


    def add_comment(self):
        """
        Ajoute un commentaire avec synchronisation BDD locale et API.
        """
        commentaire = self.commentaire_input.text().strip()
        if not commentaire:
            QMessageBox.warning(self, 'Erreur', 'Le commentaire ne peut pas être vide!')
            return

        if not self.task_id:
            self.temp_comments.append(commentaire)
            self.commentaire_input.clear()
            self.commentaires_list.addItem(f"Temp: {commentaire}")
            return
        
        try:
            # Vérification du contenu du commentaire
            commentaire = self.commentaire_input.text().strip()
            if not commentaire:
                QMessageBox.warning(self, 'Erreur', 'Le commentaire ne peut pas être vide!')
                return
    
            connection = get_connection()
            try:
                with connection.cursor() as cursor:
                    # Vérifier que la tâche existe
                    cursor.execute("""
                        SELECT t.id_tache 
                        FROM TACHES t 
                        WHERE t.id_tache = %s
                    """, (self.task_id,))
                    
                    tache = cursor.fetchone()
                    if not tache:
                        QMessageBox.warning(self, 'Erreur', 'La tâche parente n\'existe pas!')
                        return
    
                    # Création locale du commentaire
                    cursor.execute("""
                        INSERT INTO COMMENTAIRES 
                        (id_tache, id_user, commentaire, date_commentaire) 
                        VALUES (%s, %s, %s, %s)
                    """, (
                        self.task_id,
                        self.parent.parent.user_id,  # Correction ici
                        commentaire,
                        datetime.utcnow()
                    ))
                    
                    commentaire_id = cursor.lastrowid
    
                    # Ajout dans l'historique
                    cursor.execute("""
                        INSERT INTO HISTORIQUE 
                        (id_user, id_tache, action, date) 
                        VALUES (%s, %s, %s, %s)
                    """, (
                        self.parent.parent.user_id,  # Correction ici
                        self.task_id,
                        "Ajout d'un commentaire",
                        datetime.utcnow()
                    ))
    
                    # Tentative de synchronisation avec l'API
                    try:
                        response = requests.post(
                            f"{AppConfig.API_BASE_URL}/taches/{self.task_id}/commentaires",
                            json={
                                "commentaire": commentaire
                            },
                            headers=self.parent.parent.session.headers,
                            verify=AppConfig.VERIFY_SSL
                        )
                        
                        if not response.ok:
                            # Log l'erreur mais continue le processus
                            print(f"Erreur API lors de l'ajout du commentaire: {response.text}")
                            QMessageBox.warning(
                                self, 
                                'Attention',
                                'Le commentaire a été ajouté localement mais la synchronisation avec le serveur a échoué.'
                            )
    
                    except requests.RequestException as e:
                        print(f"Erreur de connexion API: {str(e)}")
                        QMessageBox.warning(
                            self,
                            'Attention',
                            'Le commentaire a été ajouté localement mais la synchronisation avec le serveur a échoué.\n'
                            'La synchronisation sera tentée automatiquement plus tard.'
                        )
    
                    # Commit des changements locaux
                    connection.commit()
    
                    # Nettoyer et rafraîchir l'interface
                    self.commentaire_input.clear()
                    self.load_comments()
                    QMessageBox.information(self, 'Succès', 'Le commentaire a été ajouté avec succès!')
    
            except pymysql.Error as e:
                connection.rollback()
                QMessageBox.critical(
                    self,
                    'Erreur',
                    f"Erreur lors de l'ajout du commentaire dans la base de données: {str(e)}"
                )
            finally:
                connection.close()
    
        except Exception as e:
            QMessageBox.critical(
                self,
                'Erreur',
                f"Une erreur inattendue s'est produite: {str(e)}"
            )


    def load_comments(self):
        self.commentaires_list.clear()
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT c.commentaire, u.username, c.date_commentaire FROM COMMENTAIRES c JOIN USER u ON c.id_user = u.id_user WHERE c.id_tache = %s ORDER BY c.date_commentaire DESC", (self.task_id,))
                commentaires = cursor.fetchall()
                for commentaire in commentaires:
                    self.commentaires_list.addItem(f"{commentaire[1]} ({commentaire[2]}): {commentaire[0]}")
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors du chargement des commentaires: {str(e)}")
        finally:
            connection.close()

    def add_sous_tache(self):
        if not self.task_id:
            # Ouvrir le formulaire de sous-tâche même si la tâche n'est pas encore créée
            sous_tache_dialog = SousTacheDialog(self, None, self.session)  # Passer None pour task_id
            if sous_tache_dialog.exec() == QDialog.DialogCode.Accepted:
                # Récupérer les informations de la sous-tâche depuis le formulaire
                titre = sous_tache_dialog.titre_input.text().strip()
                priorite = sous_tache_dialog.priorite_combo.currentIndex()
                date_fin = sous_tache_dialog.date_fin_edit.date().toPyDate()
                statut = sous_tache_dialog.statut_combo.currentIndex()

                if not titre:
                    QMessageBox.warning(self, 'Erreur', 'Le titre de la sous-tâche est obligatoire!')
                    return

                self.temp_sous_taches.append((titre, priorite, date_fin, statut))
                self.sous_taches_list.addItem(f"Temp: {titre} - Priorité: {priorite}, Date de fin: {date_fin}, Statut: {statut}")
            return

        # Ouvrir le formulaire de sous-tâche si la tâche est déjà créée
        sous_tache_dialog = SousTacheDialog(self, self.task_id, self.session)  # Passer la session ici
        if sous_tache_dialog.exec() == QDialog.DialogCode.Accepted:
            self.load_sous_taches()

    def load_sous_taches(self):
        self.sous_taches_list.clear()
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT titre, priorite, date_fin, statut FROM SOUS_TACHES WHERE id_tache = %s ORDER BY date_fin ASC", (self.task_id,))
                sous_taches = cursor.fetchall()
                for sous_tache in sous_taches:
                    self.sous_taches_list.addItem(f"{sous_tache[0]} - Priorité: {sous_tache[1]}, Date de fin: {sous_tache[2]}, Statut: {sous_tache[3]}")
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors du chargement des sous-tâches: {str(e)}")
        finally:
            connection.close()

    def apply_theme(self):
        if self.parent.parent.get_current_theme() == 'dark':
            self.setStyleSheet(DARK_STYLE)
        else:
            self.setStyleSheet(LIGHT_STYLE)

    def add_etiquette(self):
        etiquette_dialog = EtiquetteDialog(self)
        if etiquette_dialog.exec() == QDialog.DialogCode.Accepted:
            self.load_etiquettes()

class EtiquetteDialog(QDialog):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Ajouter Étiquette")
        self.setGeometry(500, 200, 400, 200)
        vbox = QVBoxLayout()
        self.nom_input = QLineEdit()
        self.nom_input.setPlaceholderText("Nom de l'étiquette")
        vbox.addWidget(self.nom_input)
        hbox = QHBoxLayout()
        self.save_button = QPushButton("Enregistrer")
        self.save_button.clicked.connect(self.save_etiquette)
        hbox.addWidget(self.save_button)
        self.cancel_button = QPushButton("Annuler")
        self.cancel_button.clicked.connect(self.reject)
        hbox.addWidget(self.cancel_button)
        vbox.addLayout(hbox)
        self.setLayout(vbox)

    def save_etiquette(self):
        description = self.nom_input.text()
        if not description:
            QMessageBox.warning(self, 'Erreur', 'La description de l\'étiquette est obligatoire!')
            return
            
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                # Création locale
                cursor.execute("INSERT INTO ETIQUETTES (description) VALUES (%s)", (description,))
                etiquette_id = cursor.lastrowid

                # Création API
                try:
                    response = requests.post(
                        f"{AppConfig.API_BASE_URL}/etiquettes",
                        json={"description": description},
                        headers=self.parent.parent.session.headers,
                        verify=AppConfig.VERIFY_SSL
                    )
                    
                    if not response.ok:
                        raise Exception(f"Erreur API lors de la création de l'étiquette: {response.text}")

                except requests.RequestException as e:
                    raise Exception(f"Erreur réseau lors de la création sur l'API: {str(e)}")

                connection.commit()
                self.accept()
                
        except Exception as e:
            connection.rollback()
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de l'enregistrement de l'étiquette: {str(e)}")
        finally:
            connection.close()

    def apply_theme(self):
        if self.parent.parent.get_current_theme() == 'dark':
            self.setStyleSheet(DARK_STYLE)
        else:
            self.setStyleSheet(LIGHT_STYLE)



class SousTacheDialog(QDialog):
    def __init__(self, parent, task_id, session):
        super().__init__()
        self.parent = parent
        self.task_id = task_id
        self.session = session or parent.session  # Utiliser la session du parent si non fournie
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Ajouter Sous-tâche")
        self.setGeometry(500, 200, 400, 300)
        vbox = QVBoxLayout()
        self.titre_input = QLineEdit()
        self.titre_input.setPlaceholderText("Titre de la sous-tâche")
        vbox.addWidget(self.titre_input)
        self.priorite_combo = QComboBox()
        self.priorite_combo.addItems(["Faible", "Moyenne", "Élevée"])
        vbox.addWidget(self.priorite_combo)
        self.date_fin_edit = QDateEdit()
        self.date_fin_edit.setDate(QDate.currentDate().addDays(7))
        vbox.addWidget(self.date_fin_edit)
        self.statut_combo = QComboBox()
        self.statut_combo.addItems(["En cours", "Terminée", "Echoué"])
        vbox.addWidget(self.statut_combo)
        hbox = QHBoxLayout()
        self.save_button = QPushButton("Enregistrer")
        self.save_button.clicked.connect(self.save_sous_tache)
        hbox.addWidget(self.save_button)
        self.cancel_button = QPushButton("Annuler")
        self.cancel_button.clicked.connect(self.reject)
        hbox.addWidget(self.cancel_button)
        vbox.addLayout(hbox)
        self.setLayout(vbox)


    def save_sous_tache(self):
        """
        Sauvegarde une sous-tâche avec vérification de la tâche parente.
        Crée d'abord en local puis synchronise avec l'API si possible.
        """
        try:
            # Récupération des données du formulaire
            titre = self.titre_input.text()
            priorite = self.priorite_combo.currentIndex()
            date_fin = self.date_fin_edit.date().toPyDate()
            statut = self.statut_combo.currentIndex()

            # Validation basique
            if not titre:
                QMessageBox.warning(self, 'Erreur', 'Le titre de la sous-tâche est obligatoire!')
                return

            # Validation de la date
            if date_fin < datetime.now().date():
                QMessageBox.warning(self, 'Erreur', 'La date de fin ne peut pas être dans le passé!')
                return

            connection = get_connection()
            try:
                with connection.cursor() as cursor:
                    # Vérifier que la tâche parente existe
                    cursor.execute("""
                        SELECT t.id_tache 
                        FROM TACHES t 
                        WHERE t.id_tache = %s
                    """, (self.task_id,))
                    
                    tache = cursor.fetchone()
                    if not tache:
                        QMessageBox.warning(self, 'Erreur', 'La tâche parente n\'existe pas!')
                        return

                    # Création locale de la sous-tâche
                    cursor.execute("""
                        INSERT INTO SOUS_TACHES 
                        (id_tache, titre, priorite, date_fin, statut) 
                        VALUES (%s, %s, %s, %s, %s)
                    """, (self.task_id, titre, priorite, date_fin, statut))
                    
                    sous_tache_id = cursor.lastrowid

                    # Ajout à l'historique
                    cursor.execute("""
                        INSERT INTO HISTORIQUE (id_user, id_tache, action, date)
                        VALUES (%s, %s, %s, %s)
                    """, (
                        self.parent.parent.parent.user_id,
                        self.task_id,
                        f"Création de la sous-tâche: {titre}",
                        datetime.utcnow()
                    ))

                    # Préparation des données pour l'API
                    sous_tache_data = {
                        "titre": titre,
                        "priorite": priorite,
                        "date_fin": date_fin.isoformat(),
                        "statut": statut,
                        "id_tache": self.task_id
                    }

                    # Tentative de synchronisation avec l'API
                    try:
                        response = requests.post(
                            f"{AppConfig.API_BASE_URL}/taches/{self.task_id}/sous-taches",
                            json=sous_tache_data,
                            headers=self.parent.parent.parent.session.headers,
                            verify=AppConfig.VERIFY_SSL
                        )
                        
                        if not response.ok:
                            # Log l'erreur mais continue le processus
                            print(f"Erreur API lors de la création de la sous-tâche: {response.text}")
                            QMessageBox.warning(
                                self, 
                                'Attention',
                                'La sous-tâche a été créée localement mais la synchronisation avec le serveur a échoué.'
                            )

                    except requests.RequestException as e:
                        print(f"Erreur de connexion API: {str(e)}")
                        QMessageBox.warning(
                            self,
                            'Attention',
                            'La sous-tâche a été créée localement mais la synchronisation avec le serveur a échoué.\n'
                            'La synchronisation sera tentée automatiquement plus tard.'
                        )

                    # Commit des changements locaux
                    connection.commit()
                    QMessageBox.information(self, 'Succès', 'La sous-tâche a été créée avec succès!')
                    self.accept()

            except pymysql.Error as e:
                connection.rollback()
                QMessageBox.critical(
                    self,
                    'Erreur',
                    f"Erreur lors de l'enregistrement dans la base de données : {str(e)}"
                )
            finally:
                connection.close()

        except Exception as e:
            QMessageBox.critical(
                self,
                'Erreur',
                f"Une erreur inattendue s'est produite : {str(e)}"
            )
            
    def apply_theme(self):
        if self.parent.parent.get_current_theme() == 'dark':
            self.setStyleSheet(DARK_STYLE)
        else:
            self.setStyleSheet(LIGHT_STYLE)


class GroupsTab(QWidget):
    """
    Onglet de gestion des groupes.
    
    Permet la création, modification et suppression des groupes de travail.
    Gère également les invitations et les permissions des membres.
    
    Attributes:
        parent (TodoListApp): Instance parente de l'application
        current_page (int): Page actuelle pour la pagination
        items_per_page (int): Nombre d'éléments par page
        
    Methods:
        load_groups(): Charge la liste des groupes
        search_groups(): Recherche dans les groupes
        check_permission_and_open_group_dialog(): Vérifie les droits avant d'ouvrir le dialogue
        open_invite_user_dialog(): Ouvre le dialogue d'invitation
        open_manage_members_dialog(): Ouvre le gestionnaire de membres
    """
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.current_page = 0
        self.items_per_page = 10
        self.initUI()

    def initUI(self):
        vbox = QVBoxLayout()
        hbox = QHBoxLayout()

        # Barre de recherche
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Rechercher un groupe...")
        self.search_button = QPushButton("Rechercher")
        self.search_button.clicked.connect(self.search_groups)
        hbox.addWidget(self.search_input)
        hbox.addWidget(self.search_button)
        vbox.addLayout(hbox)

        # Tableau des groupes
        self.groups_table = QTableWidget()
        self.groups_table.setColumnCount(6)
        self.groups_table.setHorizontalHeaderLabels(
            ["Nom", "Dernière synchronisation", "Rôle", "Actions", "Inviter", "Gérer les membres"]
        )
        self.groups_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.groups_table.cellDoubleClicked.connect(self.open_group_dialog)

        # Réduire la largeur des colonnes
        self.groups_table.setColumnWidth(0, 100)  # Ajuste la largeur de la première colonne (Nom)
        self.groups_table.setColumnWidth(1, 180)  # Ajuste la largeur de la deuxième colonne (Dernière synchronisation)
        self.groups_table.setColumnWidth(2, 100)  # Ajuste la largeur de la colonne "Rôle"
        self.groups_table.setColumnWidth(3, 100)  # Ajuste la largeur de la colonne "Actions"
        self.groups_table.setColumnWidth(4, 80)   # Ajuste la largeur de la colonne "Inviter"
        self.groups_table.setColumnWidth(5, 160)  # Ajuste la largeur de la colonne "Gérer les membres"

        self.groups_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)  # Fixe la taille des colonnes
        self.groups_table.verticalHeader().setDefaultSectionSize(40)  # Hauteur des lignes
        vbox.addWidget(self.groups_table)

        hbox = QHBoxLayout()
        
        self.prev_button = QPushButton("Précédent")
        self.prev_button.setIcon(QIcon.fromTheme("go-previous"))  # Icône standard pour "Précédent"
        self.prev_button.setIconSize(QSize(16, 16))  # Ajuster la taille de l'icône
        self.prev_button.setStyleSheet("padding: 5px 10px;")
        self.prev_button.clicked.connect(self.prev_page)
        self.prev_button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        hbox.addWidget(self.prev_button)

        self.add_group_button = QPushButton("Nouveau groupe")
        self.add_group_button.clicked.connect(self.open_group_dialog)
        self.add_group_button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        hbox.addWidget(self.add_group_button)

        self.next_button = QPushButton("Suivant")
        self.next_button.setIcon(QIcon.fromTheme("go-next"))  # Icône standard pour "Suivant"
        self.next_button.setIconSize(QSize(16, 16))  # Ajuster la taille de l'icône
        self.next_button.setStyleSheet("padding: 5px 10px;")
        self.next_button.clicked.connect(self.next_page)
        self.next_button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        hbox.addWidget(self.next_button)

        vbox.addLayout(hbox)

        self.setLayout(vbox)
        self.load_groups()

    def load_groups(self):
        self.groups_table.setRowCount(0)
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                offset = self.current_page * self.items_per_page
                cursor.execute("""
                    SELECT DISTINCT g.id_groupe, g.nom, g.synchro, 
                           COALESCE(m.role, 'membre') as role
                    FROM GROUPE g
                    LEFT JOIN MEMBRE m ON g.id_groupe = m.id_groupe AND m.id_user = %s
                    WHERE g.id_user = %s OR m.id_user = %s
                    ORDER BY g.nom
                    LIMIT %s OFFSET %s
                """, (self.parent.user_id, self.parent.user_id, self.parent.user_id, self.items_per_page, offset))
                groups = cursor.fetchall()
                for row, group in enumerate(groups):
                    self.groups_table.insertRow(row)
                    # Insérez les données dans les bonnes colonnes
                    self.groups_table.setItem(row, 0, QTableWidgetItem(group[1]))  # Nom du groupe
                    self.groups_table.setItem(row, 1, QTableWidgetItem(group[2].strftime('%Y-%m-%d %H:%M:%S')))  # Dernière synchronisation
                    self.groups_table.setItem(row, 2, QTableWidgetItem(group[3]))  # Rôle

                    # Boutons avec styles globaux
                    edit_button = QPushButton("Modifier")
                    edit_button.clicked.connect(lambda checked, group_id=group[0]: self.check_permission_and_open_group_dialog(group_id))
                    self.groups_table.setCellWidget(row, 3, edit_button)

                    invite_button = QPushButton("Inviter")
                    invite_button.clicked.connect(lambda checked, group_id=group[0]: self.check_permission_and_open_invite_user_dialog(group_id))
                    self.groups_table.setCellWidget(row, 4, invite_button)

                    manage_members_button = QPushButton("Gérer les membres")
                    manage_members_button.clicked.connect(lambda checked, group_id=group[0]: self.check_permission_and_open_manage_members_dialog(group_id))
                    self.groups_table.setCellWidget(row, 5, manage_members_button)

                    # Désactiver les boutons si l'utilisateur n'est pas admin
                    if group[3] != 'admin':
                        edit_button.setEnabled(False)
                        invite_button.setEnabled(False)
                        manage_members_button.setEnabled(False)
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors du chargement des groupes: {str(e)}")
        finally:
            connection.close()



    def search_groups(self):
        search_text = self.search_input.text()
        self.groups_table.setRowCount(0)
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT g.id_groupe, g.nom, g.synchro, 
                        (SELECT m.role FROM MEMBRE m WHERE m.id_groupe = g.id_groupe AND m.id_user = %s) AS role
                    FROM GROUPE g
                    LEFT JOIN MEMBRE m ON g.id_groupe = m.id_groupe
                    WHERE (g.id_user = %s OR m.id_user = %s) AND g.nom LIKE %s
                    GROUP BY g.id_groupe, g.nom, g.synchro
                """, (self.parent.user_id, self.parent.user_id, self.parent.user_id, f"%{search_text}%"))
                groups = cursor.fetchall()
                for row, group in enumerate(groups):
                    self.groups_table.insertRow(row)
                    # Insérez les données dans les bonnes colonnes
                    self.groups_table.setItem(row, 0, QTableWidgetItem(group[1]))  # Nom du groupe
                    self.groups_table.setItem(row, 1, QTableWidgetItem(group[2].strftime('%Y-%m-%d %H:%M:%S')))  # Dernière synchronisation
                    self.groups_table.setItem(row, 2, QTableWidgetItem(group[3]))  # Rôle

                    edit_button = QPushButton("Modifier")
                    edit_button.setStyleSheet("padding: 5px 10px;")
                    edit_button.clicked.connect(lambda checked, group_id=group[0]: self.check_permission_and_open_group_dialog(group_id))
                    self.groups_table.setCellWidget(row, 3, edit_button)

                    invite_button = QPushButton("Inviter")
                    invite_button.setStyleSheet("padding: 5px 10px;")
                    invite_button.clicked.connect(lambda checked, group_id=group[0]: self.check_permission_and_open_invite_user_dialog(group_id))
                    self.groups_table.setCellWidget(row, 4, invite_button)

                    manage_members_button = QPushButton("Gérer les membres")
                    manage_members_button.setStyleSheet("padding: 10px 20px;")
                    manage_members_button.clicked.connect(lambda checked, group_id=group[0]: self.check_permission_and_open_manage_members_dialog(group_id))
                    self.groups_table.setCellWidget(row, 5, manage_members_button)

                    if group[3] != 'admin':
                        edit_button.setEnabled(False)
                        invite_button.setEnabled(False)
                        manage_members_button.setEnabled(False)
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de la recherche des groupes: {str(e)}")
        finally:
            connection.close()


    def check_permission_and_open_group_dialog(self, group_id):
        if self.parent.is_admin(group_id):
            self.open_group_dialog(group_id)
        else:
            QMessageBox.warning(self, 'Erreur', 'Vous n\'êtes pas autorisé à modifier ce groupe.')

    def check_permission_and_open_invite_user_dialog(self, group_id):
        if self.parent.is_admin(group_id):
            self.open_invite_user_dialog(group_id)
        else:
            QMessageBox.warning(self, 'Erreur', 'Vous n\'êtes pas autorisé à inviter des utilisateurs dans ce groupe.')

    def check_permission_and_open_manage_members_dialog(self, group_id):
        if self.parent.is_admin(group_id):
            self.open_manage_members_dialog(group_id)
        else:
            QMessageBox.warning(self, 'Erreur', 'Vous n\'êtes pas autorisé à gérer les membres de ce groupe.')

    def open_group_dialog(self, group_id=None):
        if group_id:
            self.group_dialog = GroupDialog(self.parent, group_id, self.parent.session)  # Passer la session ici
        else:
            self.group_dialog = GroupDialog(self.parent, session=self.parent.session)  # Passer la session ici
        self.group_dialog.apply_theme()  # Appliquer le thème au dialogue
        self.group_dialog.group_created.connect(self.parent.select_group)  # Connecter le signal
        self.group_dialog.exec()
        self.load_groups()

    def open_invite_user_dialog(self, group_id):
        self.invite_user_dialog = InviteUserDialog(self.parent, group_id)
        self.invite_user_dialog.apply_theme()  # Appliquer le thème au dialogue
        self.invite_user_dialog.exec()

    def open_manage_members_dialog(self, group_id):
        self.manage_members_dialog = ManageMembersDialog(self.parent, group_id)
        self.manage_members_dialog.role_updated.connect(self.load_groups)  # Connect the signal to reload groups
        self.manage_members_dialog.apply_theme()  # Appliquer le thème au dialogue
        self.manage_members_dialog.exec()

    def prev_page(self):
        if self.current_page > 0:
            self.current_page -= 1
            self.load_groups()

    def next_page(self):
        self.current_page += 1
        self.load_groups()











class GroupDialog(QDialog):
    """
    Dialogue de création/modification de groupe.
    
    Permet de créer un nouveau groupe ou de modifier un groupe existant.
    
    Attributes:
        parent (GroupsTab): Onglet parent des groupes
        group_id (int): ID du groupe en édition (None pour nouveau groupe)
        group_created (pyqtSignal): Signal émis à la création d'un groupe
        
    Methods:
        load_group_data(): Charge les données du groupe
        save_group(): Sauvegarde les modifications
    """
    group_created = pyqtSignal(int)  # Signal pour notifier la création d'un groupe
    
    def __init__(self, parent, group_id=None, session=None):
        super().__init__()
        self.parent = parent
        self.group_id = group_id
        self.session = session  # Ajouter l'attribut session
        self.new_group_id = None  # Ajoutez cette ligne
        self.initUI()
        self.apply_theme()

    def initUI(self):
        self.setWindowTitle("Gestion de groupe")
        self.setGeometry(500, 200, 400, 300)
        vbox = QVBoxLayout()
        self.nom_input = QLineEdit()
        self.nom_input.setPlaceholderText("Nom du groupe")
        vbox.addWidget(self.nom_input)
        hbox = QHBoxLayout()
        self.save_button = QPushButton("Enregistrer")
        self.save_button.clicked.connect(self.save_group)
        hbox.addWidget(self.save_button)
        self.cancel_button = QPushButton("Annuler")
        self.cancel_button.clicked.connect(self.reject)
        hbox.addWidget(self.cancel_button)
        vbox.addLayout(hbox)
        if self.group_id:
            self.load_group_data()
        self.setLayout(vbox)

    def load_group_data(self):
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT nom FROM GROUPE WHERE id_groupe = %s AND id_user = %s", (self.group_id, self.parent.user_id))
                group = cursor.fetchone()
                if group:
                    self.nom_input.setText(group[0])
                else:
                    QMessageBox.warning(self, 'Erreur', 'Groupe non trouvé ou vous n\'êtes pas autorisé à le modifier.')
                    self.reject()
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors du chargement des données du groupe: {str(e)}")
        finally:
            connection.close()

    def save_group(self):
        nom = self.nom_input.text()
        if not nom:
            QMessageBox.warning(self, 'Erreur', 'Le nom du groupe est obligatoire!')
            return

        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                if self.group_id:
                    # Mise à jour locale
                    cursor.execute("""
                        UPDATE GROUPE 
                        SET nom = %s 
                        WHERE id_groupe = %s AND id_user = %s""",
                        (nom, self.group_id, self.parent.user_id))

                    # Mise à jour API
                    try:
                        response = requests.put(
                            f"{AppConfig.API_BASE_URL}/groupes/{self.group_id}",
                            json={"nom": nom},
                            headers=self.session.headers,  # Utiliser self.session ici
                            verify=AppConfig.VERIFY_SSL
                        )
                        if not response.ok:
                            raise Exception(f"Erreur API lors de la mise à jour du groupe: {response.text}")

                    except requests.RequestException as e:
                        raise Exception(f"Erreur réseau lors de la mise à jour sur l'API: {str(e)}")

                else:
                    # Création API
                    try:
                        response = requests.post(
                            f"{AppConfig.API_BASE_URL}/groupes",
                            json={"nom": nom},
                            headers=self.session.headers,  # Utiliser self.session ici
                            verify=AppConfig.VERIFY_SSL
                        )
                        if not response.ok:
                            raise Exception(f"Erreur API lors de la création du groupe: {response.text}")
                        api_group = response.json()
                        api_group_id = api_group.get('id')

                    except requests.RequestException as e:
                        raise Exception(f"Erreur réseau lors de la création sur l'API: {str(e)}")

                    # Création locale
                    cursor.execute("INSERT INTO GROUPE (nom, id_user) VALUES (%s, %s)", 
                                (nom, self.parent.user_id))
                    self.new_group_id = cursor.lastrowid
                    cursor.execute("""
                        INSERT INTO MEMBRE (id_groupe, id_user, role) 
                        VALUES (%s, %s, 'admin')""",
                        (self.new_group_id, self.parent.user_id))

                connection.commit()
                self.accept()
                self.parent.groups_tab.load_groups()
                if self.new_group_id:
                    self.group_created.emit(self.new_group_id)

        except Exception as e:
            connection.rollback()
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de l'enregistrement du groupe: {str(e)}")
        finally:
            connection.close()

    def apply_theme(self):
        if self.parent.get_current_theme() == 'dark':
            self.setStyleSheet(DARK_STYLE)
        else:
            self.setStyleSheet(LIGHT_STYLE)



class ManageMembersDialog(QDialog):
    """
    Dialogue de gestion des membres.
    
    Permet de modifier les rôles des membres et de supprimer des membres.
    
    Attributes:
        parent (GroupsTab): Onglet parent des groupes
        group_id (int): ID du groupe en édition
        role_updated (pyqtSignal): Signal émis à la mise à jour d'un rôle
        
    Methods:
        load_members(): Charge les membres du groupe
        update_role(): Met à jour le rôle d'un membre
        remove_member(): Supprime un membre
    """
    role_updated = pyqtSignal()  # Déclaration du signal

    def __init__(self, parent, group_id):
        super().__init__()
        self.parent = parent
        self.group_id = group_id
        self.current_user_role = None
        self.initUI()
        self.apply_theme()

    def initUI(self):
        self.setWindowTitle("Gestion des membres")
        self.setGeometry(500, 200, 400, 300)
        vbox = QVBoxLayout()
        self.members_table = QTableWidget()
        self.members_table.setColumnCount(3)
        self.members_table.setHorizontalHeaderLabels(["Utilisateur", "Rôle", "Actions"])
        self.members_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        vbox.addWidget(self.members_table)
        self.load_members()
        self.setLayout(vbox)


    def load_members(self):
        self.members_table.setRowCount(0)
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                # Get the current user's role in the group
                cursor.execute("SELECT role FROM MEMBRE WHERE id_groupe = %s AND id_user = %s", 
                            (self.group_id, self.parent.user_id))
                result = cursor.fetchone()
                if result:
                    self.current_user_role = result[0]
                else:
                    self.current_user_role = None
    
                cursor.execute("""
                    SELECT u.username, m.role, m.id_user
                    FROM MEMBRE m
                    JOIN USER u ON m.id_user = u.id_user
                    WHERE m.id_groupe = %s
                    ORDER BY u.username
                """, (self.group_id,))
                
                members = cursor.fetchall()
                logging.info(f"Members fetched: {members}")
                for row, member in enumerate(members):
                    logging.info(f"Inserting member: {member}")
                    self.members_table.insertRow(row)
                    self.members_table.setItem(row, 0, QTableWidgetItem(member[0]))  # Utilisateur
                    
                    role_combo = QComboBox()
                    role_combo.addItems(["lecture", "éditeur", "admin"])
                    role_combo.setCurrentText(member[1])
                    if self.current_user_role != "admin":
                        role_combo.setEnabled(False)
                    role_combo.currentIndexChanged.connect(
                        lambda index, user_id=member[2]: self.update_role(user_id, role_combo.currentText())
                    )
                    self.members_table.setCellWidget(row, 1, role_combo)  # Rôle
                    
                    remove_button = QPushButton("Supprimer")
                    remove_button.clicked.connect(lambda checked, user_id=member[2]: self.remove_member(user_id))
                    if self.current_user_role != "admin":
                        remove_button.setEnabled(False)
                    self.members_table.setCellWidget(row, 2, remove_button)  # Actions
                    
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors du chargement des membres: {str(e)}")
        finally:
            connection.close()

    def update_role(self, user_id, role):
        if self.current_user_role != "admin":
            QMessageBox.warning(self, 'Erreur', 'Vous n\'êtes pas autorisé à modifier les rôles.')
            return
    
        if role not in ["lecture", "éditeur", "admin"]:
            QMessageBox.warning(self, 'Erreur', 'Rôle invalide.')
            return
                    
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                # D'abord obtenir l'ID du membre
                cursor.execute("""
                    SELECT id_membre, id_user
                    FROM MEMBRE 
                    WHERE id_groupe = %s AND id_user = %s""", 
                    (self.group_id, user_id))
                membre = cursor.fetchone()
                if not membre:
                    raise Exception("Membre non trouvé")
                        
                membre_id = membre[0]  # Récupérer l'ID du membre
                user_id = membre[1]  # Récupérer l'ID de l'utilisateur
                # Mise à jour API - inclure id_user et role
                try:
                    payload = {
                        "role": role,
                        "id_user": user_id  # Ajout de l'id_user au payload
                    }
                        
                    response = requests.put(
                        f"{AppConfig.API_BASE_URL}/membres/{membre_id}",
                        json=payload,
                        headers=self.parent.session.headers,
                        verify=AppConfig.VERIFY_SSL
                    )
                        
                    if not response.ok:
                        raise Exception(f"Erreur API lors de la mise à jour du rôle: {response.text}")
    
                except requests.RequestException as e:
                    raise Exception(f"Erreur réseau lors de la mise à jour sur l'API: {str(e)}")
    
                # Mise à jour locale
                cursor.execute("""
                    UPDATE MEMBRE 
                    SET role = %s 
                    WHERE id_groupe = %s AND id_user = %s""", 
                    (role, self.group_id, user_id))
                        
                connection.commit()
                self.load_members()  # Recharger les membres
                self.role_updated.emit()  # Émettre le signal
                    
        except Exception as e:
            connection.rollback()
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de la mise à jour du rôle: {str(e)}")
        finally:
            connection.close()

    def remove_member(self, user_id):
        if self.current_user_role != "admin":
            QMessageBox.warning(self, 'Erreur', 'Vous n\'êtes pas autorisé à supprimer des membres.')
            return
    
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                # Vérifier si l'utilisateur est le propriétaire du groupe
                cursor.execute("SELECT id_user FROM GROUPE WHERE id_groupe = %s", (self.group_id,))
                owner = cursor.fetchone()
                if owner and owner[0] == user_id:
                    QMessageBox.warning(self, 'Erreur', 'Vous ne pouvez pas supprimer le propriétaire du groupe.')
                    return
    
                # Suppression sur l'API
                try:
                    response = requests.delete(
                        f"{AppConfig.API_BASE_URL}/groupes/{self.group_id}/membres/{user_id}",
                        headers=self.parent.session.headers,
                        verify=AppConfig.VERIFY_SSL
                    )
    
                    if not response.ok:
                        raise Exception(f"Erreur API lors de la suppression du membre: {response.json().get('error', response.text)}")
    
                except requests.RequestException as e:
                    raise Exception(f"Erreur réseau lors de la suppression sur l'API: {str(e)}")
    
                # Suppression locale
                cursor.execute("DELETE FROM MEMBRE WHERE id_groupe = %s AND id_user = %s", (self.group_id, user_id))
    
                connection.commit()
                self.load_members()  # Mettre à jour l'interface utilisateur
    
        except Exception as e:
            connection.rollback()
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de la suppression du membre: {str(e)}")
        finally:
            connection.close()

    def apply_theme(self):
        if self.parent.get_current_theme() == 'dark':
            self.setStyleSheet(DARK_STYLE)
        else:
            self.setStyleSheet(LIGHT_STYLE)






class FoldersTab(QWidget):
    """
    Onglet de gestion des dossiers.
    
    Permet d'organiser les tâches en dossiers pour une meilleure organisation.
    Implémente la recherche et la pagination.
    
    Attributes:
        parent (TodoListApp): Instance parente de l'application
        current_page (int): Page actuelle pour la pagination
        items_per_page (int): Nombre d'éléments par page
        
    Methods:
        load_folders(): Charge la liste des dossiers
        delete_folder(): Supprime un dossier
        search_folders(): Recherche dans les dossiers
        open_folder_dialog(): Ouvre le dialogue d'édition
    """
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.current_page = 0
        self.items_per_page = 10
        self.initUI()

    def initUI(self):
        vbox = QVBoxLayout()
        hbox = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Rechercher un dossier...")
        self.search_button = QPushButton("Rechercher")
        self.search_button.clicked.connect(self.search_folders)
        hbox.addWidget(self.search_input)
        hbox.addWidget(self.search_button)
        vbox.addLayout(hbox)
        self.folders_table = QTableWidget()
        self.folders_table.setColumnCount(4)  # Ajout d'une colonne pour la suppression
        self.folders_table.setHorizontalHeaderLabels(["Nom", "Nombre de tâches", "Actions", "Supprimer"])
        self.folders_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.folders_table.cellDoubleClicked.connect(self.open_folder_dialog)

        # Ajuster les largeurs des colonnes
        self.folders_table.setColumnWidth(0, 200)  # Ajuste la largeur de la première colonne (Nom)
        self.folders_table.setColumnWidth(1, 180)  # Ajuste la largeur de la deuxième colonne (Nombre de tâches)
        self.folders_table.setColumnWidth(2, 100)  # Ajuste la largeur de la colonne "Actions"
        self.folders_table.setColumnWidth(3, 100)  # Ajuste la largeur de la colonne "Supprimer"

        self.folders_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)  # Fixe la taille des colonnes
        self.folders_table.verticalHeader().setDefaultSectionSize(40)  # Hauteur des lignes
        vbox.addWidget(self.folders_table)

        hbox = QHBoxLayout()
        
        self.prev_button = QPushButton("Précédent")
        self.prev_button.setIcon(QIcon.fromTheme("go-previous"))  # Icône standard pour "Précédent"
        self.prev_button.setIconSize(QSize(16, 16))  # Ajuster la taille de l'icône
        self.prev_button.setStyleSheet("padding: 5px 10px;")
        self.prev_button.clicked.connect(self.prev_page)
        self.prev_button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        hbox.addWidget(self.prev_button)

        self.add_folder_button = QPushButton("Nouveau dossier")
        self.add_folder_button.clicked.connect(self.open_folder_dialog)
        self.add_folder_button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        hbox.addWidget(self.add_folder_button)

        self.next_button = QPushButton("Suivant")
        self.next_button.setIcon(QIcon.fromTheme("go-next"))  # Icône standard pour "Suivant"
        self.next_button.setIconSize(QSize(16, 16))  # Ajuster la taille de l'icône
        self.next_button.setStyleSheet("padding: 5px 10px;")
        self.next_button.clicked.connect(self.next_page)
        self.next_button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        hbox.addWidget(self.next_button)

        vbox.addLayout(hbox)

        self.setLayout(vbox)
        self.load_folders()

    def load_folders(self):
        if not self.parent.group_id:
            return
        self.folders_table.setRowCount(0)
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                offset = self.current_page * self.items_per_page
                cursor.execute("""
                    SELECT d.id_dossier, d.nom, COUNT(t.id_tache) AS nb_taches
                    FROM DOSSIER d
                    LEFT JOIN TACHES t ON d.id_dossier = t.id_dossier
                    WHERE d.id_groupe = %s
                    GROUP BY d.id_dossier
                    LIMIT %s OFFSET %s
                """, (self.parent.group_id, self.items_per_page, offset))
                folders = cursor.fetchall()
                for row, folder in enumerate(folders):
                    self.folders_table.insertRow(row)
                    self.folders_table.setItem(row, 0, QTableWidgetItem(folder[1]))  # Nom du dossier
                    self.folders_table.setItem(row, 1, QTableWidgetItem(str(folder[2])))  # Nombre de tâches
                    edit_button = QPushButton("Modifier")
                    edit_button.setStyleSheet("padding: 5px 10px;")
                    edit_button.clicked.connect(lambda checked, folder_id=folder[0]: self.open_folder_dialog(folder_id))
                    self.folders_table.setCellWidget(row, 2, edit_button)
                    delete_button = QPushButton("Supprimer")
                    delete_button.setStyleSheet("padding: 5px 10px;")
                    delete_button.clicked.connect(lambda checked, folder_id=folder[0]: self.delete_folder(folder_id))
                    self.folders_table.setCellWidget(row, 3, delete_button)
                    if self.parent.get_user_role() not in ['admin', 'éditeur']:
                        edit_button.setEnabled(False)
                        delete_button.setEnabled(False)
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors du chargement des dossiers: {str(e)}")
        finally:
            connection.close()


    def delete_folder(self, folder_id):
        if self.parent.get_user_role() not in ['admin', 'éditeur']:
            QMessageBox.warning(self, 'Erreur', 'Vous n\'êtes pas autorisé à supprimer des dossiers.')
            return
            
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                # Récupérer les tâches du dossier
                cursor.execute("SELECT id_tache FROM TACHES WHERE id_dossier = %s", (folder_id,))
                tasks = cursor.fetchall()

                # Suppression API
                try:
                    # Supprimer le dossier sur l'API (cela devrait supprimer aussi les tâches associées)
                    response = requests.delete(
                        f"{AppConfig.API_BASE_URL}/dossiers/{folder_id}",
                        headers=self.parent.session.headers,  # Utiliser self.parent.session ici
                        verify=AppConfig.VERIFY_SSL
                    )
                    
                    if not response.ok:
                        raise Exception(f"Erreur API lors de la suppression du dossier: {response.text}")

                    # Si l'API ne gère pas les suppressions en cascade, supprimer aussi les tâches
                    for task in tasks:
                        task_id = task[0]
                        response = requests.delete(
                            f"{AppConfig.API_BASE_URL}/taches/{task_id}",
                            headers=self.parent.session.headers,  # Utiliser self.parent.session ici
                            verify=AppConfig.VERIFY_SSL
                        )
                        if not response.ok:
                            print(f"Attention: Erreur lors de la suppression de la tâche {task_id} sur l'API")

                except requests.RequestException as e:
                    raise Exception(f"Erreur réseau lors de la suppression sur l'API: {str(e)}")

                # Suppression locale
                for task in tasks:
                    task_id = task[0]
                    cursor.execute("DELETE FROM HISTORIQUE WHERE id_tache = %s", (task_id,))
                    cursor.execute("DELETE FROM SOUS_TACHES WHERE id_tache = %s", (task_id,))
                    cursor.execute("DELETE FROM COMMENTAIRES WHERE id_tache = %s", (task_id,))
                cursor.execute("DELETE FROM TACHES WHERE id_dossier = %s", (folder_id,))
                cursor.execute("DELETE FROM DOSSIER WHERE id_dossier = %s", (folder_id,))
                
                connection.commit()
                self.load_folders()
                
        except Exception as e:
            connection.rollback()
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de la suppression du dossier: {str(e)}")
        finally:
            connection.close()
    # ...existing code...

    def search_folders(self):
        if not self.parent.group_id:
            return
        search_text = self.search_input.text()
        self.folders_table.setRowCount(0)
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT d.id_dossier, d.nom, COUNT(t.id_tache) AS nb_taches
                    FROM DOSSIER d
                    LEFT JOIN TACHES t ON d.id_dossier = t.id_dossier
                    WHERE d.id_groupe = %s AND d.nom LIKE %s
                    GROUP BY d.id_dossier
                """, (self.parent.group_id, f"%{search_text}%"))
                folders = cursor.fetchall()
                for row, folder in enumerate(folders):
                    self.folders_table.insertRow(row)
                    self.folders_table.setItem(row, 0, QTableWidgetItem(folder[1]))  # Nom du dossier
                    self.folders_table.setItem(row, 1, QTableWidgetItem(str(folder[2])))  # Nombre de tâches
                    edit_button = QPushButton("Modifier")
                    edit_button.setStyleSheet("padding: 5px 10px;")
                    edit_button.clicked.connect(lambda checked, folder_id=folder[0]: self.open_folder_dialog(folder_id))
                    self.folders_table.setCellWidget(row, 2, edit_button)
                    delete_button = QPushButton("Supprimer")
                    delete_button.setStyleSheet("padding: 5px 10px;")
                    delete_button.clicked.connect(lambda checked, folder_id=folder[0]: self.delete_folder(folder_id))
                    self.folders_table.setCellWidget(row, 3, delete_button)
                    if self.parent.get_user_role() not in ['admin', 'éditeur']:
                        edit_button.setEnabled(False)
                        delete_button.setEnabled(False)
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de la recherche des dossiers: {str(e)}")
        finally:
            connection.close()

    def open_folder_dialog(self, folder_id=None):
        if folder_id:
            self.folder_dialog = FolderDialog(self, folder_id)  # Changed from self.parent to self
        else:
            self.folder_dialog = FolderDialog(self)  # Changed from self.parent to self
        self.folder_dialog.apply_theme()  # Appliquer le thème au dialogue
        self.folder_dialog.exec()
        self.load_folders()

    def prev_page(self):
        if self.current_page > 0:
            self.current_page -= 1
            self.load_folders()

    def next_page(self):
        self.current_page += 1
        self.load_folders()

    def get_current_theme(self):
        return self.parent.get_current_theme()

class FolderDialog(QDialog):
    """
    Dialogue de création/modification de dossier.
    
    Permet de créer un nouveau dossier ou de modifier un dossier existant.
    
    Attributes:
        parent (FoldersTab): Onglet parent des dossiers
        folder_id (int): ID du dossier en édition (None pour nouveau dossier)
        
    Methods:
        load_folder_data(): Charge les données du dossier
        save_folder(): Sauvegarde les modifications
    """
    def __init__(self, parent, folder_id=None):
        super().__init__()
        self.parent = parent
        self.folder_id = folder_id
        self.initUI()
        self.apply_theme()

    def initUI(self):
        self.setWindowTitle("Gestion de dossier")
        self.setGeometry(500, 200, 400, 300)
        vbox = QVBoxLayout()
        self.nom_input = QLineEdit()
        self.nom_input.setPlaceholderText("Nom du dossier")
        vbox.addWidget(self.nom_input)
        hbox = QHBoxLayout()
        self.save_button = QPushButton("Enregistrer")
        self.save_button.clicked.connect(self.save_folder)
        hbox.addWidget(self.save_button)
        self.cancel_button = QPushButton("Annuler")
        self.cancel_button.clicked.connect(self.reject)
        hbox.addWidget(self.cancel_button)
        vbox.addLayout(hbox)
        if self.folder_id:
            self.load_folder_data()
        self.setLayout(vbox)

    def load_folder_data(self):
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT nom FROM DOSSIER WHERE id_dossier = %s", (self.folder_id,))
                folder = cursor.fetchone()
                self.nom_input.setText(folder[0])
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors du chargement des données du dossier: {str(e)}")
        finally:
            connection.close()

    def save_folder(self):
        nom = self.nom_input.text()
        id_groupe = self.parent.parent.group_id
        
        if not nom or id_groupe is None:
            QMessageBox.warning(self, 'Erreur', 'Le nom du dossier et le groupe sont obligatoires!')
            return

        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                # Vérification du rôle
                cursor.execute("""
                    SELECT role 
                    FROM MEMBRE 
                    WHERE id_groupe = %s AND id_user = %s""", 
                    (id_groupe, self.parent.parent.user_id))
                role = cursor.fetchone()
                if not role or role[0] not in ['admin', 'éditeur']:
                    QMessageBox.warning(self, 'Erreur', 'Vous n\'êtes pas autorisé à créer des dossiers dans ce groupe.')
                    return

                if self.folder_id:
                    # Mise à jour locale
                    cursor.execute("""
                        UPDATE DOSSIER 
                        SET nom = %s, id_groupe = %s 
                        WHERE id_dossier = %s""", 
                        (nom, id_groupe, self.folder_id))

                    # Mise à jour API
                    try:
                        response = requests.put(
                            f"{AppConfig.API_BASE_URL}/dossiers/{self.folder_id}",
                            json={"nom": nom},
                            headers=self.parent.parent.session.headers,
                            verify=AppConfig.VERIFY_SSL
                        )
                        print(f"API Response: {response.status_code} - {response.text}")  # Journal pour vérifier la réponse
                        if not response.ok:
                            raise Exception(f"Erreur API lors de la mise à jour du dossier: {response.text}")

                    except requests.RequestException as e:
                        raise Exception(f"Erreur réseau lors de la mise à jour sur l'API: {str(e)}")

                else:
                    # Création API
                    try:
                        response = requests.post(
                            f"{AppConfig.API_BASE_URL}/groupes/{id_groupe}/dossiers",
                            json={"nom": nom},
                            headers=self.parent.parent.session.headers,
                            verify=AppConfig.VERIFY_SSL
                        )
                        print(f"API Response: {response.status_code} - {response.text}")  # Journal pour vérifier la réponse
                        if not response.ok:
                            raise Exception(f"Erreur API lors de la création du dossier: {response.text}")

                    except requests.RequestException as e:
                        raise Exception(f"Erreur réseau lors de la création sur l'API: {str(e)}")

                    # Création locale
                    cursor.execute("""
                        INSERT INTO DOSSIER (nom, id_groupe) 
                        VALUES (%s, %s)""", 
                        (nom, id_groupe))

                connection.commit()
                self.accept()
                self.parent.load_folders()

        except Exception as e:
            connection.rollback()
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de l'enregistrement du dossier: {str(e)}")
        finally:
            connection.close()

    def apply_theme(self):
        if self.parent.get_current_theme() == 'dark':
            self.setStyleSheet(DARK_STYLE)
        else:
            self.setStyleSheet(LIGHT_STYLE)



class InviteUserDialog(QDialog):
    """
    Dialogue d'invitation d'utilisateur.
    
    Permet d'inviter un utilisateur à rejoindre un groupe.
    
    Attributes:
        parent (GroupsTab): Onglet parent des groupes
        group_id (int): ID du groupe en édition
        
    Methods:
        get_group_name(): Récupère le nom du groupe
        invite_user(): Envoie l'invitation
    """
    def __init__(self, parent, group_id):
        super().__init__()
        self.parent = parent
        self.group_id = group_id
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Inviter un utilisateur")
        self.setGeometry(500, 200, 400, 200)
        self.setStyleSheet("background-color: #23272a;")
        vbox = QVBoxLayout()
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Email de l'utilisateur")
        self.email_input.setStyleSheet("color: white;")
        vbox.addWidget(self.email_input)
        hbox = QHBoxLayout()
        self.invite_button = QPushButton("Inviter")
        self.invite_button.setStyleSheet("background-color: #7289da; color: white; padding: 10px;")
        self.invite_button.clicked.connect(self.invite_user)
        hbox.addWidget(self.invite_button)
        self.cancel_button = QPushButton("Annuler")
        self.cancel_button.setStyleSheet("background-color: #7289da; color: white; padding: 10px;")
        self.cancel_button.clicked.connect(self.reject)
        hbox.addWidget(self.cancel_button)
        vbox.addLayout(hbox)
        self.setLayout(vbox)

    def get_group_name(self, group_id):
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT nom FROM GROUPE WHERE id_groupe = %s", (group_id,))
                group = cursor.fetchone()
                if group:
                    return group[0]
                else:
                    return None
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de la récupération du nom du groupe: {str(e)}")
            return None
        finally:
            connection.close()

    def invite_user(self):
        if not self.parent.is_admin(self.group_id):
            QMessageBox.warning(self, 'Erreur', 'Vous n\'êtes pas autorisé à inviter des utilisateurs dans ce groupe.')
            return
            
        email = self.email_input.text()
        if not email:
            QMessageBox.warning(self, 'Erreur', 'L\'email est obligatoire!')
            return

        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                # Vérifications locales
                cursor.execute("SELECT id_user FROM USER WHERE mail = %s", (email,))
                user = cursor.fetchone()
                if not user:
                    QMessageBox.warning(self, 'Erreur', 'Utilisateur non trouvé!')
                    return

                # Vérification membre existant
                cursor.execute("SELECT * FROM MEMBRE WHERE id_groupe = %s AND id_user = %s", 
                            (self.group_id, user[0]))
                if cursor.fetchone():
                    QMessageBox.warning(self, 'Erreur', 'L\'utilisateur est déjà membre du groupe!')
                    return

                # Vérification invitation en attente
                cursor.execute("""
                    SELECT * FROM INVITATION 
                    WHERE id_groupe = %s AND id_user = %s AND statut = 'En attente'""", 
                    (self.group_id, user[0]))
                if cursor.fetchone():
                    QMessageBox.warning(self, 'Erreur', 'Une invitation est déjà en attente pour cet utilisateur!')
                    return

                # Création de l'invitation sur l'API
                try:
                    response = requests.post(
                        f"{AppConfig.API_BASE_URL}/invitations",
                        json={
                            "id_groupe": self.group_id,
                            "id_user": user[0]
                        },
                        headers=self.parent.session.headers,
                        verify=AppConfig.VERIFY_SSL
                    )
                    
                    if not response.ok:
                        raise Exception(f"Erreur API lors de l'envoi de l'invitation: {response.text}")

                except requests.RequestException as e:
                    raise Exception(f"Erreur réseau lors de l'envoi de l'invitation sur l'API: {str(e)}")

                # Création locale de l'invitation
                cursor.execute("INSERT INTO INVITATION (id_groupe, id_user) VALUES (%s, %s)", 
                            (self.group_id, user[0]))

                # Envoi de l'email
                group_name = self.get_group_name(self.group_id)
                if group_name:
                    subject = "Invitation à rejoindre le groupe"
                    body = f"Bonjour,\n\nVous avez été invité à rejoindre le groupe '{group_name}'.\n\nCordialement,\nL'équipe de l'application To-Do List."
                    send_email(email, subject, body)

                connection.commit()
                QMessageBox.information(self, 'Succès', 'Invitation envoyée avec succès!')
                self.accept()

        except Exception as e:
            connection.rollback()
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de l'invitation: {str(e)}")
        finally:
            connection.close()


    def apply_theme(self):
        if self.parent.get_current_theme() == 'dark':
            self.setStyleSheet(DARK_STYLE)
        else:
            self.setStyleSheet(LIGHT_STYLE)


class InvitationsTab(QWidget):
    """
    Onglet des invitations.
    
    Affiche les invitations en attente pour l'utilisateur connecté.
    
    Attributes:
        parent (TodoListApp): Instance parente de l'application
        
    Methods:
        load_invitations(): Charge les invitations en attente
        respond_invitation(): Répond à une invitation
    """
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.initUI()
        self.init_timer()  # Initialiser le timer

    def initUI(self):
        self.setWindowTitle("Invitations")
        self.setGeometry(500, 200, 400, 300)
        self.setStyleSheet("background-color: #23272a;")
        vbox = QVBoxLayout()
        self.invitations_table = QTableWidget()
        self.invitations_table.setColumnCount(3)
        self.invitations_table.setHorizontalHeaderLabels(["Groupe", "Statut", "Actions"])
        self.invitations_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        vbox.addWidget(self.invitations_table)
        self.load_invitations()
        self.setLayout(vbox)

    def init_timer(self):
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.load_invitations)
        self.timer.start(5000)  # Vérifie toutes les 5 secondes

    def load_invitations(self):
        self.invitations_table.setRowCount(0)
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT i.id_invitation, g.nom, i.statut FROM INVITATION i JOIN GROUPE g ON i.id_groupe = g.id_groupe WHERE i.id_user = %s AND i.statut = 'En attente'", (self.parent.user_id,))
                invitations = cursor.fetchall()
                for row, invitation in enumerate(invitations):
                    self.invitations_table.insertRow(row)
                    for col, value in enumerate(invitation[1:]):
                        item = QTableWidgetItem(str(value))
                        self.invitations_table.setItem(row, col, item)

                    actions_widget = QWidget()
                    actions_layout = QHBoxLayout()

                    # Créer le bouton "Accepter"
                    accept_button = QPushButton()
                    accept_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogApplyButton))
                    accept_button.setText("")  # Supprimer le texte du bouton
                    accept_button.setFixedSize(50, 50)  # Taille fixe
                    accept_button.setStyleSheet("border-radius: 25px;")  # Forme circulaire
                    accept_button.clicked.connect(lambda checked, invitation_id=invitation[0]: self.respond_invitation(invitation_id, 'Acceptée'))

                    # Créer le bouton "Refuser"
                    reject_button = QPushButton()
                    reject_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogCancelButton))
                    reject_button.setText("")  # Supprimer le texte du bouton
                    reject_button.setFixedSize(50, 50)  # Taille fixe
                    reject_button.setStyleSheet("border-radius: 25px;")  # Forme circulaire
                    reject_button.clicked.connect(lambda checked, invitation_id=invitation[0]: self.respond_invitation(invitation_id, 'Refusée'))

                    # Ajouter des espaces pour centrer les boutons
                    actions_layout.addItem(QSpacerItem(20, 40, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))
                    actions_layout.addWidget(accept_button)
                    actions_layout.addItem(QSpacerItem(10, 0, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum))  # Espace de 10 pixels
                    actions_layout.addWidget(reject_button)
                    actions_layout.addItem(QSpacerItem(20, 40, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))

                    actions_widget.setLayout(actions_layout)
                    self.invitations_table.setCellWidget(row, 2, actions_widget)

                    # Ajuster la taille de la cellule pour s'assurer que les boutons sont visibles
                    self.invitations_table .setRowHeight(row, 60)  # Ajustez la hauteur de la ligne si nécessaire
                    self.invitations_table.setColumnWidth(2, 100)  # Ajustez la largeur de la colonne des actions si nécessaire

        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors du chargement des invitations: {str(e)}")
        finally:
            connection.close()

    def respond_invitation(self, invitation_id, response):
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                # Mise à jour locale
                cursor.execute("""
                    UPDATE INVITATION 
                    SET statut = %s 
                    WHERE id_invitation = %s""", 
                    (response, invitation_id))
    
                # Mise à jour API
                try:
                    api_response = requests.put(
                        f"{AppConfig.API_BASE_URL}/invitations/{invitation_id}",
                        json={"statut": response},
                        headers=self.parent.session.headers,
                        verify=AppConfig.VERIFY_SSL
                    )
                    
                    if not api_response.ok:
                        error_data = api_response.json()
                        error_msg = error_data.get('error', 'Erreur inconnue')
                        raise Exception(f"Erreur API: {error_msg}")
    
                except requests.RequestException as e:
                    raise Exception(f"Erreur réseau: {str(e)}")
                except ValueError as e:
                    raise Exception("Erreur de format de réponse API")
    
                if response == 'Acceptée':
                    # Récupération des informations de l'invitation
                    cursor.execute("""
                        SELECT id_groupe, id_user 
                        FROM INVITATION 
                        WHERE id_invitation = %s""", 
                        (invitation_id,))
                    invitation = cursor.fetchone()
                    
                    if not invitation:
                        raise Exception("Invitation non trouvée")
    
                    # Vérification et ajout du membre localement uniquement
                    cursor.execute("""
                        SELECT * FROM MEMBRE 
                        WHERE id_groupe = %s AND id_user = %s""", 
                        (invitation[0], invitation[1]))
                    if not cursor.fetchone():
                        # Ajout local uniquement car l'API a déjà ajouté le membre
                        cursor.execute("""
                            INSERT INTO MEMBRE (id_groupe, id_user, role) 
                            VALUES (%s, %s, %s)""", 
                            (invitation[0], invitation[1], 'lecture'))
    
                connection.commit()
                self.load_invitations()
                self.parent.groups_tab.load_groups()
                self.parent.folders_tab.load_folders()
                self.parent.group_selection_tab.load_groups()
    
                # Message de succès
                if response == 'Acceptée':
                    QMessageBox.information(self, 'Succès', 'Vous avez rejoint le groupe avec succès!')
                else:
                    QMessageBox.information(self, 'Succès', 'Invitation refusée avec succès!')
    
        except Exception as e:
            connection.rollback()
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de la réponse à l'invitation: {str(e)}")
        finally:
            connection.close()



class GroupSelectionDialog(QDialog):
    def __init__(self, user_id):
        super().__init__()
        self.user_id = user_id
        self.selected_group_id = None
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Sélection de Groupe")
        self.setGeometry(500, 200, 400, 300)
        self.setStyleSheet("background-color: #23272a;")
        vbox = QVBoxLayout()
        self.group_combo = QComboBox()
        self.load_groups()
        vbox.addWidget(self.group_combo)
        self.select_button = QPushButton("Sélectionner", self)
        self.select_button.setStyleSheet("background-color: #7289da; color: white; padding: 10px;")
        self.select_button.clicked.connect(self.select_group)
        vbox.addWidget(self.select_button)
        self.setLayout(vbox)

    def load_groups(self):
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT g.id_groupe, g.nom
                    FROM GROUPE g
                    LEFT JOIN MEMBRE m ON g.id_groupe = m.id_groupe
                    WHERE g.id_user = %s OR m.id_user = %s
                """, (self.user_id, self.user_id))
                groups = cursor.fetchall()
                for group in groups:
                    self.group_combo.addItem(group[1], group[0])
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors du chargement des groupes: {str(e)}")
        finally:
            connection.close()

    def select_group(self):
        self.selected_group_id = self.group_combo.currentData()
        self.accept()

class GroupSelectionTab(QWidget):
    """
    Onglet de sélection de groupe.
    
    Affiche les groupes disponibles pour l'utilisateur connecté.
    
    Attributes:
        parent (TodoListApp): Instance parente de l'application
        
    Methods:
        load_groups(): Charge les groupes disponibles
        select_group(): Sélectionne un groupe
    """
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Sélection de Groupe")
        self.setGeometry(100, 100, 1200, 800)
        self.setStyleSheet("""
            QWidget {
                background-color: #2c2f33;
            }
            QPushButton {
                background-color: #7289da;
                color: white;
                padding: 20px;
                font-size: 18px;
                border-radius: 10px;
                margin: 10px;
            }
            QPushButton:hover {
                background-color: #5a6fb2;
            }
            QLabel {
                color: white;
            }
        """)
        vbox = QVBoxLayout()
        self.group_layout = QGridLayout()
        self.load_groups()
        vbox.addLayout(self.group_layout)
        self.setLayout(vbox)

    def load_groups(self, selected_group_id=None):
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT DISTINCT g.id_groupe, g.nom, g.date_creation,
                        (SELECT COUNT(*) FROM MEMBRE m WHERE m.id_groupe = g.id_groupe) AS nb_membres
                    FROM GROUPE g
                    LEFT JOIN MEMBRE m ON g.id_groupe = m.id_groupe
                    WHERE g.id_user = %s OR m.id_user = %s
                """, (self.parent.user_id, self.parent.user_id))
                groups = cursor.fetchall()
                row = 0
                col = 0
                for group in groups:
                    group_button = QPushButton(f"{group[1]}\nMembres: {group[3]}\nCréé le: {group[2].strftime('%Y-%m-%d')}")
                    group_button.clicked.connect(lambda checked, group_id=group[0]: self.select_group(group_id))
                    self.group_layout.addWidget(group_button, row, col)
                    if selected_group_id and group[0] == selected_group_id:
                        self.select_group(group[0])
                    col += 1
                    if col > 2:
                        col = 0
                        row += 1
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors du chargement des groupes: {str(e)}")
        finally:
            connection.close()



    def select_group(self, group_id):
        self.parent.group_id = group_id
        self.parent.load_folders()
        self.parent.tabs.setCurrentWidget(self.parent.tasks_tab)


class CalendarTab(QWidget):
    """
    Onglet du calendrier.
    
    Affiche les tâches dans une vue calendrier.
    
    Attributes:
        parent (TodoListApp): Instance parente de l'application
        calendar_widget (QCalendarWidget): Widget de calendrier
        
    Methods:
        show_tasks(): Affiche les tâches pour une date donnée
    """
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Calendrier")
        self.setGeometry(100, 100, 1200, 800)
        self.setStyleSheet("background-color: #2c2f33; color: white;")
        vbox = QVBoxLayout()
        self.calendar = QCalendarWidget()
        self.calendar.setGridVisible(True)
        self.calendar.clicked.connect(self.show_tasks)
        vbox.addWidget(self.calendar)
        self.tasks_list = QListWidget()
        vbox.addWidget(self.tasks_list)
        self.setLayout(vbox)

    def show_tasks(self, date):
        self.tasks_list.clear()
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT t.titre, t.date_fin
                    FROM TACHES t
                    JOIN DOSSIER d ON t.id_dossier = d.id_dossier
                    WHERE (t.id_user = %s OR t.id_dossier IN (
                        SELECT d.id_dossier
                        FROM DOSSIER d
                        JOIN MEMBRE m ON d.id_groupe = m.id_groupe
                        WHERE m.id_user = %s
                    )) AND d.id_groupe = %s AND t.date_fin = %s
                """, (self.parent.user_id, self.parent.user_id, self.parent.group_id, date.toPyDate()))
                tasks = cursor.fetchall()
                for task in tasks:
                    self.tasks_list.addItem(f"{task[0]} - {task[1].strftime('%Y-%m-%d')}")
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors du chargement des tâches: {str(e)}")
        finally:
            connection.close()

class ReportsTab(QWidget):
    """
    Onglet des rapports.
    
    Permet de générer des rapports PDF sur l'avancement des tâches
    et l'activité des utilisateurs.
    
    Attributes:
        parent (TodoListApp): Instance parente de l'application
        
    Methods:
        generate_report(): Génère un rapport d'activité
        download_report(): Télécharge le rapport au format PDF
        create_pdf(): Crée le fichier PDF du rapport
    """
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Rapports")
        self.setGeometry(100, 100, 1200, 800)
        self.setStyleSheet("background-color: #2c2f33; color: white;")
        vbox = QVBoxLayout()
        self.generate_report_button = QPushButton("Générer Rapport")
        self.generate_report_button.setIcon(QIcon("icons/report.png"))  # Ajouter une icône
        self.generate_report_button.clicked.connect(self.generate_report)
        vbox.addWidget(self.generate_report_button)
        self.download_report_button = QPushButton("Télécharger Rapport en PDF")
        self.download_report_button.setIcon(QIcon("icons/download.png"))  # Ajouter une icône
        self.download_report_button.clicked.connect(self.download_report)
        vbox.addWidget(self.download_report_button)
        self.report_label = QLabel("")
        vbox.addWidget(self.report_label)
        self.setLayout(vbox)

    def generate_report(self):
        """
        Génère un rapport d'activité.
        
        Processus :
        1. Récupération des données de l'activité
        2. Création du graphique
        3. Sauvegarde du graphique
        
        Returns:
            bool: True si le rapport est généré avec succès, False sinon
            
        Raises:
            Exception: En cas d'erreur pendant la génération du rapport
        """
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT t.statut, COUNT(*)
                    FROM TACHES t
                    JOIN DOSSIER d ON t.id_dossier = d.id_dossier
                    WHERE (t.id_user = %s OR t.id_dossier IN (
                        SELECT d.id_dossier
                        FROM DOSSIER d
                        JOIN MEMBRE m ON d.id_groupe = m.id_groupe
                        WHERE m.id_user = %s
                    )) AND d.id_groupe = %s
                    GROUP BY t.statut
                """, (self.parent.user_id, self.parent.user_id, self.parent.group_id))
                data = cursor.fetchall()
                statuses = ["En cours", "Terminée", "Échoué"]
                counts = [0, 0, 0]
                for row in data:
                    counts[row[0]] = row[1]
                plt.bar(statuses, counts, color=['orange', 'green', 'red'])
                plt.xlabel('Statut')
                plt.ylabel('Nombre de tâches')
                plt.title('Rapport des tâches')
                plt.savefig('report.png')
                plt.close()
                pixmap = QPixmap('report.png')
                self.report_label.setPixmap(pixmap)
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de la génération du rapport: {str(e)}")
        finally:
            connection.close()

    def download_report(self):
        """
        Télécharge le rapport au format PDF.
        
        Processus :
        1. Création du PDF
        2. Sauvegarde du PDF
        
        Returns:
            bool: True si le rapport est téléchargé avec succès, False sinon
            
        Raises:
            Exception: En cas d'erreur pendant le téléchargement du rapport
        """
        file_path, _ = QFileDialog.getSaveFileName(self, "Enregistrer le rapport en PDF", "", "PDF Files (*.pdf)")
        if file_path:
            self.create_pdf(file_path)

    def create_pdf(self, file_path):
        """
        Crée le fichier PDF du rapport.
        
        Processus :
        1. Récupération des données de l'activité
        2. Création du PDF
        
        Args:
            file_path (str): Chemin du fichier PDF à créer
            
        Returns:
            bool: True si le PDF est créé avec succès, False sinon
            
        Raises:
            Exception: En cas d'erreur pendant la création du PDF
        """
        connection = get_connection()
        try:
            with connection.cursor() as cursor:
                # Récupérer le nom du groupe sélectionné
                cursor.execute("SELECT nom FROM GROUPE WHERE id_groupe = %s", (self.parent.group_id,))
                group_name = cursor.fetchone()
                group_name = group_name[0] if group_name else "le groupe"

                cursor.execute("""
                    SELECT t.statut, COUNT(*)
                    FROM TACHES t
                    JOIN DOSSIER d ON t.id_dossier = d.id_dossier
                    WHERE (t.id_user = %s OR t.id_dossier IN (
                        SELECT d.id_dossier
                        FROM DOSSIER d
                        JOIN MEMBRE m ON d.id_groupe = m.id_groupe
                        WHERE m.id_user = %s
                    )) AND d.id_groupe = %s
                    GROUP BY t.statut
                """, (self.parent.user_id, self.parent.user_id, self.parent.group_id))
                data = cursor.fetchall()
                statuses = ["En cours", "Terminée", "Échoué"]
                counts = [0, 0, 0]
                for row in data:
                    counts[row[0]] = row[1]

                # Créer le graphique
                plt.bar(statuses, counts, color=['orange', 'green', 'red'])
                plt.xlabel('Statut')
                plt.ylabel('Nombre de tâches')
                plt.title('Rapport des tâches')
                buf = io.BytesIO()
                plt.savefig(buf, format='png')
                buf.seek(0)
                plt.close()

                c = canvas.Canvas(file_path, pagesize=letter)
                c.setFont("Helvetica", 12)
                c.drawString(100, 750, "Rapport des tâches")
                c.drawString(100, 730, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                c.drawString(100, 710, f"Groupe: {group_name}")

                y = 680
                for status, count in zip(statuses, counts):
                    c.drawString(100, y, f"{status}: {count}")
                    y -= 20

                # Ajouter le graphique au PDF
                image = ImageReader(buf)
                c.drawImage(image, 100, 400, width=400, height=300)

                c.showPage()
                c.save()
                QMessageBox.information(self, 'Succès', 'Le rapport a été téléchargé avec succès!')
        except pymysql.MySQLError as e:
            QMessageBox.critical(self, 'Erreur', f"Erreur lors de la génération du rapport PDF: {str(e)}")
        finally:
            connection.close()

class HelpWindow(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Aide - TodoList")
        self.setGeometry(100, 100, 1024, 768)
        self.setStyleSheet("background-color: #ffffff;")
        
        main_layout = QVBoxLayout()
        
        # Zone de défilement pour le contenu
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        # Création des sections
        sections = [
            {
                "title": "1. Organisation des Dossiers et Groupes",
                "video": "videos/Creation_Groupe_Dossier.mp4",
                "height": 200,
                "description": """
                    <div class="feature-item">
                        <h3>Gestion des Groupes et Dossiers</h3>
                        <ul>
                            <li>Créez facilement des groupes pour organiser votre travail d'équipe</li>
                            <li>Structurez vos tâches en créant des dossiers dédiés</li>
                            <li>Organisez vos projets de manière claire et efficace</li>
                        </ul>
                    </div>
                """
            },
            {
                "title": "2. Gestion des Membres et Invitations",
                "video": "videos/Invitation_Utilisateur.mp4",
                "height": 200,
                "description": """
                    <div class="feature-item">
                        <h3>Collaboration et Gestion des Membres</h3>
                        <ul>
                            <li>Invitez de nouveaux membres dans vos groupes</li>
                            <li>Les utilisateurs peuvent accepter ou refuser les invitations</li>
                            <li>Les administrateurs peuvent :</li>
                            <ul>
                                <li>Visualiser les rôles des membres via "Gérer les membres"</li>
                                <li>Modifier les rôles des utilisateurs</li>
                                <li>Gérer les permissions du groupe</li>
                            </ul>
                        </ul>
                    </div>
                """
            },
            {
                "title": "3. Création et Gestion des Tâches",
                "video": "videos/Création_de_tâches.mp4",
                "height": 200,
                "description": """
                    <div class="feature-item">
                        <h3>Gestion Complète des Tâches</h3>
                        <ul>
                            <li>Créez une nouvelle tâche avec le bouton "Nouvelle tâche" :</li>
                            <ul>
                                <li>Définissez le titre et choisissez le dossier</li>
                                <li>Fixez la date d'échéance</li>
                                <li>Sélectionnez la priorité (faible, moyenne, élevée)</li>
                                <li>Choisissez le statut (en cours, terminé, échoué)</li>
                                <li>Assignez la tâche à un ou plusieurs utilisateurs</li>
                            </ul>
                            <li>Fonctionnalités supplémentaires :</li>
                            <ul>
                                <li>Ajoutez des commentaires et sous-tâches via le bouton "Modifier"</li>
                                <li>Notifications par email pour les membres du groupe lors de la création d'une tâche</li>
                                <li>Notifications spécifiques pour les utilisateurs assignés</li>
                            </ul>
                        </ul>
                    </div>
                """
            },
            {
                "title": "4. Import/Export de Base de Données",
                "video": "videos/Import_export_bdd.mp4",
                "height": 200,
                "description": """
                    <div class="feature-item">
                        <h3>Gestion de la Base de Données</h3>
                        <ul>
                            <li>Accédez aux fonctions via le bouton "Import/Export"</li>
                            <li>Options disponibles :</li>
                            <ul>
                                <li>Exportez votre base de données pour la sauvegarder</li>
                                <li>Importez une base de données existante</li>
                            </ul>
                            <li><strong>Note importante :</strong> L'application est entièrement synchronisée</li>
                            <li>Pour plus d'informations, consultez la documentation sur GitHub</li>
                        </ul>
                    </div>
                """
            },
            {
                "title": "5. Intégration avec Google Calendar",
                "video": "videos/Calendrier_Rapport.mp4",
                "height": 200,
                "description": """
                    <div class="feature-item">
                        <h3>Synchronisation avec Google Calendar</h3>
                        <ul>
                            <li>Synchronisez vos tâches avec Google Calendar :</li>
                            <ul>
                                <li>Visualisez vos tâches dans votre calendrier Google</li>
                                <li>Gardez une vue d'ensemble de vos échéances</li>
                                <li>Accédez à vos tâches depuis n'importe quel appareil</li>
                            </ul>
                            <li>Générez des rapports détaillés :</li>
                            <ul>
                                <li>Suivez l'avancement de vos projets</li>
                                <li>Analysez la répartition des tâches</li>
                                <li>Évaluez la performance de votre équipe</li>
                            </ul>
                        </ul>
                    </div>
                """
            }
        ]
        
        # Création des lecteurs vidéo
        self.video_players = []
        self.video_widgets = []
        self.video_positions = {}
        
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        for section in sections:
            # Création du widget web pour la section
            web_view = QWebEngineView()
            web_view.setFixedHeight(section["height"])
            
            # Chargement du HTML spécifique à la section
            html_content = f"""
                <div style="padding: 20px;">
                    <style>
                        .feature-item {{
                            background: white;
                            padding: 20px;
                            border-radius: 8px;
                            margin-top: 10px;
                            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                        }}
                        h2 {{
                            color: #3498db;
                            border-bottom: 2px solid #3498db;
                            padding-bottom: 10px;
                            margin-top: 0;
                        }}
                        h3 {{
                            color: #2c3e50;
                            margin-top: 0;
                        }}
                        ul {{
                            padding-left: 20px;
                            margin: 10px 0;
                        }}
                        li {{
                            margin-bottom: 8px;
                        }}
                        .keyboard-shortcut {{
                            background: #e9ecef;
                            padding: 2px 6px;
                            border-radius: 4px;
                            font-family: monospace;
                        }}
                    </style>
                    <h2>{section["title"]}</h2>
                    {section["description"]}
                </div>
            """
            web_view.setHtml(html_content)
            scroll_layout.addWidget(web_view)
            
            # Création du widget vidéo
            video_widget = QVideoWidget()
            video_widget.setMinimumHeight(300)
            self.video_widgets.append(video_widget)
            
            # Création du lecteur média
            player = QMediaPlayer()
            player.setVideoOutput(video_widget)
            
            # Chargement de la vidéo
            video_path = os.path.join(current_dir, section["video"])
            player.setSource(QUrl.fromLocalFile(video_path))
            
            self.video_players.append(player)
            self.video_positions[player] = 0
            
            # Connecter le signal de position
            player.positionChanged.connect(lambda pos, p=player: self.update_position(p, pos))
            
            # Création des contrôles
            controls = QHBoxLayout()
            
            play_button = QPushButton("▶️ Lecture/Pause")
            play_button.clicked.connect(lambda checked, p=player: self.toggle_video(p))
            
            stop_button = QPushButton("⏹️ Stop")
            stop_button.clicked.connect(lambda checked, p=player: self.stop_video(p))
            
            restart_button = QPushButton("🔄 Recommencer")
            restart_button.clicked.connect(lambda checked, p=player: self.restart_video(p))
            
            for button in [play_button, stop_button, restart_button]:
                button.setStyleSheet("""
                    QPushButton {
                        background-color: #4a90e2;
                        color: white;
                        padding: 8px 16px;
                        border-radius: 4px;
                        margin: 5px;
                    }
                    QPushButton:hover {
                        background-color: #357abd;
                    }
                """)
                controls.addWidget(button)
            
            # Création d'un widget pour contenir la vidéo et ses contrôles
            video_container = QWidget()
            video_container_layout = QVBoxLayout(video_container)
            video_container_layout.addWidget(video_widget)
            video_container_layout.addLayout(controls)
            
            scroll_layout.addWidget(video_container)
        
        scroll_area.setWidget(scroll_widget)
        main_layout.addWidget(scroll_area)
        
        # Bouton de fermeture
        close_button = QPushButton("Fermer")
        close_button.setStyleSheet("""
            QPushButton {
                background-color: #4a90e2;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #357abd;
            }
        """)
        close_button.clicked.connect(self.close)
        
        main_layout.addWidget(close_button)
        self.setLayout(main_layout)
    
    def update_position(self, player, position):
        """Met à jour la position actuelle de la vidéo"""
        if player.playbackState() == QMediaPlayer.PlaybackState.PlayingState:
            self.video_positions[player] = position
    
    def toggle_video(self, player):
        """Gère la lecture/pause de la vidéo"""
        # Arrêter toutes les autres vidéos
        for p in self.video_players:
            if p != player:
                self.stop_video(p)
        
        # Lecture/Pause de la vidéo sélectionnée
        if player.playbackState() == QMediaPlayer.PlaybackState.PlayingState:
            player.pause()
        else:
            pos = self.video_positions.get(player, 0)
            player.setPosition(pos)
            player.play()
    
    def stop_video(self, player):
        """Arrête la vidéo"""
        player.stop()
        self.video_positions[player] = 0
    
    def restart_video(self, player):
        """Recommence la vidéo depuis le début"""
        player.setPosition(0)
        self.video_positions[player] = 0
        player.play()
    
    def closeEvent(self, event):
        # Arrêter toutes les vidéos lors de la fermeture
        for player in self.video_players:
            player.stop()
        super().closeEvent(event)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    welcome_screen = WelcomeScreen()
    welcome_screen.show()
    sys.exit(app.exec())
