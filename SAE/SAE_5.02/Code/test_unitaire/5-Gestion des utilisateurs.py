
import unittest
from unittest.mock import patch, MagicMock
from PyQt6.QtWidgets import QApplication
from Application import SignupWindow, LoginWindow
import bcrypt

class TestUserManagement(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication([])

    @patch('Application_UPDATE.get_connection')
    def test_user_signup(self, mock_get_connection):
        mock_connection = mock_get_connection.return_value
        mock_cursor = mock_connection.cursor.return_value.__enter__.return_value
        signup_window = SignupWindow()
        signup_window.nom_input.setText("Test")
        signup_window.prenom_input.setText("User")
        signup_window.username_input.setText("testuser")
        signup_window.email_input.setText("test@example.com")
        signup_window.password_input.setText("StrongPass1!")
        signup_window.signup()
        mock_cursor.execute.assert_called()

    @patch('Application_UPDATE.get_connection')
    def test_user_login(self, mock_get_connection):
        mock_connection = mock_get_connection.return_value
        mock_cursor = mock_connection.cursor.return_value.__enter__.return_value
        
        # Créer un mot de passe haché pour le test
        hashed_password = bcrypt.hashpw("StrongPass1!".encode('utf-8'), bcrypt.gensalt())
        
        # Configurer le mock pour retourner un utilisateur avec le mot de passe haché
        mock_cursor.fetchone.return_value = (1, "testuser", hashed_password.decode('utf-8'), "otp_secret", False)
        
        login_window = LoginWindow()
        login_window.email_input.setText("test@example.com")
        login_window.password_input.setText("StrongPass1!")
        login_window.login()
        mock_cursor.execute.assert_called()

if __name__ == '__main__':
    unittest.main()
