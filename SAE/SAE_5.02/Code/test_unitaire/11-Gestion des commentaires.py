import unittest
from unittest.mock import patch, MagicMock
from PyQt6.QtWidgets import QApplication
from Application import InviteUserDialog

class TestInvitationManagement(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication([])

    @patch('Application_UPDATE.get_connection')
    def test_invite_user(self, mock_get_connection):
        mock_connection = mock_get_connection.return_value
        mock_cursor = mock_connection.cursor.return_value.__enter__.return_value
        # Simuler les retours de fetchone
        mock_cursor.fetchone.side_effect = [
            (1,),  # Retour pour vérifier si l'utilisateur existe
            None,  # Retour pour vérifier si l'utilisateur est déjà membre du groupe
            None,  # Retour pour vérifier si une invitation est déjà en attente
            ("Test Group",)  # Retour pour get_group_name
        ]
        parent = MagicMock()
        parent.is_admin.return_value = True
        invite_user_dialog = InviteUserDialog(parent, 1)
        invite_user_dialog.email_input.setText("test@example.com")
        invite_user_dialog.invite_user()
        mock_cursor.execute.assert_called()

if __name__ == '__main__':
    unittest.main()
