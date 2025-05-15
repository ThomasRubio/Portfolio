import unittest
from unittest.mock import patch, MagicMock
from PyQt6.QtWidgets import QApplication
from Application import ManageMembersDialog

class TestMemberManagement(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication([])

    @patch('Application_UPDATE.get_connection')
    def test_update_role(self, mock_get_connection):
        mock_connection = mock_get_connection.return_value
        mock_cursor = mock_connection.cursor.return_value.__enter__.return_value
        mock_cursor.fetchone.return_value = ("admin",)  # Simuler le retour de fetchone pour le rôle
        parent = MagicMock()
        parent.user_id = 1
        manage_members_dialog = ManageMembersDialog(parent, 1)
        manage_members_dialog.update_role(1, "admin")
        mock_cursor.execute.assert_called()

    @patch('Application_UPDATE.get_connection')
    def test_remove_member(self, mock_get_connection):
        mock_connection = mock_get_connection.return_value
        mock_cursor = mock_connection.cursor.return_value.__enter__.return_value
        mock_cursor.fetchone.return_value = ("admin",)  # Simuler le retour de fetchone pour le rôle
        parent = MagicMock()
        parent.user_id = 1
        manage_members_dialog = ManageMembersDialog(parent, 1)
        manage_members_dialog.remove_member(1)
        mock_cursor.execute.assert_called()

if __name__ == '__main__':
    unittest.main()
