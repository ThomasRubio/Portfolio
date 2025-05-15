import unittest
from unittest.mock import patch, MagicMock
from PyQt6.QtWidgets import QApplication
from Application import FolderDialog

class TestFolderManagement(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication([])

    @patch('Application_UPDATE.get_connection')
    def test_save_folder(self, mock_get_connection):
        mock_connection = mock_get_connection.return_value
        mock_cursor = mock_connection.cursor.return_value.__enter__.return_value
        mock_cursor.fetchone.return_value = ("admin",)  # Simuler le retour de fetchone pour le rôle
        parent = MagicMock()
        parent.group_id = 1
        parent.user_id = 1
        folder_dialog = FolderDialog(parent)
        folder_dialog.nom_input.setText("Test Folder")
        folder_dialog.save_folder()
        mock_cursor.execute.assert_called()

if __name__ == '__main__':
    unittest.main()
