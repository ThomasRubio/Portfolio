import unittest
from unittest.mock import patch, MagicMock
from PyQt6.QtWidgets import QApplication
from Application import SousTacheDialog

class TestSubtaskManagement(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication([])

    @patch('Application_UPDATE.get_connection')
    def test_add_subtask(self, mock_get_connection):
        mock_connection = mock_get_connection.return_value
        mock_cursor = mock_connection.cursor.return_value.__enter__.return_value
        subtask_dialog = SousTacheDialog(None, 1)
        subtask_dialog.titre_input.setText("Test Subtask")
        subtask_dialog.save_sous_tache()
        mock_cursor.execute.assert_called()

if __name__ == '__main__':
    unittest.main()
