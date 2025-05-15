import unittest
from unittest.mock import patch, MagicMock
from PyQt6.QtWidgets import QApplication
from Application import GroupSelectionDialog

class TestGroupSelection(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication([])

    @patch('Application_UPDATE.get_connection')
    def test_load_groups(self, mock_get_connection):
        mock_connection = mock_get_connection.return_value
        mock_cursor = mock_connection.cursor.return_value.__enter__.return_value
        group_selection_dialog = GroupSelectionDialog(1)
        group_selection_dialog.load_groups()
        mock_cursor.execute.assert_called()

if __name__ == '__main__':
    unittest.main()
