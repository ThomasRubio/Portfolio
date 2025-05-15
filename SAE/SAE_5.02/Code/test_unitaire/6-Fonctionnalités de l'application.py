import unittest
from unittest.mock import patch, MagicMock
from PyQt6.QtWidgets import QApplication, QWidget
from Application import ReportsTab

class FakeParent(QWidget):
    def __init__(self):
        super().__init__()
        self.user_id = 1
        self.group_id = 1

class TestAppFeatures(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication([])

    @patch('Application_UPDATE.get_connection')
    def test_generate_report(self, mock_get_connection):
        mock_connection = mock_get_connection.return_value
        mock_cursor = mock_connection.cursor.return_value.__enter__.return_value
        mock_cursor.fetchall.return_value = [(0, 5), (1, 3), (2, 2)]  # Exemple de données de retour
        parent = FakeParent()
        reports_tab = ReportsTab(parent)
        reports_tab.generate_report()
        mock_cursor.execute.assert_called()

    @patch('Application_UPDATE.get_connection')
    def test_download_report(self, mock_get_connection):
        mock_connection = mock_get_connection.return_value
        mock_cursor = mock_connection.cursor.return_value.__enter__.return_value
        mock_cursor.fetchone.return_value = ("Test Group",)  # Exemple de données de retour
        mock_cursor.fetchall.return_value = [(0, 5), (1, 3), (2, 2)]  # Exemple de données de retour
        parent = FakeParent()
        reports_tab = ReportsTab(parent)
        reports_tab.download_report()
        mock_cursor.execute.assert_called()

if __name__ == '__main__':
    unittest.main()
