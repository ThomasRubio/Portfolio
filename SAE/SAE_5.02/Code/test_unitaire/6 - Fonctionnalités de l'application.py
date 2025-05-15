import unittest
from unittest.mock import patch, MagicMock
from PyQt6.QtWidgets import QApplication, QDialog
import sys
import os

# Importer les classes nécessaires de votre application
from Application import TodoListApp, ReportsTab, get_connection

class TestTodoListApp(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)

    def setUp(self):
        self.user_id = 1  # Utilisateur fictif pour les tests
        self.username = "testuser"
        self.main_window = TodoListApp(self.user_id, self.username)

    def test_generate_report(self):
        reports_tab = ReportsTab(self.main_window)
        with patch('Application_UPDATE.get_connection') as mock_get_connection:
            mock_connection = MagicMock()
            mock_cursor = MagicMock()
            mock_get_connection.return_value = mock_connection
            mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
            mock_cursor.fetchall.return_value = [(0, 5), (1, 3), (2, 2)]  # Données fictives

            reports_tab.generate_report()
            self.assertTrue(os.path.exists('report.png'))
            os.remove('report.png')

    def test_download_report(self):
        reports_tab = ReportsTab(self.main_window)
        with patch('Application_UPDATE.QFileDialog.getSaveFileName') as mock_getSaveFileName, \
             patch('Application_UPDATE.canvas.Canvas') as mock_Canvas, \
             patch('Application_UPDATE.canvas.pagesizes.letter', (612.0, 792.0)), \
             patch('Application_UPDATE.get_connection') as mock_get_connection:
            mock_getSaveFileName.return_value = ('test_report.pdf', 'pdf')
            mock_canvas_instance = mock_Canvas.return_value

            mock_connection = MagicMock()
            mock_cursor = MagicMock()
            mock_get_connection.return_value = mock_connection
            mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
            mock_cursor.fetchone.return_value = ["Test Group"]  # Simuler un nom de groupe valide
            mock_cursor.fetchall.return_value = [(0, 5), (1, 3), (2, 2)]  # Données fictives

            reports_tab.download_report()
            mock_Canvas.assert_called_once_with('test_report.pdf', pagesize=(612.0, 792.0))
            mock_canvas_instance.save.assert_called_once()
            if os.path.exists('test_report.pdf'):
                os.remove('test_report.pdf')

    def test_import_google_calendar(self):
        with patch('Application_UPDATE.ImportGoogleCalendar.exec') as mock_exec:
            mock_exec.return_value = QDialog.DialogCode.Accepted
            self.main_window.import_google()
            mock_exec.assert_called_once()

    def test_export_google_calendar(self):
        with patch('Application_UPDATE.ExportGoogleCalendar.exec') as mock_exec:
            mock_exec.return_value = QDialog.DialogCode.Accepted
            self.main_window.export_google()
            mock_exec.assert_called_once()

if __name__ == '__main__':
    unittest.main()
