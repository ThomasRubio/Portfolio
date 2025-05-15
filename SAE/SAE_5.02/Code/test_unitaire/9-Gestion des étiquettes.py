import unittest
from unittest.mock import patch, MagicMock
from PyQt6.QtWidgets import QApplication
from Application import ManageLabelsDialog

class TestLabelManagement(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication([])

    @patch('Application_UPDATE.get_connection')
    def test_add_label(self, mock_get_connection):
        mock_connection = mock_get_connection.return_value
        mock_cursor = mock_connection.cursor.return_value.__enter__.return_value
        manage_labels_dialog = ManageLabelsDialog(None)
        manage_labels_dialog.label_input.setText("Test Label")
        manage_labels_dialog.add_label()
        mock_cursor.execute.assert_called()

    @patch('Application_UPDATE.get_connection')
    def test_edit_label(self, mock_get_connection):
        mock_connection = mock_get_connection.return_value
        mock_cursor = mock_connection.cursor.return_value.__enter__.return_value
        manage_labels_dialog = ManageLabelsDialog(None)
        manage_labels_dialog.label_input.setText("Updated Label")
        manage_labels_dialog.edit_label()
        mock_cursor.execute.assert_called()

    @patch('Application_UPDATE.get_connection')
    def test_delete_label(self, mock_get_connection):
        mock_connection = mock_get_connection.return_value
        mock_cursor = mock_connection.cursor.return_value.__enter__.return_value
        manage_labels_dialog = ManageLabelsDialog(None)
        manage_labels_dialog.delete_label()
        mock_cursor.execute.assert_called()

if __name__ == '__main__':
    unittest.main()
