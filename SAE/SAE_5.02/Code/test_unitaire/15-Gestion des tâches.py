
import unittest
from unittest.mock import patch, MagicMock
from PyQt6.QtWidgets import QApplication
from Application import TaskDialog

class TestTaskManagement(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication([])

    @patch('Application_UPDATE.get_connection')
    def test_save_task(self, mock_get_connection):
        mock_connection = mock_get_connection.return_value
        mock_cursor = mock_connection.cursor.return_value.__enter__.return_value
        parent = MagicMock()
        parent.group_id = 1
        parent.user_id = 1
        task_dialog = TaskDialog(parent)
        task_dialog.titre_input.setText("Test Task")
        task_dialog.save_task()
        mock_cursor.execute.assert_called()

if __name__ == '__main__':
    unittest.main()
