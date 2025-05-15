# Dans test_application_interactions.py

import unittest
from unittest.mock import patch, MagicMock
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QDate  # Importer QDate
from Application import get_connection, TaskDialog

class TestApplicationInteractions(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Initialize QApplication once for all tests
        cls.app = QApplication([])

    @patch('Application_UPDATE.get_connection')
    def test_save_task(self, mock_get_connection):
        mock_connection = MagicMock()
        mock_get_connection.return_value = mock_connection
        mock_cursor = mock_connection.cursor.return_value.__enter__.return_value

        # Simulate saving a task
        task_id = None  # Use None to simulate inserting a new task
        title = "Test Task"
        description = "This is a test task"
        priority = 1
        due_date = "2023-12-31"
        status = 0

        # Create an instance of TaskDialog with a mock parent
        parent = MagicMock()
        parent.group_id = 1  # Set a valid group_id
        parent.user_id = 1  # Set a valid user_id
        task_dialog = TaskDialog(parent)

        # Set the values in the dialog
        task_dialog.titre_input.setText(title)
        task_dialog.commentaire_input.setText(description)
        task_dialog.priorite_combo.setCurrentIndex(priority)
        task_dialog.date_fin_edit.setDate(QDate.fromString(due_date, "yyyy-MM-dd"))
        task_dialog.statut_combo.setCurrentIndex(status)
        task_dialog.dossier_combo.addItem("Test Folder", 1)
        task_dialog.dossier_combo.setCurrentIndex(0)

        # Call the save_task method
        task_dialog.save_task(task_id, title, description, priority, due_date, status)

        # Check if the correct SQL query was executed
        mock_cursor.execute.assert_any_call(
            "INSERT INTO TACHES (titre, id_dossier, priorite, date_fin, commentaire, statut) VALUES (%s, %s, %s, %s, %s, %s)",
            (title, 1, priority, due_date, description, status)
        )
        mock_connection.commit.assert_called_once()

if __name__ == '__main__':
    unittest.main()
