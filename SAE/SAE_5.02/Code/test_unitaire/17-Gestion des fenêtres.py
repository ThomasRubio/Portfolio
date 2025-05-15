import unittest
from PyQt6.QtWidgets import QApplication
from Application import WelcomeScreen, LoginWindow, SignupWindow, TodoListApp

class TestWindowManagement(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication([])

    def test_welcome_screen(self):
        welcome_screen = WelcomeScreen()
        self.assertEqual(welcome_screen.windowTitle(), "To-Do List App")

    def test_login_window(self):
        login_window = LoginWindow()
        self.assertEqual(login_window.windowTitle(), "Connexion")

    def test_signup_window(self):
        signup_window = SignupWindow()
        self.assertEqual(signup_window.windowTitle(), "Inscription")

    def test_todolist_app(self):
        todolist_app = TodoListApp(1, "testuser")
        self.assertEqual(todolist_app.windowTitle(), "To-Do List")

if __name__ == '__main__':
    unittest.main()
