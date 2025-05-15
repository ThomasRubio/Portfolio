import unittest
from PyQt6.QtWidgets import QApplication
from Application import WelcomeScreen, LoginWindow, SignupWindow, TodoListApp

class TestUIComponents(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication([])

    def test_welcome_screen_init(self):
        welcome_screen = WelcomeScreen()
        self.assertEqual(welcome_screen.windowTitle(), "To-Do List App")
        self.assertEqual(welcome_screen.width(), 1280)
        self.assertEqual(welcome_screen.height(), 720)

    def test_login_window_init(self):
        login_window = LoginWindow()
        self.assertEqual(login_window.windowTitle(), "Connexion")
        self.assertEqual(login_window.width(), 400)
        self.assertEqual(login_window.height(), 300)

    def test_signup_window_init(self):
        signup_window = SignupWindow()
        self.assertEqual(signup_window.windowTitle(), "Inscription")
        self.assertEqual(signup_window.width(), 400)
        self.assertEqual(signup_window.height(), 600)

    def test_todo_list_app_init(self):
        todo_list_app = TodoListApp(user_id=1, username="testuser")
        self.assertEqual(todo_list_app.windowTitle(), "To-Do List")
        self.assertEqual(todo_list_app.width(), 1200)
        self.assertEqual(todo_list_app.height(), 800)

if __name__ == '__main__':
    unittest.main()
