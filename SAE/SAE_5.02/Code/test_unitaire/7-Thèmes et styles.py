
import unittest
from PyQt6.QtWidgets import QApplication
from Application import TodoListApp, DARK_STYLE, LIGHT_STYLE

class TestThemesAndStyles(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication([])

    def test_apply_dark_theme(self):
        app = TodoListApp(1, "testuser")
        app.current_theme = 'dark'
        app.apply_theme()
        self.assertEqual(app.styleSheet(), DARK_STYLE)

    def test_apply_light_theme(self):
        app = TodoListApp(1, "testuser")
        app.current_theme = 'light'
        app.apply_theme()
        self.assertEqual(app.styleSheet(), LIGHT_STYLE)

if __name__ == '__main__':
    unittest.main()
