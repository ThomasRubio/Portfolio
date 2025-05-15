import unittest
from Application import is_valid_email, evaluate_password_strength, get_priority_string, predict_priority

class TestUtilityFunctions(unittest.TestCase):

    def test_is_valid_email(self):
        self.assertTrue(is_valid_email("test@example.com"))
        self.assertTrue(is_valid_email("user.name@domain.fr"))
        self.assertFalse(is_valid_email("invalid-email"))
        self.assertFalse(is_valid_email("user@domain"))
        self.assertFalse(is_valid_email("user@domain.xyz"))

    def test_evaluate_password_strength(self):
        self.assertEqual(evaluate_password_strength("StrongPass1!"), ("Très fort", "green"))
        self.assertEqual(evaluate_password_strength("StrongPass1"), ("Fort", "blue"))
        self.assertEqual(evaluate_password_strength("StrongPass"), ("Moyen", "orange"))
        self.assertEqual(evaluate_password_strength("weak"), ("Faible", "red"))

    def test_get_priority_string(self):
        self.assertEqual(get_priority_string(0), "Faible")
        self.assertEqual(get_priority_string(1), "Moyenne")
        self.assertEqual(get_priority_string(2), "Élevée")
        self.assertEqual(get_priority_string(3), "Inconnue")
        self.assertEqual(get_priority_string(None), "Inconnue")

    def test_predict_priority(self):
        title = "Tâche urgente"
        description = "Doit être fait immédiatement"
        self.assertEqual(predict_priority(title, description), 2)

        title = "Tâche normale"
        description = "Peut attendre quelques jours"
        self.assertEqual(predict_priority(title, description), 1)

        title = "Tâche basse priorité"
        description = "Pas urgent"
        self.assertEqual(predict_priority(title, description), 0)

if __name__ == '__main__':
    unittest.main()
