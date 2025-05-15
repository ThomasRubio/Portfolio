
import unittest
from unittest.mock import patch, MagicMock
from Application import get_connection, send_email

class TestDatabaseInteractions(unittest.TestCase):

    @patch('Application_UPDATE.pymysql.connect')
    def test_get_connection(self, mock_connect):
        mock_connect.return_value = MagicMock()
        connection = get_connection()
        self.assertTrue(mock_connect.called)
        self.assertIsNotNone(connection)

    @patch('Application_UPDATE.smtplib.SMTP')
    def test_send_email(self, mock_smtp):
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server
        send_email("test@example.com", "Test Subject", "Test Body")
        mock_smtp.assert_called_with('smtp.gmail.com', 587)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("abdullahgozel68@gmail.com", "aykf wxfq xskb ouzs")
        mock_server.send_message.assert_called_once()

if __name__ == '__main__':
    unittest.main()
