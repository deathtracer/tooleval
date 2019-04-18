from unittest import TestCase
from django.test import Client

class TestIndex(TestCase):
    def test_index(self):
        c = Client()
        response = c.get('/')
        self.assertEqual(response.status_code, 200)
