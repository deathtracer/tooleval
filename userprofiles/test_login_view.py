from unittest import TestCase
from django.test import Client

class TestLogin_view(TestCase):
    def test_login_view(self):
    	c = Client()
    	response = c.post('/login/',{'username':'root', 'password': 'hacker@123'})
    	self.assertEqual(response.status_code, 200)
