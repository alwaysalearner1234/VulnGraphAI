import unittest
from fastapi.testclient import TestClient
from backend.main import app

class TestFrontendServe(unittest.TestCase):
    def test_serve_frontend(self):
        client = TestClient(app)
        # Using context manager to trigger startup lifespan events
        with client as c:
            response = c.get("/")
            self.assertEqual(response.status_code, 200)
            self.assertIn("text/html", response.headers["content-type"])
            self.assertIn("VulnGraph AI", response.text)

    def test_serve_assets(self):
        client = TestClient(app)
        with client as c:
            response = c.get("/app.css")
            self.assertEqual(response.status_code, 200)
            self.assertIn("text/css", response.headers["content-type"])

            response = c.get("/app.js")
            self.assertEqual(response.status_code, 200)
            self.assertIn("application/javascript", response.headers["content-type"])

if __name__ == "__main__":
    unittest.main()
