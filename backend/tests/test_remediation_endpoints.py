import unittest
from fastapi.testclient import TestClient
from backend.main import app
from backend.models.database import SessionLocal, Finding

class TestRemediationAndConfigEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.client.__enter__()
        cls.db = SessionLocal()

    @classmethod
    def tearDownClass(cls):
        cls.db.close()
        cls.client.__exit__(None, None, None)

    def test_remediation_endpoint(self):
        # Fetch an active finding from DB
        finding = self.db.query(Finding).filter(Finding.status == "active").first()
        self.assertIsNotNone(finding, "Should have at least one active finding from seeded db")

        response = self.client.get(f"/api/remediation/{finding.id}")
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertEqual(data["finding_id"], finding.id)
        self.assertEqual(data["package_name"], finding.package_name)
        self.assertIn("remediation_cmd", data)
        self.assertIn("patch_diff", data)
        self.assertIn("explanation", data)

        # Test invalid finding id
        response = self.client.get("/api/remediation/99999")
        self.assertEqual(response.status_code, 404)

    def test_risk_config_endpoints(self):
        # 1. Test GET config
        response = self.client.get("/api/risk/config")
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertAlmostEqual(data["cvss_weight"], 10.0)
        self.assertAlmostEqual(data["epss_weight"], 1.0)
        self.assertAlmostEqual(data["patch_lag_weight"], 1.0)
        self.assertAlmostEqual(data["depth_weight"], 1.0)

        # 2. Test POST config (update weights)
        payload = {
            "cvss_weight": 5.0,
            "epss_weight": 0.8,
            "patch_lag_weight": 1.2,
            "depth_weight": 2.0
        }
        response = self.client.post("/api/risk/config", json=payload)
        self.assertEqual(response.status_code, 200)
        
        updated_data = response.json()
        self.assertIn("config", updated_data)
        self.assertAlmostEqual(updated_data["config"]["cvss_weight"], 5.0)

        # Verify that the GET endpoint returns the new weights
        response = self.client.get("/api/risk/config")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertAlmostEqual(data["cvss_weight"], 5.0)

        # Reset weights to default
        reset_payload = {
            "cvss_weight": 10.0,
            "epss_weight": 1.0,
            "patch_lag_weight": 1.0,
            "depth_weight": 1.0
        }
        self.client.post("/api/risk/config", json=reset_payload)

if __name__ == "__main__":
    unittest.main()
