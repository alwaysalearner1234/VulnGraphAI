import unittest
from backend.services.risk_engine import RiskEngine

class TestRiskEngine(unittest.TestCase):
    def test_version_distance(self):
        # Major version difference
        dist1 = RiskEngine.calculate_version_distance("1.0.0", "2.0.0")
        self.assertEqual(dist1, 1.0)
        
        # Patch version difference
        dist2 = RiskEngine.calculate_version_distance("4.17.15", "4.17.21")
        self.assertAlmostEqual(dist2, 0.3)  # 6 * 0.05

        # Target version is same or older
        dist3 = RiskEngine.calculate_version_distance("2.0.0", "1.5.0")
        self.assertEqual(dist3, 0.0)

    def test_calculate_risk_score(self):
        # High CVSS, high EPSS, direct dependency, old version
        res1 = RiskEngine.calculate_risk_score(
            cvss=9.8,
            epss=0.95,
            depth=1,
            installed_version="1.0.0",
            fixed_version="2.0.0"
        )
        self.assertEqual(res1["category"], "CRITICAL")
        self.assertTrue(res1["score"] > 80.0)
        
        # Transitive dependency mitigation test
        res2 = RiskEngine.calculate_risk_score(
            cvss=9.8,
            epss=0.95,
            depth=4,
            installed_version="1.0.0",
            fixed_version="2.0.0"
        )
        # Depth=4 cuts the raw score in half (1 / sqrt(4) = 0.5)
        self.assertAlmostEqual(res2["depth_factor"], 0.5)
        self.assertTrue(res2["score"] < res1["score"])

if __name__ == "__main__":
    unittest.main()
