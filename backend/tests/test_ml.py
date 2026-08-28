import unittest
import os
from backend.services.ml_service import MLService

class TestMLService(unittest.TestCase):
    def test_training_and_loading(self):
        # Trigger model load (which auto-trains if model.joblib is not present)
        model = MLService.load_model()
        self.assertIsNotNone(model)
        self.assertTrue(os.path.exists(MLService.load_model.__globals__['MODEL_PATH']))

    def test_prediction(self):
        inputs = {
            "cvss": 9.8,
            "epss": 0.95,
            "depth": 1,
            "patch_lag": 1.0,
            "exploit_available": True,
            "in_degree": 1,
            "out_degree": 2,
            "dependents_count": 5
        }
        
        prediction = MLService.predict(inputs)
        self.assertIn("risk_probability", prediction)
        self.assertIn("category", prediction)
        self.assertIn("feature_contributions", prediction)
        
        # Verify feature contribution contains percentage breakdowns
        contribs = prediction["feature_contributions"]
        self.assertTrue(len(contribs) > 0)
        self.assertIn("feature", contribs[0])
        self.assertIn("percentage", contribs[0])

if __name__ == "__main__":
    unittest.main()
