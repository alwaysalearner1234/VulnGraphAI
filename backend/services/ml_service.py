import os
from typing import Dict, Any, List, Tuple
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib

# Determine model save path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "ml")
os.makedirs(MODEL_DIR, exist_ok=True)
MODEL_PATH = os.path.join(MODEL_DIR, "prioritizer_model.joblib")

class MLService:
    FEATURES = [
        "cvss", 
        "epss", 
        "depth", 
        "patch_lag", 
        "exploit_available", 
        "in_degree", 
        "out_degree", 
        "dependents_count"
    ]
    
    _model = None
    _feature_importances = None

    @classmethod
    def train_model(cls) -> str:
        """
        Generates synthetic vulnerability prioritization dataset and trains a
        Random Forest model. Saves the model to disk.
        """
        np.random.seed(42)
        size = 1500
        
        # Synthesize features
        cvss = np.random.uniform(1.0, 10.0, size)
        epss = np.random.uniform(0.001, 0.99, size)
        depth = np.random.randint(1, 6, size)
        patch_lag = np.random.uniform(0.0, 1.5, size)
        exploit_available = np.random.choice([0, 1], size=size, p=[0.7, 0.3])
        in_degree = np.random.randint(0, 10, size)
        out_degree = np.random.randint(0, 15, size)
        dependents_count = np.random.randint(0, 30, size)
        
        # Combine into DataFrame
        df = pd.DataFrame({
            "cvss": cvss,
            "epss": epss,
            "depth": depth,
            "patch_lag": patch_lag,
            "exploit_available": exploit_available,
            "in_degree": in_degree,
            "out_degree": out_degree,
            "dependents_count": dependents_count
        })
        
        # Define Ground Truth classification rules
        # Classes: 0: LOW, 1: MEDIUM, 2: HIGH, 3: CRITICAL
        y = []
        for idx, row in df.iterrows():
            # Risk formula baseline
            score = row["cvss"] * (0.2 + 0.8 * row["epss"]) * (1.0 + row["patch_lag"]) / np.sqrt(row["depth"])
            
            # Boost score based on active exploits and Direct Reachability
            if row["exploit_available"] == 1:
                score += 2.0
            if row["depth"] == 1:
                score += 1.5
            if row["dependents_count"] > 10:
                score += 1.0
                
            # Classify
            if score >= 12.0:
                y.append(3) # CRITICAL
            elif score >= 8.0:
                y.append(2) # HIGH
            elif score >= 4.0:
                y.append(1) # MEDIUM
            else:
                y.append(0) # LOW
                
        y = np.array(y)
        
        # Train Random Forest Classifier
        model = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42)
        model.fit(df, y)
        
        # Save model
        joblib.dump(model, MODEL_PATH)
        cls._model = model
        
        return MODEL_PATH

    @classmethod
    def load_model(cls):
        """Loads the trained model from disk, or trains it if missing."""
        if cls._model is not None:
            return cls._model
            
        if not os.path.exists(MODEL_PATH):
            cls.train_model()
            
        try:
            cls._model = joblib.load(MODEL_PATH)
        except Exception:
            # Re-train on failure
            cls.train_model()
            cls._model = joblib.load(MODEL_PATH)
            
        # Store global feature importances for explainability
        cls._feature_importances = dict(zip(cls.FEATURES, cls._model.feature_importances_))
        return cls._model

    @classmethod
    def predict(cls, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run inference using the Random Forest classifier.
        Returns:
            Dict containing: risk_probability, classification, feature_contributions
        """
        model = cls.load_model()
        
        # Format input feature vector
        feat_vector = []
        for feat in cls.FEATURES:
            val = inputs.get(feat, 0.0)
            # Boolean conversions
            if isinstance(val, bool):
                val = 1 if val else 0
            feat_vector.append(float(val))
            
        # Perform prediction
        X_test = pd.DataFrame([feat_vector], columns=cls.FEATURES)
        pred_class_idx = model.predict(X_test)[0]
        pred_proba = model.predict_proba(X_test)[0]
        
        # Maps index to category
        categories = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        category = categories[pred_class_idx]
        
        # High priority probability is sum of High + Critical probabilities
        risk_probability = float(pred_proba[2] + pred_proba[3])
        # If class index is critical/high, return class probability, otherwise fallback
        if pred_class_idx == 3:
            risk_probability = float(pred_proba[3])
        elif pred_class_idx == 2:
            risk_probability = float(pred_proba[2])
        elif pred_class_idx == 1:
            risk_probability = float(pred_proba[1])
        else:
            risk_probability = float(pred_proba[0])

        # Explainability: Feature contribution estimation
        # Calculate local contributions by scaling global feature importances with inputs
        # (normalized to express contribution percentages)
        raw_contributions = {}
        for feat in cls.FEATURES:
            val = inputs.get(feat, 0.0)
            if isinstance(val, bool):
                val = 1.0 if val else 0.0
                
            importance = cls._feature_importances.get(feat, 0.1)
            
            # Non-linear scaling for input values to reflect direct/inverse contribution
            if feat == "depth":
                # Inverse depth is higher risk
                factor = 1.0 / val if val > 0 else 1.0
            elif feat == "cvss":
                factor = val / 10.0
            elif feat == "epss":
                factor = val
            elif feat == "patch_lag":
                factor = val / 1.5
            elif feat == "exploit_available":
                factor = float(val)
            else: # topology metrics
                factor = min(1.0, val / 10.0)
                
            raw_contributions[feat] = importance * factor

        # Normalize contributions to percentages
        total_contrib = sum(raw_contributions.values())
        if total_contrib == 0:
            total_contrib = 1.0
            
        contributions = {
            feat: round((val / total_contrib) * 100, 1) 
            for feat, val in raw_contributions.items()
        }

        # Format feature names nicely for display
        display_names = {
            "cvss": "CVSS Base Score",
            "epss": "EPSS Probability",
            "depth": "Dependency Depth",
            "patch_lag": "Patch Lag Version Distance",
            "exploit_available": "Exploit Availability",
            "in_degree": "In-Degree Node Degree",
            "out_degree": "Out-Degree Node Degree",
            "dependents_count": "Graph Dependents Count"
        }
        
        formatted_contribs = [
            {"feature": display_names.get(f, f), "percentage": val} 
            for f, val in contributions.items()
        ]
        
        # Sort by percentage descending
        formatted_contribs.sort(key=lambda x: x["percentage"], reverse=True)

        return {
            "risk_probability": round(risk_probability, 2),
            "category": category,
            "feature_contributions": formatted_contribs,
            "priority_rank": 4 - pred_class_idx  # 1 is Critical, 4 is Low
        }
