"""
Machine Learning Anomaly Detector using Isolation Forest
"""
import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Dict, Any, Tuple

SENSITIVE_EXTENSIONS = {".cron", ".sh", ".exe", ".bat", ".ps1", ".dll", ".sys", ".conf", ".env", ".key"}

class FIMAnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        self.is_fitted = False
        self._initialize_default_training_data()

    def extract_features(self, change_event: Dict[str, Any]) -> np.ndarray:
        """
        Extract numerical feature vector:
        [entropy, entropy_delta, size_delta, path_depth, hour_of_day, is_sensitive_ext]
        """
        new_meta = change_event.get("new_meta") or change_event.get("old_meta") or {}
        entropy = float(new_meta.get("entropy", 4.0))
        entropy_delta = float(change_event.get("entropy_delta", 0.0))
        size_delta = float(change_event.get("size_delta", 0.0))

        rel_path = new_meta.get("rel_path", change_event.get("rel_path", ""))
        depth = rel_path.count("/") + rel_path.count("\\")
        ext = new_meta.get("extension", "")

        is_sensitive = 1.0 if ext in SENSITIVE_EXTENSIONS or "cron" in rel_path.lower() else 0.0
        hour = 12.0  # default midday if mtime unavailable

        mtime = new_meta.get("mtime")
        if mtime:
            from datetime import datetime
            hour = datetime.fromtimestamp(mtime).hour

        return np.array([[entropy, entropy_delta, size_delta, depth, hour, is_sensitive]])

    def _initialize_default_training_data(self):
        """Fit model with representative normal file modification behavior."""
        np.random.seed(42)
        # Normal features: entropy ~3.5-5.5, entropy_delta ~-0.5 to 0.5, size_delta ~-500 to +2000, depth ~1-3, hour ~8-18, non-sensitive
        normal_samples = []
        for _ in range(200):
            ent = np.random.uniform(3.0, 5.5)
            ent_d = np.random.uniform(-0.3, 0.3)
            sz_d = np.random.uniform(-200, 1000)
            dep = np.random.randint(1, 4)
            hr = np.random.randint(8, 19)
            sens = 0.0
            normal_samples.append([ent, ent_d, sz_d, dep, hr, sens])

        X_train = np.array(normal_samples)
        self.model.fit(X_train)
        self.is_fitted = True

    def predict(self, change_event: Dict[str, Any]) -> Tuple[bool, float, str]:
        """
        Predict if a change event is an anomaly.
        Returns: (is_anomaly, risk_score_0_100, reasoning_summary)
        """
        if not self.is_fitted:
            self._initialize_default_training_data()

        X = self.extract_features(change_event)
        raw_score = self.model.decision_function(X)[0]  # Higher score = more normal, lower = anomaly
        prediction = self.model.predict(X)[0]           # -1 for anomaly, 1 for normal

        is_anomaly = (prediction == -1)
        # Convert decision function score to 0 - 100 risk score
        risk_score = round(max(0.0, min(100.0, (0.5 - raw_score) * 100)), 1)

        reasoning = []
        features = X[0]
        if features[0] > 7.0:
            reasoning.append(f"High file entropy ({features[0]:.2f}) indicates potential encryption/ransomware.")
        if abs(features[1]) > 2.0:
            reasoning.append(f"Unusually large entropy jump ({features[1]:+.2f}).")
        if features[5] == 1.0:
            reasoning.append("Modified file is in a high-security/sensitive extension path.")

        reasoning_str = " ".join(reasoning) if reasoning else "Statistical anomaly detected by Isolation Forest."

        return is_anomaly, risk_score, reasoning_str
