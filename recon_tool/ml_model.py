# recon_tool/recon_tool/ml_model.py

import joblib
import logging
import os

class MLModel:
    def __init__(self, model_path: str):
        if not os.path.isfile(model_path):
            logging.error(f"Machine learning model file not found: {model_path}")
            raise FileNotFoundError(f"Machine learning model file not found: {model_path}")
        try:
            self.model = joblib.load(model_path)
            logging.info(f"Loaded ML model from {model_path}")
        except Exception as e:
            logging.exception(f"Failed to load ML model from {model_path}: {e}")
            raise e

    def predict_stealthy_mode(self, response_time: float, status_code: int, content_length: int, waf_detected: bool) -> bool:
        """
        Predict whether to switch to stealthy mode based on response characteristics.

        Args:
            response_time (float): Time taken for the response.
            status_code (int): HTTP status code.
            content_length (int): Length of the response content.
            waf_detected (bool): Whether a WAF was detected.

        Returns:
            bool: True if stealthy mode should be enabled, False otherwise.
        """
        try:
            # Example feature vector; adjust based on your model's training
            features = [[response_time, status_code, content_length, int(waf_detected)]]
            prediction = self.model.predict(features)
            return bool(prediction[0])
        except Exception as e:
            logging.exception(f"Failed to make prediction with ML model: {e}")
            return False
