"""
Ensemble prediction module - combines multiple detection methods
Uses majority voting from Decision Tree, XGBoost, and Security Scanner
"""

import joblib
import os
import pandas as pd
from typing import Dict, Tuple
from src.feature_extraction import extract_features
from src.validators import check_url_with_security_scanner
from src.logger import get_logger

logger = get_logger(__name__)


class EnsemblePredictor:
    """Ensemble predictor combining multiple detection methods"""
    
    def __init__(self):
        """Initialize ensemble predictor and load models"""
        self.dt_model = None
        self.xgb_model = None
        self.feature_names = None
        self.load_models()
    
    def load_models(self):
        """Load trained ML models"""
        try:
            if os.path.exists('models/dt_model.pkl'):
                self.dt_model = joblib.load('models/dt_model.pkl')
                logger.info("Decision Tree model loaded")
            
            if os.path.exists('models/xgb_model.pkl'):
                self.xgb_model = joblib.load('models/xgb_model.pkl')
                logger.info("XGBoost model loaded")
            
            if os.path.exists('models/feature_names.pkl'):
                self.feature_names = joblib.load('models/feature_names.pkl')
                logger.info(f"Feature names loaded: {len(self.feature_names)} features")
                
        except Exception as e:
            logger.error(f"Error loading models: {e}")
    
    def predict_single_url(self, url: str, use_security_scan: bool = True) -> Dict:
        """
        Predict if URL is malicious using ensemble of methods
        
        Args:
            url: URL to check
            use_security_scan: Whether to use Security Scanner
        
        Returns:
            Dict with predictions from all methods and ensemble result
        """
        result = {
            'url': url,
            'decision_tree': None,
            'xgboost': None,
            'security_scan': None,
            'ensemble_prediction': None,
            'ensemble_confidence': 0.0,
            'details': {}
        }
        
        # Prepare URL data for ML models
        try:
            df = pd.DataFrame({'url': [url], 'label': [0]})
            df_features = extract_features(df)
            df_features = df_features.drop('label', axis=1, errors='ignore')
            
            # Ensure features match training
            if self.feature_names:
                for feature in self.feature_names:
                    if feature not in df_features.columns:
                        df_features[feature] = 0
                df_features = df_features[self.feature_names]
        
        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            result['details']['error'] = str(e)
            return result
        
        votes = []
        predictions = []
        
        # 1. Decision Tree Prediction
        if self.dt_model:
            try:
                dt_pred = self.dt_model.predict(df_features)[0]
                dt_proba = self.dt_model.predict_proba(df_features)[0]
                
                result['decision_tree'] = {
                    'prediction': 'Phishing' if dt_pred == 1 else 'Safe',
                    'confidence': float(max(dt_proba)) * 100,
                    'safe_prob': float(dt_proba[0]) * 100,
                    'phishing_prob': float(dt_proba[1]) * 100
                }
                votes.append(dt_pred)
                predictions.append(('Decision Tree', dt_pred, max(dt_proba)))
                
            except Exception as e:
                logger.error(f"Decision Tree prediction failed: {e}")
                result['decision_tree'] = {'error': str(e)}
        
        # 2. XGBoost Prediction
        if self.xgb_model:
            try:
                xgb_pred = self.xgb_model.predict(df_features)[0]
                xgb_proba = self.xgb_model.predict_proba(df_features)[0]
                
                result['xgboost'] = {
                    'prediction': 'Phishing' if xgb_pred == 1 else 'Safe',
                    'confidence': float(max(xgb_proba)) * 100,
                    'safe_prob': float(xgb_proba[0]) * 100,
                    'phishing_prob': float(xgb_proba[1]) * 100
                }
                votes.append(xgb_pred)
                predictions.append(('XGBoost', xgb_pred, max(xgb_proba)))
                
            except Exception as e:
                logger.error(f"XGBoost prediction failed: {e}")
                result['xgboost'] = {'error': str(e)}
        
        # 3. Security Scanner Check
        if use_security_scan:
            try:
                scan_result = check_url_with_security_scanner(url)
                
                if scan_result['checked']:
                    # Convert scan results to binary prediction
                    scan_pred = 1 if scan_result['malicious'] > scan_result['clean'] else 0
                    scan_confidence = scan_result['malicious'] / max(scan_result['total_scans'], 1)
                    
                    result['security_scan'] = {
                        'prediction': 'Phishing' if scan_pred == 1 else 'Safe',
                        'confidence': float(scan_confidence) * 100,
                        'malicious_count': scan_result['malicious'],
                        'clean_count': scan_result['clean'],
                        'total_scans': scan_result['total_scans']
                    }
                    votes.append(scan_pred)
                    predictions.append(('Security Scan', scan_pred, scan_confidence))
                else:
                    result['security_scan'] = {
                        'enabled': scan_result['enabled'],
                        'error': scan_result.get('error', 'Not checked')
                    }
            
            except Exception as e:
                logger.error(f"Security Scanner check failed: {e}")
                result['security_scan'] = {'error': str(e)}
        
        # 4. Ensemble Decision (Majority Voting)
        if len(votes) >= 2:
            # Majority vote
            phishing_votes = sum(votes)
            safe_votes = len(votes) - phishing_votes
            
            ensemble_pred = 1 if phishing_votes > safe_votes else 0
            ensemble_confidence = max(phishing_votes, safe_votes) / len(votes) * 100
            
            result['ensemble_prediction'] = 'Phishing' if ensemble_pred == 1 else 'Safe'
            result['ensemble_confidence'] = ensemble_confidence
            
            result['details'] = {
                'total_votes': len(votes),
                'phishing_votes': phishing_votes,
                'safe_votes': safe_votes,
                'agreement': 'Unanimous' if len(set(votes)) == 1 else 'Split Decision',
                'methods_used': [name for name, _, _ in predictions]
            }
            
            logger.info(f"Ensemble prediction for {url}: {result['ensemble_prediction']} "
                       f"({ensemble_confidence:.1f}% confidence, {len(votes)} methods)")
        else:
            result['details']['error'] = 'Insufficient predictions for ensemble'
        
        return result


def get_ensemble_prediction(url: str, use_security_scan: bool = True) -> Dict:
    """
    Convenience function to get ensemble prediction
    
    Args:
        url: URL to check
        use_security_scan: Whether to use Security Scanner
    
    Returns:
        Dict with ensemble prediction results
    """
    predictor = EnsemblePredictor()
    return predictor.predict_single_url(url, use_security_scan)
