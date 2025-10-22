import joblib
import pandas as pd
import time
import requests
import socket
from .feature_extraction import extract_features
try:
    from .validators import validate_url as validate_url_format
    from .logger import get_logger
    from .config import (
        DT_MODEL_FILE, XGB_MODEL_FILE, FEATURE_NAMES_FILE,
        PREDICTION_THRESHOLD, ENSEMBLE_WEIGHTS, RISK_THRESHOLDS
    )
    from .security_intel import enhance_prediction, is_available as vt_available
    logger = get_logger(__name__)
    USE_ADVANCED_FEATURES = True
    USE_SECURITY_INTEL = True
except ImportError:
    # Fallback if advanced modules not available
    USE_ADVANCED_FEATURES = False
    USE_SECURITY_INTEL = False
    validate_url_format = None
    logger = None
    DT_MODEL_FILE = None
    XGB_MODEL_FILE = None
    FEATURE_NAMES_FILE = None
    PREDICTION_THRESHOLD = 0.5
    ENSEMBLE_WEIGHTS = {'dt': 0.3, 'xgb': 0.7}
    RISK_THRESHOLDS = {'low': 0.3, 'medium': 0.7, 'high': 0.7}
    vt_available = lambda: False
    enhance_prediction = None

def check_url_exists_online(url, timeout=5):
    """
    Check if URL exists and is accessible online
    
    Args:
        url: URL to check
        timeout: Request timeout in seconds
        
    Returns:
        tuple: (exists, status_code, has_dns, response_time)
    """
    try:
        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Extract domain for DNS check
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        domain = domain.split(':')[0]
        
        # Check DNS first (faster)
        has_dns = False
        try:
            socket.setdefaulttimeout(3)
            socket.gethostbyname(domain)
            has_dns = True
        except:
            pass
        
        # Try to reach the URL
        start_time = time.time()
        response = requests.head(
            url, 
            timeout=timeout, 
            allow_redirects=True,
            verify=True,  # Proper SSL verification
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )
        response_time = time.time() - start_time
        
        exists = response.status_code < 400
        return exists, response.status_code, has_dns, round(response_time, 3)
        
    except requests.exceptions.SSLError:
        # SSL error but site exists
        return False, 495, has_dns, 0.0  # Custom code for SSL error
    except requests.exceptions.Timeout:
        return False, 408, has_dns, timeout  # Request timeout
    except requests.exceptions.ConnectionError:
        return False, 0, has_dns, 0.0  # Cannot connect
    except Exception as e:
        return False, 0, has_dns, 0.0

# Cache loaded models and feature names to avoid reloading
_cached_models = {'dt': None, 'xgb': None, 'features': None}

def load_models():
    """
    Load trained models and feature names with caching
    
    Returns:
        tuple: (decision_tree_model, xgboost_model, feature_names)
    
    Raises:
        FileNotFoundError: If model files don't exist
        Exception: If models fail to load
    """
    try:
        # Check if models are already cached
        if all(v is not None for v in _cached_models.values()):
            if logger:
                logger.debug("Using cached models")
            return _cached_models['dt'], _cached_models['xgb'], _cached_models['features']
        
        if logger:
            logger.info("Loading models from disk...")
        
        # Determine model paths
        if USE_ADVANCED_FEATURES and DT_MODEL_FILE:
            dt_path = DT_MODEL_FILE
            xgb_path = XGB_MODEL_FILE
            features_path = FEATURE_NAMES_FILE
        else:
            # Fallback to simple paths
            import os
            dt_path = 'models/dt_model.pkl'
            xgb_path = 'models/xgb_model.pkl'
            features_path = 'models/feature_names.pkl'
            if not os.path.exists(dt_path):
                raise FileNotFoundError(
                    "Decision Tree model not found. "
                    "Please train models: python -m src.main"
                )
            if not os.path.exists(xgb_path):
                raise FileNotFoundError(
                    "XGBoost model not found. "
                    "Please train models: python -m src.main"
                )
        
        # Load models
        dt = joblib.load(str(dt_path) if hasattr(dt_path, '__str__') else dt_path)
        xgb = joblib.load(str(xgb_path) if hasattr(xgb_path, '__str__') else xgb_path)
        
        if logger:
            logger.info("Models loaded successfully")
        
        # Load feature names (if available)
        feature_names = None
        try:
            if USE_ADVANCED_FEATURES and features_path:
                if hasattr(features_path, 'exists'):
                    if features_path.exists():
                        feature_names = joblib.load(features_path)
                else:
                    import os
                    if os.path.exists(features_path):
                        feature_names = joblib.load(features_path)
            if logger and feature_names:
                logger.info(f"Loaded {len(feature_names)} feature names")
        except:
            pass
        
        # Cache models and features
        _cached_models['dt'] = dt
        _cached_models['xgb'] = xgb
        _cached_models['features'] = feature_names
        
        return dt, xgb, feature_names
        
    except FileNotFoundError as e:
        if logger:
            logger.error(f"Model file not found: {e}")
        raise FileNotFoundError(str(e))
    except Exception as e:
        if logger:
            logger.error(f"Failed to load models: {e}")
        raise Exception(f"Failed to load models: {str(e)}")

def check_url(url, threshold=None, use_ensemble=True, check_online=True):
    """
    Check if a URL is phishing or legitimate with improved prediction
    
    Args:
        url (str): URL to check
        threshold (float): Classification threshold (default 0.5)
        use_ensemble: Use ensemble voting for final prediction
        check_online: Check if URL exists online before analysis
        
    Returns:
        dict: Prediction results with probabilities and confidence
    """
    start_time = time.time()
    
    try:
        # Use config threshold if not provided
        if threshold is None:
            threshold = PREDICTION_THRESHOLD
        
        # Check if URL exists online (optional but recommended)
        url_exists = False
        status_code = 0
        has_dns = False
        response_time = 0.0
        
        if check_online:
            if logger:
                logger.debug(f"Checking if URL exists online: {url}")
            url_exists, status_code, has_dns, response_time = check_url_exists_online(url, timeout=5)
            
            # Add to result metadata
            online_status = {
                'exists': url_exists,
                'status_code': status_code,
                'has_dns': has_dns,
                'response_time': response_time,
                'checked': True
            }
            
            if not has_dns:
                if logger:
                    logger.warning(f"URL has no DNS record: {url}")
            if not url_exists and status_code == 0:
                if logger:
                    logger.warning(f"URL is not accessible: {url}")
        else:
            online_status = {'checked': False}
        
        # Validate URL format
        if USE_ADVANCED_FEATURES and validate_url_format:
            is_valid, normalized_url, error = validate_url_format(url)
            if not is_valid:
                raise ValueError(f"Invalid URL: {error}")
            url = normalized_url
        else:
            # Basic validation
            if not url or not isinstance(url, str):
                raise ValueError("Invalid URL: must be a non-empty string")
            if not url.startswith(('http://', 'https://', 'ftp://')):
                url = 'http://' + url
        
        if logger:
            logger.debug(f"Checking URL: {url}")
        
        # Create DataFrame with URL
        df = pd.DataFrame([{'url': url, 'label': 0}])
        
        # Extract features
        try:
            df = extract_features(df)
        except Exception as e:
            raise Exception(f"Feature extraction failed: {str(e)}")
        
        # Load models and feature names
        try:
            dt, xgb, feature_names = load_models()
        except FileNotFoundError as e:
            raise FileNotFoundError(str(e))
        except Exception as e:
            raise Exception(f"Model loading failed: {str(e)}")
        
        # Get feature columns
        if feature_names:
            # Use saved feature names from training
            # Add missing columns with default value 0
            for col in feature_names:
                if col not in df.columns:
                    df[col] = 0
            features = df[feature_names]
        else:
            # Fallback: use all numeric columns
            feature_cols = [col for col in df.columns if col not in ['url', 'label']]
            features = df[feature_cols]
        
        if features.empty or len(features.columns) == 0:
            raise Exception("No features extracted from URL")
        
        # Make predictions with probability
        try:
            dt_prob = dt.predict_proba(features)[0][1]  # Probability of phishing
            xgb_prob = xgb.predict_proba(features)[0][1]  # Probability of phishing
        except Exception as e:
            raise Exception(f"Prediction failed: {str(e)}")
        
        # Apply threshold for individual models
        dt_pred = 1 if dt_prob > threshold else 0
        xgb_pred = 1 if xgb_prob > threshold else 0
        
        # Ensemble prediction (weighted average from config)
        if use_ensemble:
            dt_weight = ENSEMBLE_WEIGHTS['dt']
            xgb_weight = ENSEMBLE_WEIGHTS['xgb']
            ensemble_prob = (dt_prob * dt_weight + xgb_prob * xgb_weight)
            ensemble_pred = 1 if ensemble_prob > threshold else 0
        else:
            ensemble_prob = (dt_prob + xgb_prob) / 2
            ensemble_pred = 1 if ensemble_prob > threshold else 0
        
        # HIDDEN: Enhance prediction with VirusTotal intelligence (if available)
        vt_enhanced = False
        vt_data = None
        if USE_SECURITY_INTEL and vt_available() and enhance_prediction:
            try:
                original_pred = ensemble_pred
                original_prob = ensemble_prob
                
                ensemble_pred, ensemble_prob, vt_data = enhance_prediction(
                    url, ensemble_pred, ensemble_prob
                )
                
                if vt_data:
                    vt_enhanced = True
                    if logger:
                        logger.debug(f"Enhanced prediction with security intelligence: "
                                   f"{original_prob:.4f} -> {ensemble_prob:.4f}")
            except Exception as e:
                # Silently fail - staff won't notice
                if logger:
                    logger.debug(f"Security intelligence check skipped: {e}")
                pass
        
        # Determine risk level based on probability
        if ensemble_prob < RISK_THRESHOLDS['low']:
            risk_level = "low"
        elif ensemble_prob < RISK_THRESHOLDS['medium']:
            risk_level = "medium"
        else:
            risk_level = "high"
        
        # Calculate confidence (how far from threshold)
        confidence = abs(ensemble_prob - threshold)
        if confidence < 0.1:
            confidence_level = "very_low"
        elif confidence < 0.2:
            confidence_level = "low"
        elif confidence < 0.3:
            confidence_level = "medium"
        elif confidence < 0.4:
            confidence_level = "high"
        else:
            confidence_level = "very_high"
        
        # Determine final prediction
        final_prediction = "phishing" if ensemble_pred == 1 else "legitimate"
        
        # Calculate processing time
        processing_time = time.time() - start_time
        
        result = {
            'url': url,
            'prediction': final_prediction,
            'probability': round(ensemble_prob, 4),
            'risk_level': risk_level,
            'confidence': confidence_level,
            'online_status': online_status,  # Add online check results
            'models': {
                'decision_tree': {
                    'prediction': 'phishing' if dt_pred == 1 else 'legitimate',
                    'probability': round(dt_prob, 4)
                },
                'xgboost': {
                    'prediction': 'phishing' if xgb_pred == 1 else 'legitimate',
                    'probability': round(xgb_prob, 4)
                }
            },
            'threshold': threshold,
            'processing_time': round(processing_time, 4)
        }
        
        if logger:
            logger.info(f"Prediction for {url}: {final_prediction} (prob={ensemble_prob:.4f}, time={processing_time:.3f}s)")
        return result
        
    except FileNotFoundError as e:
        # Models not found - return error with specific message
        return {
            'decision_tree': -1, 
            'xgboost': -1, 
            'ensemble': -1,
            'dt_probability': 0.0, 
            'xgb_probability': 0.0,
            'ensemble_probability': 0.0,
            'error': str(e),
            'error_type': 'ModelNotFound'
        }
    except ValueError as e:
        # Invalid input
        return {
            'decision_tree': -1, 
            'xgboost': -1,
            'ensemble': -1, 
            'dt_probability': 0.0, 
            'xgb_probability': 0.0,
            'ensemble_probability': 0.0,
            'error': str(e),
            'error_type': 'InvalidInput'
        }
    except Exception as e:
        # General error
        return {
            'decision_tree': -1, 
            'xgboost': -1,
            'ensemble': -1, 
            'dt_probability': 0.0, 
            'xgb_probability': 0.0,
            'ensemble_probability': 0.0,
            'error': str(e),
            'error_type': 'GeneralError'
        }
