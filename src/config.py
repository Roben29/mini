"""
Central configuration file for the Phishing URL Detector
All paths, timeouts, and parameters are defined here
"""

import os
from pathlib import Path

# ============================================
# PROJECT PATHS
# ============================================

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Data directories
DATA_DIR = BASE_DIR / 'data'
MODELS_DIR = BASE_DIR / 'models'
LOGS_DIR = BASE_DIR / 'logs'

# Dataset files
DATASET_FILE = DATA_DIR / 'urls.csv'
SAMPLED_DATASET_FILE = DATA_DIR / 'urls_sampled.csv'

# Model files
DT_MODEL_FILE = MODELS_DIR / 'dt_model.pkl'
XGB_MODEL_FILE = MODELS_DIR / 'xgb_model.pkl'
FEATURE_NAMES_FILE = MODELS_DIR / 'feature_names.pkl'
FEATURE_STATS_FILE = MODELS_DIR / 'feature_stats.pkl'
MODEL_METADATA_FILE = MODELS_DIR / 'model_metadata.json'

# Ensure directories exist
for directory in [DATA_DIR, MODELS_DIR, LOGS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# ============================================
# NETWORK SETTINGS
# ============================================

# Timeouts (in seconds)
NETWORK_TIMEOUT = 5  # General network operations
DNS_TIMEOUT = 3      # DNS lookups
SSL_TIMEOUT = 3      # SSL certificate checks
HTTP_TIMEOUT = 5     # HTTP requests
WHOIS_TIMEOUT = 10   # WHOIS lookups (can be slow)

# Retries
MAX_RETRIES = 2
RETRY_DELAY = 1  # seconds

# User agent for HTTP requests
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

# ============================================
# FEATURE EXTRACTION SETTINGS
# ============================================

# Enable/disable different feature types
ENABLE_STATIC_FEATURES = True
ENABLE_DNS_FEATURES = True
ENABLE_SSL_FEATURES = True
ENABLE_WHOIS_FEATURES = True
ENABLE_CONTENT_FEATURES = True

# Feature extraction modes
FAST_MODE = False  # Skip slow network checks
SAMPLE_SIZE = None  # Limit network checks to N samples (None = all)

# Suspicious keywords for phishing detection
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'update', 'secure', 'banking',
    'password', 'credential', 'confirm', 'suspend', 'restricted', 'verify',
    'unlock', 'expire', 'urgent', 'alert', 'warning', 'notification'
]

# ============================================
# MODEL TRAINING SETTINGS
# ============================================

# Data splitting
TEST_SIZE = 0.2
RANDOM_STATE = 42
STRATIFY = True

# Cross-validation
CV_FOLDS = 5
CV_SCORING = 'f1'

# Decision Tree parameters
DT_PARAMS = {
    'max_depth': 15,
    'min_samples_split': 25,
    'min_samples_leaf': 12,
    'max_features': 'sqrt',
    'splitter': 'best',
    'criterion': 'gini',
    'min_impurity_decrease': 0.0005,
    'max_leaf_nodes': 500,
    'random_state': RANDOM_STATE
}

# XGBoost parameters
XGB_PARAMS = {
    'max_depth': 7,
    'n_estimators': 150,
    'learning_rate': 0.03,
    'objective': 'binary:logistic',
    'eval_metric': 'logloss',
    'subsample': 0.8,
    'colsample_bytree': 0.8,
    'colsample_bylevel': 0.8,
    'colsample_bynode': 0.8,
    'min_child_weight': 5,
    'gamma': 0.2,
    'reg_alpha': 0.1,
    'reg_lambda': 2.0,
    'tree_method': 'hist',
    'max_bin': 256,
    'grow_policy': 'depthwise',
    'random_state': RANDOM_STATE,
    'verbosity': 0,
    'use_label_encoder': False
}

# Calibration
USE_CALIBRATION = True
CALIBRATION_METHOD = 'isotonic'  # 'isotonic' or 'sigmoid'
CALIBRATION_CV = 5

# ============================================
# PREPROCESSING SETTINGS
# ============================================

# Feature selection
REMOVE_ZERO_VARIANCE = True
REMOVE_HIGH_CORRELATION = True
CORRELATION_THRESHOLD = 0.95

# Outlier removal
REMOVE_OUTLIERS = False
OUTLIER_METHOD = 'iqr'  # 'iqr' or 'zscore'
OUTLIER_THRESHOLD = 3.0

# Scaling
USE_SCALING = False  # Not recommended for tree-based models
SCALER_TYPE = 'robust'  # 'standard' or 'robust'

# ============================================
# PREDICTION SETTINGS
# ============================================

# Classification threshold
PREDICTION_THRESHOLD = 0.5

# Ensemble method
USE_ENSEMBLE = True
ENSEMBLE_WEIGHTS = {
    'dt': 0.3,   # Decision Tree weight
    'xgb': 0.7   # XGBoost weight (higher because it's more accurate)
}

# Risk level thresholds
RISK_THRESHOLDS = {
    'low': 0.3,      # < 0.3 = LOW risk
    'medium': 0.7,   # 0.3-0.7 = MEDIUM risk
    'high': 0.7      # > 0.7 = HIGH risk
}

# Model caching
CACHE_MODELS = True

# ============================================
# LOGGING SETTINGS
# ============================================

LOG_LEVEL = 'INFO'  # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_TO_FILE = True
LOG_TO_CONSOLE = True
LOG_MAX_SIZE = 10 * 1024 * 1024  # 10MB
LOG_BACKUP_COUNT = 5

# ============================================
# GUI SETTINGS
# ============================================

WINDOW_WIDTH = 900
WINDOW_HEIGHT = 700
WINDOW_TITLE = "Phishing URL Detector - ML Powered"

# Colors
GUI_COLORS = {
    'bg': '#f0f0f0',
    'primary': '#2196F3',
    'danger': '#f44336',
    'success': '#4CAF50',
    'warning': '#FF9800',
    'safe': '#4CAF50',
    'phishing': '#f44336'
}

# ============================================
# PERFORMANCE SETTINGS
# ============================================

# Parallel processing
USE_PARALLEL = True
N_JOBS = -1  # -1 = use all cores, or specify number

# Memory optimization
CHUNK_SIZE = 1000  # Process data in chunks
MEMORY_EFFICIENT_MODE = False

# ============================================
# VERSION INFO
# ============================================

VERSION = '2.0.0'
PROJECT_NAME = 'Phishing URL Detector'
AUTHOR = 'Roben29'
GITHUB_REPO = 'https://github.com/Roben29/phishing-url-detector-2025'

# ============================================
# HELPER FUNCTIONS
# ============================================

def get_optimal_threads():
    """Get optimal number of threads based on CPU cores"""
    if N_JOBS == -1:
        try:
            cpu_count = os.cpu_count() or 2
            return max(1, min(cpu_count // 2, 4))
        except:
            return 2
    return N_JOBS

def get_model_path(model_type):
    """Get path for specific model type"""
    paths = {
        'dt': DT_MODEL_FILE,
        'xgb': XGB_MODEL_FILE,
        'feature_names': FEATURE_NAMES_FILE,
        'feature_stats': FEATURE_STATS_FILE,
        'metadata': MODEL_METADATA_FILE
    }
    return paths.get(model_type)

def validate_config():
    """Validate configuration settings"""
    errors = []
    
    # Check thresholds
    if not 0 <= PREDICTION_THRESHOLD <= 1:
        errors.append("PREDICTION_THRESHOLD must be between 0 and 1")
    
    # Check ensemble weights
    if USE_ENSEMBLE:
        total_weight = sum(ENSEMBLE_WEIGHTS.values())
        if not 0.99 <= total_weight <= 1.01:
            errors.append(f"ENSEMBLE_WEIGHTS must sum to 1.0 (currently {total_weight})")
    
    # Check test size
    if not 0 < TEST_SIZE < 1:
        errors.append("TEST_SIZE must be between 0 and 1")
    
    if errors:
        raise ValueError("Configuration validation failed:\n" + "\n".join(errors))
    
    return True

# Validate configuration on import
validate_config()
