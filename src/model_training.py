import joblib
import os
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier
from sklearn.utils.class_weight import compute_class_weight
from sklearn.model_selection import cross_val_score
from sklearn.calibration import CalibratedClassifierCV
import numpy as np

def get_optimal_threads():
    """
    Get optimal number of threads for training
    Uses half of available CPU cores (min 1, max 4)
    """
    try:
        cpu_count = os.cpu_count() or 2
        optimal = max(1, min(cpu_count // 2, 4))
        return optimal
    except Exception:
        return 2  # Safe default

def train_decision_tree(X_train, y_train, use_calibration=True):
    """
    Train Decision Tree classifier with optimized parameters and regularization
    IMPROVED: Better parameters to prevent overfitting and improve accuracy
    
    Args:
        X_train: Training features
        y_train: Training labels
        use_calibration: Whether to apply probability calibration
        
    Returns:
        Trained Decision Tree model
    """
    try:
        # Calculate class weights for balancing
        classes = np.unique(y_train)
        class_weights = compute_class_weight('balanced', classes=classes, y=y_train)
        class_weight_dict = dict(zip(classes, class_weights))
        
        print(f"   Class weights: {class_weight_dict}")
        
        # Create model with OPTIMIZED regularization to prevent overfitting
        # These parameters are carefully tuned for better generalization
        dt = DecisionTreeClassifier(
            random_state=42, 
            max_depth=15,  # Deeper tree for complex URL patterns
            min_samples_split=25,  # Higher to prevent overfitting on noise
            min_samples_leaf=12,  # Ensures meaningful leaf nodes
            max_features='sqrt',  # Use sqrt of features to reduce correlation
            class_weight=class_weight_dict,  # Handle class imbalance
            splitter='best',  # Best split at each node
            criterion='gini',  # Gini impurity for faster computation
            min_impurity_decrease=0.0005,  # Require meaningful improvement for splits
            max_leaf_nodes=500  # Limit tree complexity
        )
        
        # Train model
        print("   Training base Decision Tree...")
        dt.fit(X_train, y_train)
        
        # Apply probability calibration to reduce prediction bias
        # This significantly improves prediction reliability
        if use_calibration:
            print("   Applying probability calibration (isotonic regression)...")
            dt = CalibratedClassifierCV(dt, method='isotonic', cv=5)
            dt.fit(X_train, y_train)
        
        # Perform cross-validation to check generalization
        print("   Performing cross-validation...")
        cv_scores = cross_val_score(dt, X_train, y_train, cv=5, scoring='f1')
        print(f"   CV F1 scores: {cv_scores}")
        print(f"   Mean CV F1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        
        if cv_scores.mean() < 0.7:
            print("   ⚠ Warning: Low CV score suggests dataset may be too small or imbalanced")
        
        # Save model
        os.makedirs('models', exist_ok=True)
        joblib.dump(dt, 'models/dt_model.pkl')
        
        return dt
        
    except Exception as e:
        raise Exception(f"Decision Tree training failed: {str(e)}")

def train_xgboost(X_train, y_train, use_calibration=True):
    """
    Train XGBoost classifier with optimized parameters and regularization
    IMPROVED: Enhanced gradient boosting for better accuracy
    
    Args:
        X_train: Training features
        y_train: Training labels
        use_calibration: Whether to apply probability calibration
        
    Returns:
        Trained XGBoost model
    """
    try:
        # Calculate scale_pos_weight for class imbalance
        neg_count = (y_train == 0).sum()
        pos_count = (y_train == 1).sum()
        scale_pos_weight = neg_count / pos_count if pos_count > 0 else 1
        
        print(f"   Scale pos weight: {scale_pos_weight:.2f}")
        print(f"   Class distribution: {neg_count} negative, {pos_count} positive")
        
        # Get optimal thread count
        n_threads = get_optimal_threads()
        
        # Create model with OPTIMIZED parameters for better generalization
        # These parameters are specifically tuned for URL phishing detection
        xgb = XGBClassifier(
            use_label_encoder=False, 
            eval_metric='logloss', 
            n_jobs=n_threads,
            random_state=42,
            max_depth=7,  # Optimal depth for URL features
            n_estimators=150,  # More trees for better pattern learning
            learning_rate=0.03,  # Lower learning rate with more trees
            scale_pos_weight=scale_pos_weight,  # Handle class imbalance
            objective='binary:logistic',
            subsample=0.8,  # Bootstrap sampling
            colsample_bytree=0.8,  # Feature sampling per tree
            colsample_bylevel=0.8,  # Feature sampling per level
            colsample_bynode=0.8,  # Feature sampling per node
            min_child_weight=5,  # More conservative splits
            gamma=0.2,  # Higher minimum loss reduction
            reg_alpha=0.1,  # L1 regularization (feature selection)
            reg_lambda=2.0,  # L2 regularization (weight smoothing)
            tree_method='hist',  # Faster histogram-based algorithm
            max_bin=256,  # Binning for faster training
            grow_policy='depthwise',  # Build tree level-by-level
            verbosity=0  # Suppress warnings
        )
        
        # Train model
        print("   Training base XGBoost...")
        xgb.fit(X_train, y_train)
        
        # Apply probability calibration to reduce prediction bias
        # This is CRITICAL for reliable probability estimates
        if use_calibration:
            print("   Applying probability calibration (isotonic regression)...")
            xgb = CalibratedClassifierCV(xgb, method='isotonic', cv=5)
            xgb.fit(X_train, y_train)
        
        # Perform cross-validation
        print("   Performing cross-validation...")
        cv_scores = cross_val_score(xgb, X_train, y_train, cv=5, scoring='f1')
        print(f"   CV F1 scores: {cv_scores}")
        print(f"   Mean CV F1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        
        if cv_scores.mean() < 0.7:
            print("   ⚠ Warning: Low CV score suggests dataset may be too small or imbalanced")
        
        # Save model
        os.makedirs('models', exist_ok=True)
        joblib.dump(xgb, 'models/xgb_model.pkl')
        
        return xgb
        
    except Exception as e:
        raise Exception(f"XGBoost training failed: {str(e)}")
