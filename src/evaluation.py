from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score, 
    roc_curve, precision_recall_curve, average_precision_score
)
import numpy as np

def evaluate_model(model, X_test, y_test, model_name="Model", verbose=True):
    """
    Comprehensive model evaluation with detailed metrics
    
    Args:
        model: Trained model
        X_test: Test features
        y_test: True labels
        model_name: Name for display
        verbose: Print detailed report
    
    Returns:
        dict: Comprehensive evaluation metrics
    """
    # Make predictions
    y_pred = model.predict(X_test)
    
    # Get probability predictions if available
    try:
        y_pred_proba = model.predict_proba(X_test)[:, 1]
    except AttributeError:
        y_pred_proba = y_pred
    
    # Basic metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    # Additional metrics
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0  # True negative rate
    false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
    false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
    
    # ROC AUC (if probabilities available)
    try:
        roc_auc = roc_auc_score(y_test, y_pred_proba)
        avg_precision = average_precision_score(y_test, y_pred_proba)
    except:
        roc_auc = 0.0
        avg_precision = 0.0
    
    # Detailed report
    if verbose:
        print(f"\n{'='*70}")
        print(f"  {model_name} - DETAILED EVALUATION")
        print(f"{'='*70}\n")
        
        print(f"📊 Basic Metrics:")
        print(f"   Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
        print(f"   Precision: {precision:.4f} ({precision*100:.2f}%)")
        print(f"   Recall:    {recall:.4f} ({recall*100:.2f}%)")
        print(f"   F1-Score:  {f1:.4f} ({f1*100:.2f}%)")
        
        if roc_auc > 0:
            print(f"   ROC AUC:   {roc_auc:.4f}")
            print(f"   Avg Prec:  {avg_precision:.4f}")
        
        print(f"\n🎯 Confusion Matrix:")
        print(f"                    Predicted")
        print(f"                Legit    Phishing")
        print(f"   Actual Legit    {tn:6,}   {fp:6,}  (FPR: {false_positive_rate:.2%})")
        print(f"         Phishing  {fn:6,}   {tp:6,}  (FNR: {false_negative_rate:.2%})")
        
        print(f"\n📈 Detailed Metrics:")
        print(f"   True Positives:  {tp:,} (phishing correctly identified)")
        print(f"   True Negatives:  {tn:,} (legitimate correctly identified)")
        print(f"   False Positives: {fp:,} (legitimate marked as phishing)")
        print(f"   False Negatives: {fn:,} (phishing marked as legitimate)")
        print(f"   Specificity:     {specificity:.4f} (true negative rate)")
        
        print(f"\n💡 Interpretation:")
        if false_positive_rate > 0.1:
            print(f"   ⚠  High false positive rate ({false_positive_rate:.2%})")
            print(f"      Too many legitimate URLs marked as phishing")
        if false_negative_rate > 0.1:
            print(f"   ⚠  High false negative rate ({false_negative_rate:.2%})")
            print(f"      Too many phishing URLs marked as legitimate")
        if false_positive_rate < 0.05 and false_negative_rate < 0.05:
            print(f"   ✓  Excellent balance between false positives and negatives")
        
        print(f"\n{'='*70}\n")
    
    # Return comprehensive metrics
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'specificity': specificity,
        'roc_auc': roc_auc,
        'avg_precision': avg_precision,
        'confusion_matrix': cm,
        'true_positives': int(tp),
        'true_negatives': int(tn),
        'false_positives': int(fp),
        'false_negatives': int(fn),
        'false_positive_rate': false_positive_rate,
        'false_negative_rate': false_negative_rate
    }

def find_optimal_threshold(model, X_test, y_test, target_fpr=0.05):
    """
    Find optimal classification threshold to balance FPR and FNR
    
    Args:
        model: Trained model
        X_test: Test features
        y_test: True labels
        target_fpr: Target false positive rate
    
    Returns:
        float: Optimal threshold
    """
    try:
        y_pred_proba = model.predict_proba(X_test)[:, 1]
        fpr, tpr, thresholds = roc_curve(y_test, y_pred_proba)
        
        # Find threshold that gives desired FPR
        idx = np.argmin(np.abs(fpr - target_fpr))
        optimal_threshold = thresholds[idx]
        
        print(f"\n🎯 Optimal Threshold Analysis:")
        print(f"   Target FPR: {target_fpr:.2%}")
        print(f"   Optimal threshold: {optimal_threshold:.3f}")
        print(f"   Achieved FPR: {fpr[idx]:.2%}")
        print(f"   Achieved TPR (Recall): {tpr[idx]:.2%}")
        
        return optimal_threshold
    except:
        return 0.5
