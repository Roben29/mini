from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, RobustScaler
import pandas as pd
import joblib
import os
import numpy as np

def prepare_data(df, save_feature_names=True, use_scaling=False, remove_outliers=False):
    """
    Prepare data for model training with enhanced preprocessing
    
    Args:
        df: DataFrame with features and labels
        save_feature_names: Save feature names for later use
        use_scaling: Apply feature scaling (not recommended for tree-based models)
        remove_outliers: Remove statistical outliers
    
    Returns:
        X_train, X_test, y_train, y_test
    """
    print("📋 Preparing data for model training...")
    
    # Keep only numeric feature columns for ML training
    feature_cols = [col for col in df.columns if col not in ['url', 'label']]
    
    X = df[feature_cols].copy()
    y = df['label']
    
    print(f"Initial features: {len(feature_cols)}")
    print(f"Original feature matrix shape: {X.shape}")
    
    # Ensure all features are numeric
    print("Converting features to numeric...")
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)
    
    # Remove any columns with zero variance (all same values)
    print("Checking for zero-variance features...")
    variance = X.var()
    zero_var_cols = variance[variance == 0].index.tolist()
    if zero_var_cols:
        print(f"  Removing {len(zero_var_cols)} zero-variance columns")
        X = X.drop(columns=zero_var_cols)
    
    # Remove highly correlated features to reduce redundancy
    print("Checking for highly correlated features...")
    correlation_matrix = X.corr().abs()
    upper_triangle = correlation_matrix.where(
        np.triu(np.ones(correlation_matrix.shape), k=1).astype(bool)
    )
    high_corr_cols = [col for col in upper_triangle.columns if any(upper_triangle[col] > 0.95)]
    if high_corr_cols:
        print(f"  Removing {len(high_corr_cols)} highly correlated features (>0.95)")
        X = X.drop(columns=high_corr_cols)
    
    # Remove outliers if requested (use IQR method)
    if remove_outliers:
        print("Removing statistical outliers...")
        Q1 = X.quantile(0.25)
        Q3 = X.quantile(0.75)
        IQR = Q3 - Q1
        outlier_mask = ~((X < (Q1 - 3 * IQR)) | (X > (Q3 + 3 * IQR))).any(axis=1)
        
        original_size = len(X)
        X = X[outlier_mask]
        y = y[outlier_mask]
        removed = original_size - len(X)
        
        if removed > 0:
            print(f"  Removed {removed} outlier samples ({removed/original_size*100:.2f}%)")
    
    print(f"Final feature matrix shape: {X.shape}")
    print(f"Active features: {len(X.columns)}")
    
    # Enhanced class distribution display
    class_counts = y.value_counts().to_dict()
    total_samples = len(y)
    print(f"\n📊 Class Distribution:")
    for label, count in sorted(class_counts.items()):
        label_name = "Legitimate" if label == 0 else "Phishing"
        percentage = (count / total_samples) * 100
        bar = '█' * int(percentage / 2)
        print(f"  {label_name:11} (label={label}): {count:6,} ({percentage:5.2f}%) {bar}")
    
    # Check if dataset is reasonably balanced
    if 0 in class_counts and 1 in class_counts:
        ratio = max(class_counts.values()) / min(class_counts.values())
        if ratio > 10:
            print(f"\n⚠  WARNING: Dataset is heavily imbalanced (ratio: 1:{ratio:.1f})")
            print(f"   Models will use class weights to compensate")
            print(f"   Consider running: python download_and_balance.py")
        elif ratio > 2:
            print(f"\n⚠  Dataset is moderately imbalanced (ratio: 1:{ratio:.1f})")
            print(f"   Models will use class weights to compensate")
        else:
            print(f"\n✓  Dataset is well balanced (ratio: 1:{ratio:.1f})")
    
    # Save the final feature names for prediction
    if save_feature_names:
        os.makedirs('models', exist_ok=True)
        feature_names = X.columns.tolist()
        joblib.dump(feature_names, 'models/feature_names.pkl')
        print(f"\n✓ Saved feature names: {len(feature_names)} features")
        
        # Save feature importance info
        feature_stats = {
            'names': feature_names,
            'means': X.mean().to_dict(),
            'stds': X.std().to_dict()
        }
        joblib.dump(feature_stats, 'models/feature_stats.pkl')
    
    # Apply feature scaling if requested (generally not needed for tree-based models)
    scaler = None
    if use_scaling:
        print("\n⚙  Applying robust feature scaling...")
        scaler = RobustScaler()  # More robust to outliers than StandardScaler
        X = pd.DataFrame(
            scaler.fit_transform(X),
            columns=X.columns,
            index=X.index
        )
        joblib.dump(scaler, 'models/scaler.pkl')
    
    # Split with stratification to maintain class balance
    print(f"\n✂  Splitting data: 70% train, 30% test (stratified)")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, 
        test_size=0.3, 
        random_state=42, 
        stratify=y  # Maintain class distribution in both sets
    )
    
    print(f"   Training set: {len(X_train):,} samples")
    print(f"   Test set:     {len(X_test):,} samples")
    
    # Display class distribution in splits
    train_phishing = sum(y_train)
    train_legit = len(y_train) - train_phishing
    test_phishing = sum(y_test)
    test_legit = len(y_test) - test_phishing
    
    print(f"\n   Train split: {train_legit:,} legitimate, {train_phishing:,} phishing")
    print(f"   Test split:  {test_legit:,} legitimate, {test_phishing:,} phishing")
    
    return X_train, X_test, y_train, y_test
