"""
Optimized training script with proper online security checks
Uses the standard feature extraction but with the full 20k dataset
"""
import sys
import os
sys.path.append('src')

print("=" * 70)
print("  TRAINING WITH REAL SECURITY CHECKS (20K BALANCED DATASET)")
print("=" * 70)

# Use the standard feature extraction with online checks
from feature_extraction import extract_features
from data_collection import load_dataset
from preprocessing import prepare_data
from model_training import train_decision_tree, train_xgboost
from evaluation import evaluate_model

print("\n[1/5] Loading dataset...")
df = load_dataset()
print(f"   ✓ Loaded {len(df)} URLs")

print("\n[2/5] Extracting features (WITH online security checks)...")
print("⏱️  This will take 30-60 minutes for 20k URLs")
df_features = extract_features(df)
print(f"   ✓ Extracted {df_features.shape[1]} features")

print("\n[3/5] Preparing data...")
X_train, X_test, y_train, y_test = prepare_data(df_features)
print(f"   ✓ Training: {len(X_train)}, Testing: {len(X_test)}")

print("\n[4/5] Training models...")
print("\n   Training Decision Tree...")
dt_model = train_decision_tree(X_train, y_train)
print("\n   Training XGBoost...")
xgb_model = train_xgboost(X_train, y_train)

print("\n[5/5] Evaluating models...")
print("\n" + "=" * 70)
print("DECISION TREE RESULTS")
print("=" * 70)
evaluate_model(dt_model, X_test, y_test, "Decision Tree")

print("\n" + "=" * 70)
print("XGBOOST RESULTS")
print("=" * 70)
evaluate_model(xgb_model, X_test, y_test, "XGBoost")

print("\n" + "=" * 70)
print("✅ TRAINING COMPLETED SUCCESSFULLY!")
print("=" * 70)
print("Models saved to: models/")
