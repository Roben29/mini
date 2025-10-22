import os
import sys
import time
from datetime import datetime
from .data_collection import load_dataset
from .feature_extraction import extract_features
from .preprocessing import prepare_data
from .model_training import train_decision_tree, train_xgboost
from .evaluation import evaluate_model

def check_models_exist():
    """Check if trained models already exist"""
    dt_path = 'models/dt_model.pkl'
    xgb_path = 'models/xgb_model.pkl'
    
    dt_exists = os.path.exists(dt_path)
    xgb_exists = os.path.exists(xgb_path)
    
    if dt_exists and xgb_exists:
        try:
            # Get model file timestamps
            dt_time = datetime.fromtimestamp(os.path.getmtime(dt_path))
            xgb_time = datetime.fromtimestamp(os.path.getmtime(xgb_path))
            return True, dt_time, xgb_time
        except Exception:
            return False, None, None
    
    return False, None, None

def run(force_retrain=False):
    """
    Run the training pipeline
    
    Args:
        force_retrain (bool): If True, retrain models even if they exist
    """
    print("\n" + "=" * 70)
    print("  PHISHING URL DETECTION - MODEL TRAINING")
    print("=" * 70 + "\n")
    
    try:
        # Check if models already exist
        models_exist, dt_time, xgb_time = check_models_exist()
        
        if models_exist and not force_retrain:
            print("✓ Models already exist!")
            print(f"  Decision Tree: trained on {dt_time.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  XGBoost:       trained on {xgb_time.strftime('%Y-%m-%d %H:%M:%S')}")
            print("\n" + "-" * 70)
            print("Options:")
            print("  1. Skip training (use existing models)")
            print("  2. Retrain models (overwrite existing)")
            print("-" * 70)
            
            choice = input("\nEnter choice (1-2, default=1): ").strip()
            
            if choice != '2':
                print("\n✓ Using existing models")
                print("  Models are ready for predictions!")
                print("\n" + "=" * 70)
                print("  To use the models:")
                print("  • Launch GUI:  python -m src.gui")
                print("  • Or run:      run_gui.bat")
                print("=" * 70 + "\n")
                return True
            else:
                print("\n⚠ Retraining models (this will overwrite existing models)...")
        
        # Start timing
        start_time = time.time()
        
        # Load dataset
        print("[Step 1/6] Loading dataset...")
        step_start = time.time()
        try:
            df = load_dataset()
            step_time = time.time() - step_start
            print(f"           ✓ Loaded {len(df)} URLs ({step_time:.2f}s)")
            
            if len(df) < 10:
                print("\n⚠ WARNING: Very small dataset detected!")
                print("  For better accuracy, use at least 1,000 URLs")
                print("  Run: python download_dataset.py")
                
        except FileNotFoundError:
            print("\n✗ ERROR: Dataset file not found!")
            print("  Expected: data/urls.csv")
            print("\n  Solutions:")
            print("  1. Place verified_online.csv in project root")
            print("  2. Run: convert_dataset.bat")
            print("  3. Or run: python download_dataset.py")
            return False
        except Exception as e:
            print(f"\n✗ ERROR loading dataset: {str(e)}")
            return False
        
        # Extract features
        print("\n[Step 2/6] Extracting features...")
        step_start = time.time()
        try:
            df = extract_features(df)
            step_time = time.time() - step_start
            feature_count = len([col for col in df.columns if col not in ['url', 'label']])
            print(f"           ✓ Extracted {feature_count} features per URL ({step_time:.2f}s)")
        except Exception as e:
            print(f"\n✗ ERROR extracting features: {str(e)}")
            return False
        
        # Prepare data
        print("\n[Step 3/6] Preparing training and test sets...")
        step_start = time.time()
        try:
            X_train, X_test, y_train, y_test = prepare_data(df)
            step_time = time.time() - step_start
            print(f"           ✓ Training set: {len(X_train)} samples")
            print(f"           ✓ Test set:     {len(X_test)} samples")
            
            # Check class balance
            phishing_train = sum(y_train)
            legit_train = len(y_train) - phishing_train
            print(f"           ✓ Balance: {phishing_train} phishing, {legit_train} legitimate ({step_time:.2f}s)")
            
        except Exception as e:
            print(f"\n✗ ERROR preparing data: {str(e)}")
            return False
        
        # Create models directory
        os.makedirs('models', exist_ok=True)
        
        # Train Decision Tree
        print("\n[Step 4/6] Training Decision Tree model...")
        print("           (Using optimized parameters...)")
        step_start = time.time()
        try:
            dt_model = train_decision_tree(X_train, y_train)
            dt_metrics = evaluate_model(dt_model, X_test, y_test)
            step_time = time.time() - step_start
            
            print(f"           ✓ Training complete! ({step_time:.2f}s)")
            print(f"           ✓ Accuracy:  {dt_metrics['accuracy']:.2%}")
            print(f"           ✓ Precision: {dt_metrics['precision']:.2%}")
            print(f"           ✓ Recall:    {dt_metrics['recall']:.2%}")
            print(f"           ✓ F1-Score:  {dt_metrics['f1']:.2%}")
            
        except Exception as e:
            print(f"\n✗ ERROR training Decision Tree: {str(e)}")
            return False
        
        # Train XGBoost
        print("\n[Step 5/6] Training XGBoost model...")
        print("           (Using gradient boosting...)")
        step_start = time.time()
        try:
            xgb_model = train_xgboost(X_train, y_train)
            xgb_metrics = evaluate_model(xgb_model, X_test, y_test)
            step_time = time.time() - step_start
            
            print(f"           ✓ Training complete! ({step_time:.2f}s)")
            print(f"           ✓ Accuracy:  {xgb_metrics['accuracy']:.2%}")
            print(f"           ✓ Precision: {xgb_metrics['precision']:.2%}")
            print(f"           ✓ Recall:    {xgb_metrics['recall']:.2%}")
            print(f"           ✓ F1-Score:  {xgb_metrics['f1']:.2%}")
            
        except Exception as e:
            print(f"\n✗ ERROR training XGBoost: {str(e)}")
            return False
        
        # Summary
        print("\n[Step 6/6] Saving models...")
        print(f"           ✓ Saved: models/dt_model.pkl")
        print(f"           ✓ Saved: models/xgb_model.pkl")
        
        total_time = time.time() - start_time
        minutes = int(total_time // 60)
        seconds = int(total_time % 60)
        
        print("\n" + "=" * 70)
        print("  TRAINING COMPLETED SUCCESSFULLY!")
        print(f"  Total Time: {minutes}m {seconds}s")
        print("=" * 70)
        
        print("\nModel Performance Summary:")
        print("-" * 70)
        print(f"  Decision Tree - Accuracy: {dt_metrics['accuracy']:.2%} | F1: {dt_metrics['f1']:.2%}")
        print(f"  XGBoost       - Accuracy: {xgb_metrics['accuracy']:.2%} | F1: {xgb_metrics['f1']:.2%}")
        print("-" * 70)
        
        print("\n" + "=" * 70)
        print("  NEXT STEPS:")
        print("=" * 70)
        print("  Launch GUI:")
        print("    • python -m src.gui")
        print("    • OR run_gui.bat")
        print("\n  Check a URL:")
        print("    • from src.url_checker import check_url")
        print("    • result = check_url('http://example.com')")
        print("=" * 70 + "\n")
        
        return True
        
    except KeyboardInterrupt:
        print("\n\n⚠ Training interrupted by user")
        return False
    except Exception as e:
        print(f"\n\n✗ UNEXPECTED ERROR: {str(e)}")
        print(f"   Error type: {type(e).__name__}")
        import traceback
        print("\nTraceback:")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    # Check for command line arguments
    force = '--force' in sys.argv or '-f' in sys.argv
    success = run(force_retrain=force)
    
    if not success:
        sys.exit(1)
