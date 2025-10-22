"""
Clean Project - Remove Cache and Temporary Files
=================================================
Clears all cache, old models, and temporary files for fresh start.
"""

import os
import shutil

def clean_project():
    print("\n" + "="*70)
    print("  CLEANING PROJECT - REMOVING CACHE AND TEMP FILES")
    print("="*70 + "\n")
    
    cleaned = []
    errors = []
    
    # Directories to clean
    dirs_to_remove = [
        'src/__pycache__',
        '__pycache__',
        '.pytest_cache',
        'temp_tranco',
        'temp_umbrella',
    ]
    
    # Files to clean
    files_to_remove = [
        'temp_tranco.zip',
        'temp_umbrella.zip',
    ]
    
    # Clean __pycache__ directories
    print("[1/4] Removing __pycache__ directories...")
    for root, dirs, files in os.walk('.'):
        for dir in dirs:
            if dir == '__pycache__':
                path = os.path.join(root, dir)
                try:
                    shutil.rmtree(path)
                    cleaned.append(path)
                    print(f"   ✓ Removed: {path}")
                except Exception as e:
                    errors.append((path, str(e)))
                    print(f"   ✗ Failed: {path} - {e}")
    
    # Clean old models (we'll retrain with new features)
    print("\n[2/4] Removing old trained models...")
    if os.path.exists('models'):
        model_files = [
            'models/dt_model.pkl',
            'models/xgb_model.pkl',
            'models/feature_names.pkl',
            'models/feature_stats.pkl',
            'models/scaler.pkl',
        ]
        
        for file in model_files:
            if os.path.exists(file):
                try:
                    os.remove(file)
                    cleaned.append(file)
                    print(f"   ✓ Removed: {file}")
                except Exception as e:
                    errors.append((file, str(e)))
                    print(f"   ✗ Failed: {file} - {e}")
    
    # Clean temporary directories
    print("\n[3/4] Removing temporary directories...")
    for dir_path in dirs_to_remove:
        if os.path.exists(dir_path):
            try:
                shutil.rmtree(dir_path)
                cleaned.append(dir_path)
                print(f"   ✓ Removed: {dir_path}")
            except Exception as e:
                errors.append((dir_path, str(e)))
                print(f"   ✗ Failed: {dir_path} - {e}")
    
    # Clean temporary files
    print("\n[4/4] Removing temporary files...")
    for file_path in files_to_remove:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                cleaned.append(file_path)
                print(f"   ✓ Removed: {file_path}")
            except Exception as e:
                errors.append((file_path, str(e)))
                print(f"   ✗ Failed: {file_path} - {e}")
    
    # Summary
    print("\n" + "="*70)
    print("  ✅ CLEANUP COMPLETE")
    print("="*70)
    print(f"\nCleaned items: {len(cleaned)}")
    
    if errors:
        print(f"Errors: {len(errors)}")
        print("\nFailed to clean:")
        for path, error in errors:
            print(f"  • {path}: {error}")
    else:
        print("No errors!")
    
    print("\n" + "="*70)
    print("Project is clean and ready for fresh training!")
    print("="*70 + "\n")
    
    print("Next steps:")
    print("  1. Sample dataset: python sample_dataset.py")
    print("  2. Train models: TRAIN_MODELS.bat")
    print("  3. Test predictions: python quick_test.py\n")

if __name__ == "__main__":
    try:
        clean_project()
    except KeyboardInterrupt:
        print("\n\n⚠ Cleanup interrupted by user\n")
    except Exception as e:
        print(f"\n\n❌ Cleanup error: {e}\n")
        import traceback
        traceback.print_exc()
