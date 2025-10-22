

IMPORTANT NOTES:
================

✓ INSTALL_REQUIREMENTS.bat must run on BOTH computers
✓ Only train ONCE at home (takes 2-7 hours)
✓ Copy ALL 4 model files (not just 1 or 2)
✓ RUN_AT_COLLEGE.bat runs FULL system, not demo
✓ No internet needed at college (models pre-trained)
✓ Can run detector unlimited times
✓ 85-92% accuracy is GOOD (100% = overfitting)


FILES STRUCTURE:
================

BAT file\                    (You are here)
  ├─ INSTALL_REQUIREMENTS.bat
  ├─ TRAIN_AT_HOME.bat
  ├─ CHECK_MODELS.bat
  ├─ RUN_AT_COLLEGE.bat
  └─ README.txt             (This file)

..\data\
  ├─ urls.csv              (99,474 URLs - full dataset)
  └─ urls_sampled.csv      (5,000 URLs - training subset)

..\models\                  (Model files go here)
  ├─ dt_model.pkl
  ├─ xgb_model.pkl
  ├─ feature_names.pkl
  └─ feature_stats.pkl

..\src\                     (Python source code)
  ├─ main.py               (GUI application)
  ├─ model_training.py     (Training pipeline)
  ├─ feature_extraction.py (79 features)
  └─ url_checker.py        (Detection logic)


EXECUTION SUMMARY:
==================

HOME:
  1. Run: INSTALL_REQUIREMENTS.bat
  2. Run: TRAIN_AT_HOME.bat (wait 2-7 hrs)
  3. Copy 4 files to USB

COLLEGE:
  1. Run: INSTALL_REQUIREMENTS.bat
  2. Paste 4 files from USB
  3. Run: RUN_AT_COLLEGE.bat
  4. Demo to teacher!


========================================
 GOOD LUCK WITH YOUR DEMONSTRATION!
========================================

For more details, see text files in main folder:
  - EXECUTION_ORDER.txt
  - INSTRUCTIONS.txt
  - QUICK_START.txt
