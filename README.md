# 🛡️ Malicious URL Detector 2025

A machine learning-based phishing detection system that analyzes URLs to identify potential malicious websites.

## 📊 Dataset

- **Legitimate URLs**: 10,000 samples
- **Phishing URLs**: 10,000 samples
- **Total**: 20,000 balanced URLs for training

## 🚀 Quick Start

### Local Training

1. **Install Dependencies**
```bash
pip install -r requirements.txt
```

2. **Train the Models**
```bash
python -m src.main
```

3. **Run the GUI**
```bash
python -m src.gui
```

### Training on Deepnote

1. Go to [Deepnote](https://deepnote.com)
2. Import this repository
3. Open `train_on_deepnote.ipynb`
4. Run all cells
5. Download trained models

## 🧠 Models

- **Decision Tree**: Fast, interpretable baseline model
- **XGBoost**: Advanced gradient boosting for better accuracy

## 📁 Project Structure

```
├── data/                      # Dataset files
│   ├── legimate.csv          # 10k legitimate URLs
│   └── malicious.csv         # 10k phishing URLs
├── src/                       # Source code
│   ├── main.py               # Training pipeline
│   ├── gui.py                # GUI application
│   ├── feature_extraction.py # 79 feature extractors
│   ├── model_training.py     # Model training
│   └── url_checker.py        # URL validation
├── models/                    # Trained models (generated)
├── balance_to_10k.py         # Dataset balancing script
├── train_on_deepnote.ipynb   # Deepnote training notebook
└── requirements.txt          # Python dependencies

```

## 🎯 Features Extracted

The system extracts **79 features** from each URL:
- URL structure (length, special characters, etc.)
- Domain information (age, registration, DNS)
- Security indicators (HTTPS, certificates)
- Content analysis (HTML, redirects)

## 📈 Expected Performance

- **Accuracy**: 85-95%
- **Training Time**: 45-70 minutes (on Deepnote)
- **Prediction Time**: < 1 second per URL

## 🔧 Utility Scripts

- `balance_to_10k.py` - Balance dataset to 10k each class

## 📦 Requirements

- Python 3.8+
- pandas, numpy, scikit-learn
- xgboost, joblib
- requests, beautifulsoup4
- python-whois, dnspython

## 📝 License

Educational project for malicious URL detection research.

## 👨‍💻 Author

Roben29

---

**⚠️ Note**: This is a research/educational project. For production use, consider additional security measures and regular model updates.
