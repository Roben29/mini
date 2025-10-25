from src.ensemble_predictor import get_ensemble_prediction

# Test URLs
test_cases = [
    ("https://www.google.com", "Safe"),
    ("https://www.microsoft.com", "Safe"),
    ("https://www.amazon.com", "Safe"),
    ("https://github.com", "Safe"),
    ("http://paypal-verify.tk", "Phishing"),
    ("http://secure-banking.ml", "Phishing"),
]

print("\n" + "="*70)
print("TESTING ENSEMBLE PREDICTOR")
print("="*70 + "\n")

correct = 0
total = len(test_cases)

for url, expected in test_cases:
    result = get_ensemble_prediction(url)
    prediction = result['ensemble_prediction']
    confidence = result['ensemble_confidence']
    
    is_correct = (prediction.lower() == expected.lower())
    if is_correct:
        correct += 1
        status = "✓ CORRECT"
    else:
        status = "✗ WRONG"
    
    print(f"{status} | {url}")
    print(f"  Expected: {expected} | Got: {prediction} ({confidence:.1f}%)")
    print()

print("="*70)
print(f"Accuracy: {correct}/{total} = {(correct/total)*100:.1f}%")
print("="*70)
