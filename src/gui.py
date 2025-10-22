import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import pandas as pd
import os

class UrlCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing URL Detector - ML Powered")
        self.root.geometry("900x700")
        self.root.resizable(False, False)
        
        # Color scheme
        self.colors = {
            'bg': '#f0f0f0',
            'primary': '#2196F3',
            'danger': '#f44336',
            'success': '#4CAF50',
            'warning': '#FF9800',
            'safe': '#4CAF50',
            'phishing': '#f44336'
        }
        
        self.root.configure(bg=self.colors['bg'])
        
        # Header Frame
        header_frame = tk.Frame(root, bg=self.colors['primary'], height=80)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(header_frame, text="Phishing URL Detector", 
                              font=("Segoe UI", 22, "bold"), 
                              bg=self.colors['primary'], fg="white")
        title_label.pack(pady=15)
        
        subtitle_label = tk.Label(header_frame, 
                                 text="Machine Learning-Based URL Security Analysis", 
                                 font=("Segoe UI", 10), 
                                 bg=self.colors['primary'], fg="white")
        subtitle_label.pack()

        
        # Main Container
        main_container = tk.Frame(root, bg=self.colors['bg'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Input Section
        input_frame = tk.LabelFrame(main_container, text=" Enter URL to Analyze ", 
                                   font=("Arial", 11, "bold"), 
                                   bg=self.colors['bg'], padx=10, pady=10)
        input_frame.pack(fill=tk.X, pady=(0, 15))
        
        # URL Entry with example
        url_container = tk.Frame(input_frame, bg=self.colors['bg'])
        url_container.pack(fill=tk.X)
        
        self.url_entry = tk.Entry(url_container, font=("Segoe UI", 12), 
                                 relief=tk.SOLID, bd=1)
        self.url_entry.pack(fill=tk.X, pady=5)
        self.url_entry.insert(0, "https://")
        
        example_label = tk.Label(url_container, 
                               text="Example: https://www.google.com or paypal-verify.suspicious.com", 
                               font=("Segoe UI", 9, "italic"), 
                               bg=self.colors['bg'], fg="gray")
        example_label.pack(anchor="w")
        
        # Buttons
        button_frame = tk.Frame(input_frame, bg=self.colors['bg'])
        button_frame.pack(pady=10)
        
        self.check_button = tk.Button(button_frame, text="Analyze URL", 
                                     font=("Segoe UI", 12, "bold"), 
                                     bg=self.colors['primary'], fg="white",
                                     padx=20, pady=8, cursor="hand2",
                                     relief=tk.RAISED, bd=2,
                                     command=self.check_url)
        self.check_button.grid(row=0, column=0, padx=5)
        
        self.clear_button = tk.Button(button_frame, text="Clear", 
                                     font=("Segoe UI", 12), 
                                     bg=self.colors['danger'], fg="white",
                                     padx=20, pady=8, cursor="hand2",
                                     relief=tk.RAISED, bd=2,
                                     command=self.clear_results)
        self.clear_button.grid(row=0, column=1, padx=5)

        
        # Results Section with Notebook (Tabs)
        results_frame = tk.LabelFrame(main_container, text=" Analysis Results ", 
                                     font=("Segoe UI", 11, "bold"), 
                                     bg=self.colors['bg'], padx=10, pady=10)
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create Notebook for tabs
        self.notebook = ttk.Notebook(results_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Tab 1: Prediction Results
        prediction_tab = tk.Frame(self.notebook, bg="white")
        self.notebook.add(prediction_tab, text="  Prediction  ")
        
        self.prediction_text = scrolledtext.ScrolledText(prediction_tab, 
                                                        font=("Consolas", 10),
                                                        bg="white", relief=tk.FLAT,
                                                        wrap=tk.WORD)
        self.prediction_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tab 2: Feature Details
        features_tab = tk.Frame(self.notebook, bg="white")
        self.notebook.add(features_tab, text="  Features  ")
        
        self.features_text = scrolledtext.ScrolledText(features_tab, 
                                                      font=("Consolas", 9),
                                                      bg="white", relief=tk.FLAT,
                                                      wrap=tk.WORD)
        self.features_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tab 3: About
        about_tab = tk.Frame(self.notebook, bg="white")
        self.notebook.add(about_tab, text="  About  ")
        
        about_text = scrolledtext.ScrolledText(about_tab, 
                                              font=("Segoe UI", 10),
                                              bg="white", relief=tk.FLAT,
                                              wrap=tk.WORD)
        about_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        about_content = """
Phishing URL Detector
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ABOUT THIS APPLICATION:
This machine learning-powered tool analyzes URLs to detect potential 
phishing websites and malicious links.

MACHINE LEARNING MODELS:
• Decision Tree Classifier (85% accuracy)
• XGBoost Classifier (92% accuracy)

FEATURES ANALYZED (25+):
• URL Structure: length, depth, special characters
• Protocol: HTTPS detection
• Suspicious Keywords: login, verify, account, update, etc.
• IP Address Detection
• Domain Analysis

HOW IT WORKS:
1. Enter a URL in the input field
2. Click "Analyze URL" to start analysis
3. View prediction results and confidence levels
4. Check extracted features for details

INTERPRETATION:
• Green (SAFE): URL appears legitimate
• Red (PHISHING): URL shows suspicious patterns
• Both models agree = higher confidence
• Models disagree = exercise caution

DATASET:
Trained on balanced dataset of legitimate and phishing URLs
with 70-30 train-test split for optimal performance.

ACCURACY:
• Decision Tree: ~85%
• XGBoost: ~92%
• Combined: Enhanced reliability

DEVELOPERS:
Built using Python, scikit-learn, XGBoost, and Tkinter
For educational and security awareness purposes.

DISCLAIMER:
This tool provides analysis based on ML models. Always verify
suspicious URLs through official channels and use antivirus software.
"""
        about_text.insert(1.0, about_content)
        about_text.config(state=tk.DISABLED)

        
        # Status Bar
        status_container = tk.Frame(root, bg="white", relief=tk.SUNKEN, bd=1)
        status_container.pack(side=tk.BOTTOM, fill=tk.X)
        
        if os.path.exists('models/dt_model.pkl') and os.path.exists('models/xgb_model.pkl'):
            self.models_available = True
            status_text = "Models Loaded | Decision Tree + XGBoost Ready"
            status_color = self.colors['success']
        else:
            self.models_available = False
            status_text = "Models Not Found | Please run: python -m src.main"
            status_color = self.colors['danger']
            
        self.status_label = tk.Label(status_container, text=status_text, 
                                    font=("Segoe UI", 9), fg=status_color, 
                                    bg="white", anchor="w")
        self.status_label.pack(side=tk.LEFT, padx=10, pady=3)
        
        # Version info
        version_label = tk.Label(status_container, text="v1.0", 
                               font=("Segoe UI", 9), fg="gray", 
                               bg="white", anchor="e")
        version_label.pack(side=tk.RIGHT, padx=10, pady=3)

    def clear_results(self):
        """Clear all input and results"""
        self.prediction_text.delete(1.0, tk.END)
        self.features_text.delete(1.0, tk.END)
        self.url_entry.delete(0, tk.END)
        self.url_entry.insert(0, "https://")
        self.notebook.select(0)  # Switch back to prediction tab


    def check_url(self):
        """Analyze the entered URL and display results"""
        if not self.models_available:
            messagebox.showerror(
                "Models Not Available", 
                "ML models are not loaded!\n\n"
                "Please train the models first:\n\n"
                "Option 1: Run complete setup\n"
                "  • Double-click: run_complete.bat\n\n"
                "Option 2: Train models only\n"
                "  • Run: python -m src.main\n\n"
                "The models will be automatically saved and loaded next time."
            )
            return

        url = self.url_entry.get().strip()
        
        # Validate URL
        if not url or url == "https://" or url == "http://":
            messagebox.showwarning("Input Required", "Please enter a valid URL to analyze.")
            return
        
        # Auto-add protocol if missing
        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'http://' + url
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, url)

        try:
            # Clear previous results
            self.prediction_text.delete(1.0, tk.END)
            self.features_text.delete(1.0, tk.END)
            
            # Show analyzing message
            self.prediction_text.insert(tk.END, "Analyzing URL...\n")
            self.prediction_text.insert(tk.END, f"URL: {url}\n")
            self.prediction_text.insert(tk.END, "━" * 70 + "\n\n")
            self.prediction_text.insert(tk.END, "Please wait...\n")
            self.root.update()
            
            # Import and run analysis
            from .url_checker import check_url
            from .feature_extraction import extract_features
            
            result = check_url(url)
            
            # Check for errors in result
            if 'error' in result:
                error_type = result.get('error_type', 'Unknown')
                error_msg = result['error']
                
                self.prediction_text.delete(1.0, tk.END)
                self.prediction_text.insert(tk.END, "ERROR DURING ANALYSIS\n")
                self.prediction_text.insert(tk.END, "━" * 70 + "\n\n")
                self.prediction_text.insert(tk.END, f"Error Type: {error_type}\n")
                self.prediction_text.insert(tk.END, f"Details: {error_msg}\n\n")
                
                if error_type == 'ModelNotFound':
                    self.prediction_text.insert(tk.END, "Solution:\n")
                    self.prediction_text.insert(tk.END, "• Run: python -m src.main\n")
                    self.prediction_text.insert(tk.END, "• Or double-click: TRAIN_AT_HOME.bat\n")
                elif error_type == 'InvalidInput':
                    self.prediction_text.insert(tk.END, "Solution:\n")
                    self.prediction_text.insert(tk.END, "• Check URL format\n")
                    self.prediction_text.insert(tk.END, "• Example: https://www.example.com\n")
                else:
                    self.prediction_text.insert(tk.END, "Possible causes:\n")
                    self.prediction_text.insert(tk.END, "• Invalid URL format\n")
                    self.prediction_text.insert(tk.END, "• Missing dependencies\n")
                    self.prediction_text.insert(tk.END, "• Models corrupted\n")
                
                messagebox.showerror("Analysis Error", error_msg)
                return
            
            # Clear and display formatted results
            self.prediction_text.delete(1.0, tk.END)
            
            # Header
            self.prediction_text.insert(tk.END, "PHISHING URL DETECTION RESULTS\n")
            self.prediction_text.insert(tk.END, "━" * 70 + "\n\n")
            self.prediction_text.insert(tk.END, f"URL: {url}\n")
            self.prediction_text.insert(tk.END, "━" * 70 + "\n\n")
            
            # Model Predictions
            self.prediction_text.insert(tk.END, "MACHINE LEARNING PREDICTIONS:\n\n")
            
            # Decision Tree
            dt_info = result.get('models', {}).get('decision_tree', {})
            dt_prediction = dt_info.get('prediction', 'unknown')
            dt_probability = dt_info.get('probability', 0) * 100
            dt_label = "[PHISHING DETECTED]" if dt_prediction == 'phishing' else "[APPEARS SAFE]"
            dt_color = self.colors['phishing'] if dt_prediction == 'phishing' else self.colors['safe']
            
            self.prediction_text.insert(tk.END, "┌─ Decision Tree Classifier ─────────────────────\n")
            self.prediction_text.insert(tk.END, f"│ Prediction: {dt_label}\n")
            self.prediction_text.insert(tk.END, f"│ Confidence: {dt_probability:.1f}%\n")
            self.prediction_text.insert(tk.END, f"│ Accuracy: ~85%\n")
            self.prediction_text.insert(tk.END, "└" + "─" * 48 + "\n\n")
            
            # XGBoost
            xgb_info = result.get('models', {}).get('xgboost', {})
            xgb_prediction = xgb_info.get('prediction', 'unknown')
            xgb_probability = xgb_info.get('probability', 0) * 100
            xgb_label = "[PHISHING DETECTED]" if xgb_prediction == 'phishing' else "[APPEARS SAFE]"
            xgb_color = self.colors['phishing'] if xgb_prediction == 'phishing' else self.colors['safe']
            
            self.prediction_text.insert(tk.END, "┌─ XGBoost Classifier ───────────────────────────\n")
            self.prediction_text.insert(tk.END, f"│ Prediction: {xgb_label}\n")
            self.prediction_text.insert(tk.END, f"│ Confidence: {xgb_probability:.1f}%\n")
            self.prediction_text.insert(tk.END, f"│ Accuracy: ~92%\n")
            self.prediction_text.insert(tk.END, "└" + "─" * 48 + "\n\n")
            
            # Overall Assessment
            self.prediction_text.insert(tk.END, "━" * 70 + "\n")
            self.prediction_text.insert(tk.END, "FINAL ASSESSMENT:\n\n")
            
            both_safe = dt_prediction == 'legitimate' and xgb_prediction == 'legitimate'
            both_phishing = dt_prediction == 'phishing' and xgb_prediction == 'phishing'
            disagreement = dt_prediction != xgb_prediction
            
            if both_safe:
                self.prediction_text.insert(tk.END, "VERDICT: URL APPEARS SAFE\n\n")
                self.prediction_text.insert(tk.END, "Both models agree that this URL looks legitimate.\n")
                self.prediction_text.insert(tk.END, "However, always verify important links independently.\n")
            elif both_phishing:
                self.prediction_text.insert(tk.END, "VERDICT: LIKELY PHISHING WEBSITE\n\n")
                self.prediction_text.insert(tk.END, "WARNING: Both models detected suspicious patterns!\n")
                self.prediction_text.insert(tk.END, "• Do NOT enter personal information\n")
                self.prediction_text.insert(tk.END, "• Do NOT download files\n")
                self.prediction_text.insert(tk.END, "• Verify the website through official channels\n")
            else:
                self.prediction_text.insert(tk.END, "VERDICT: MIXED RESULTS - EXERCISE CAUTION\n\n")
                self.prediction_text.insert(tk.END, "Models disagree on classification.\n")
                self.prediction_text.insert(tk.END, "• Be cautious when interacting with this URL\n")
                self.prediction_text.insert(tk.END, "• Verify authenticity before proceeding\n")
                self.prediction_text.insert(tk.END, "• Check for spelling errors in domain name\n")
            
            self.prediction_text.insert(tk.END, "\n" + "━" * 70 + "\n")
            
            # Recommendation
            avg_confidence = (dt_probability + xgb_probability) / 2
            self.prediction_text.insert(tk.END, f"\nAverage Confidence: {avg_confidence:.1f}%\n")
            
            if avg_confidence > 80:
                self.prediction_text.insert(tk.END, "   Models are highly confident in this prediction.\n")
            elif avg_confidence > 60:
                self.prediction_text.insert(tk.END, "   Models show moderate confidence.\n")
            else:
                self.prediction_text.insert(tk.END, "   Models show lower confidence - verify manually.\n")
            
            # Extract and display features
            self.show_features(url)
            
            # Switch to prediction tab
            self.notebook.select(0)
            
        except Exception as e:
            self.prediction_text.delete(1.0, tk.END)
            self.prediction_text.insert(tk.END, "ERROR DURING ANALYSIS\n")
            self.prediction_text.insert(tk.END, "━" * 70 + "\n\n")
            self.prediction_text.insert(tk.END, f"An error occurred: {str(e)}\n\n")
            self.prediction_text.insert(tk.END, "Possible causes:\n")
            self.prediction_text.insert(tk.END, "• Models not trained properly\n")
            self.prediction_text.insert(tk.END, "• Invalid URL format\n")
            self.prediction_text.insert(tk.END, "• Missing dependencies\n\n")
            self.prediction_text.insert(tk.END, "Try running: python -m src.main\n")
            messagebox.showerror("Analysis Error", f"Error: {str(e)}")
    
    def show_features(self, url):
        """Display extracted features in features tab"""
        try:
            from .feature_extraction import extract_features
            
            df = pd.DataFrame([{'url': url, 'label': 0}])
            features_df = extract_features(df)
            feature_cols = [col for col in features_df.columns if col not in ['url', 'label']]
            features = features_df[feature_cols].iloc[0].to_dict()
            
            self.features_text.insert(tk.END, "EXTRACTED FEATURES ANALYSIS\n")
            self.features_text.insert(tk.END, "━" * 70 + "\n\n")
            self.features_text.insert(tk.END, f"URL: {url}\n")
            self.features_text.insert(tk.END, f"Total Features Extracted: {len(features)}\n")
            self.features_text.insert(tk.END, "━" * 70 + "\n\n")
            
            # Categorize features
            structural_features = {}
            keyword_features = {}
            other_features = {}
            
            for key, value in features.items():
                if key.startswith('has_'):
                    keyword_features[key] = value
                elif key in ['url_length', 'num_dots', 'num_hyphens', 'num_underscores', 
                           'num_slashes', 'url_depth', 'has_ip', 'is_https']:
                    structural_features[key] = value
                else:
                    other_features[key] = value
            
            # Display Structural Features
            self.features_text.insert(tk.END, "STRUCTURAL FEATURES:\n")
            self.features_text.insert(tk.END, "─" * 70 + "\n")
            for key, value in structural_features.items():
                formatted_key = key.replace('_', ' ').title()
                self.features_text.insert(tk.END, f"  • {formatted_key:.<35} {value}\n")
            
            # Display Keyword Features
            self.features_text.insert(tk.END, "\nSUSPICIOUS KEYWORD DETECTION:\n")
            self.features_text.insert(tk.END, "─" * 70 + "\n")
            keywords_found = [k.replace('has_', '').title() for k, v in keyword_features.items() if v == 1]
            if keywords_found:
                self.features_text.insert(tk.END, f"  [!] Found: {', '.join(keywords_found)}\n")
            else:
                self.features_text.insert(tk.END, "  [OK] No suspicious keywords detected\n")
            
            # Display all keyword checks
            self.features_text.insert(tk.END, "\n  Keyword Checks:\n")
            for key, value in keyword_features.items():
                keyword = key.replace('has_', '').title()
                status = "[+] Found" if value == 1 else "[-] Not Found"
                self.features_text.insert(tk.END, f"    {keyword:.<30} {status}\n")
            
            # Display Other Features
            if other_features:
                self.features_text.insert(tk.END, "\nADVANCED FEATURES:\n")
                self.features_text.insert(tk.END, "─" * 70 + "\n")
                for key, value in other_features.items():
                    formatted_key = key.replace('_', ' ').title()
                    display_value = value if value not in [-1, None] else "Not Available"
                    self.features_text.insert(tk.END, f"  • {formatted_key:.<35} {display_value}\n")
            
            self.features_text.insert(tk.END, "\n" + "━" * 70 + "\n")
            self.features_text.insert(tk.END, "\nNOTE: These features are analyzed by ML models to detect phishing patterns.\n")
            
        except Exception as e:
            self.features_text.insert(tk.END, f"Error extracting features: {str(e)}\n")

def run_gui():
    root = tk.Tk()
    app = UrlCheckerApp(root)
    root.mainloop()

if __name__ == "__main__":
    run_gui()
