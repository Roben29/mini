import pandas as pd
import os

def load_dataset():
    # Try to load sampled dataset first (for production training with real security checks)
    if os.path.exists('data/urls_sampled.csv'):
        print("Loading sampled dataset for production training...")
        df = pd.read_csv('data/urls_sampled.csv')
        print(f"Dataset loaded: {len(df)} URLs, {(df['label']==0).sum()} legitimate, {(df['label']==1).sum()} phishing")
        return df
    
    # Fall back to full dataset
    if not os.path.exists('data/urls.csv'):
        # Create a larger, balanced sample dataset
        sample_data = {
            'url': [
                # Legitimate URLs (0)
                'http://www.google.com',
                'https://www.facebook.com',  
                'https://amazon.com',
                'https://www.microsoft.com',
                'https://www.github.com',
                'https://stackoverflow.com',
                'https://www.youtube.com',
                'https://www.linkedin.com',
                'https://www.twitter.com',
                'https://www.netflix.com',
                'https://www.apple.com',
                'https://www.reddit.com',
                'https://www.wikipedia.org',
                'https://www.instagram.com',
                'https://www.dropbox.com',
                
                # Phishing URLs (1)
                'https://secure-bank-login.fake.com',
                'http://paypal-verification.scam.net',
                'http://phishing-site.malicious.org',
                'http://fake-paypal.suspicious.org',
                'https://amazon-security.phish.net',
                'http://microsoft-login.scam.com',
                'https://facebook-verify.fake.org',
                'http://google-secure.malicious.net',
                'https://apple-id.phishing.com',
                'http://netflix-update.scam.org',
                'https://linkedin-security.fake.com',
                'http://twitter-verify.malicious.org',
                'https://instagram-login.phish.net',
                'http://dropbox-security.scam.com',
                'https://github-verify.fake.org'
            ],
            'label': [
                # 15 legitimate (0)
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                # 15 phishing (1) 
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
            ]
        }
        df = pd.DataFrame(sample_data)
        os.makedirs('data', exist_ok=True)
        df.to_csv('data/urls.csv', index=False)
        print("Created balanced sample dataset at data/urls.csv")
    
    df = pd.read_csv('data/urls.csv')
    
    # ===== AUTOMATIC LABEL CONVERSION =====
    # Convert text labels to numeric (0 and 1)
    if df['label'].dtype == 'object':  # If labels are text
        print("Converting text labels to numeric...")
        
        # Convert common text labels to 0 and 1
        label_mapping = {
            # Legitimate/Safe labels → 0
            'legitimate': 0,
            'legit': 0,
            'safe': 0,
            'good': 0,
            'benign': 0,
            'normal': 0,
            '0': 0,
            0: 0,
            
            # Phishing/Malicious labels → 1
            'phishing': 1,
            'malicious': 1,
            'bad': 1,
            'malware': 1,
            'defacement': 1,
            'scam': 1,
            'fraud': 1,
            '1': 1,
            1: 1
        }
        
        # Convert to lowercase for case-insensitive matching
        df['label'] = df['label'].astype(str).str.lower().str.strip()
        
        # Map text labels to numbers
        df['label'] = df['label'].map(label_mapping)
        
        # Check for any unmapped labels
        if df['label'].isnull().any():
            unmapped = df[df['label'].isnull()]['label'].unique()
            print(f"⚠️ Warning: Found unmapped labels: {unmapped}")
            print("Setting unmapped labels to 0 (safe) by default")
            df['label'] = df['label'].fillna(0)
        
        # Convert to integer
        df['label'] = df['label'].astype(int)
        print("✅ Label conversion completed!")
    
    print(f"Dataset loaded: {len(df)} URLs, {(df['label']==0).sum()} legitimate, {(df['label']==1).sum()} phishing")
    return df
