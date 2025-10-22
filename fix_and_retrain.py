"""
Fix the corrupted dataset and retrain models with correct data
"""
import pandas as pd
import os

print("\n" + "=" * 70)
print("  FIXING DATASET AND RETRAINING MODELS")
print("=" * 70 + "\n")

# Create a proper balanced dataset with REAL URLs
print("[1/3] Creating proper dataset with real URLs...")

legitimate_urls = [
    'https://www.google.com',
    'https://www.facebook.com',
    'https://www.amazon.com',
    'https://www.microsoft.com',
    'https://www.github.com',
    'https://www.stackoverflow.com',
    'https://www.youtube.com',
    'https://www.linkedin.com',
    'https://www.twitter.com',
    'https://www.netflix.com',
    'https://www.apple.com',
    'https://www.reddit.com',
    'https://www.wikipedia.org',
    'https://www.instagram.com',
    'https://www.dropbox.com',
    'https://www.spotify.com',
    'https://www.adobe.com',
    'https://www.ibm.com',
    'https://www.oracle.com',
    'https://www.salesforce.com',
    'https://www.slack.com',
    'https://www.zoom.us',
    'https://www.docker.com',
    'https://www.python.org',
    'https://www.nodejs.org',
    'https://www.mozilla.org',
    'https://www.wordpress.org',
    'https://www.medium.com',
    'https://www.kaggle.com',
    'https://www.coursera.org',
    'https://www.udemy.com',
    'https://www.edx.org',
    'https://www.cnn.com',
    'https://www.bbc.com',
    'https://www.nytimes.com',
    'https://www.yahoo.com',
    'https://www.bing.com',
    'https://www.paypal.com',
    'https://www.ebay.com',
    'https://www.walmart.com',
    'https://www.target.com',
    'https://www.bestbuy.com',
    'https://www.nike.com',
    'https://www.adidas.com',
    'https://www.chase.com',
    'https://www.wellsfargo.com',
    'https://www.bankofamerica.com',
    'https://www.citibank.com',
    'https://www.capitalone.com',
    'https://www.americanexpress.com',
]

phishing_urls = [
    'http://paypal-secure.com-verify.tk',
    'http://accounts-google.web.app',
    'http://secure-login-paypal.000webhostapp.com',
    'http://apple-id-verify.netlify.app',
    'http://amazon-security-alert.wixsite.com',
    'http://microsoft-account-recovery.weebly.com',
    'http://facebook-security-checkpoint.blogspot.com',
    'http://netflix-payment-update.github.io',
    'http://ebay-suspended-account.wordpress.com',
    'http://bank-verification-required.site',
    'http://dhl-delivery-confirmation.ml',
    'http://fedex-package-tracking.tk',
    'http://usps-redelivery-schedule.cf',
    'http://irs-tax-refund-claim.ga',
    'http://social-security-benefits.gq',
    'http://paypal-limitation-resolve.000webhostapp.com',
    'http://apple-icloud-locked.netlify.app',
    'http://google-account-suspended.web.app',
    'http://microsoft-office-expired.weebly.com',
    'http://amazon-prime-renewal.wixsite.com',
    'http://wellsfargo-alert-fraud.blogspot.com',
    'http://chase-security-alert.github.io',
    'http://bankofamerica-verify.wordpress.com',
    'http://citibank-confirmation.site',
    'http://capitalone-fraud-alert.ml',
    'http://americanexpress-verify.tk',
    'http://walmart-giftcard-winner.cf',
    'http://target-survey-reward.ga',
    'http://bestbuy-prize-claim.gq',
    'http://ups-delivery-failed.000webhostapp.com',
    'http://cryptocurrency-wallet-verification.netlify.app',
    'http://instagram-copyright-violation.web.app',
    'http://linkedin-profile-suspended.weebly.com',
    'http://twitter-account-locked.wixsite.com',
    'http://dropbox-storage-full.blogspot.com',
    'http://adobe-license-expired.github.io',
    'http://spotify-premium-free.wordpress.com',
    'http://zoom-meeting-verification.site',
    'http://whatsapp-account-expired.ml',
    'http://telegram-verify-account.tk',
    'http://tiktok-copyright-claim.cf',
    'http://snapchat-account-recovery.ga',
    'http://discord-nitro-free.gq',
    'http://steam-account-suspended.000webhostapp.com',
    'http://playstation-network-verify.netlify.app',
    'http://xbox-live-suspended.web.app',
    'http://epic-games-security.weebly.com',
    'http://fortnite-vbucks-free.wixsite.com',
    'http://roblox-free-robux.blogspot.com',
    'http://minecraft-account-verify.github.io',
]

# Create balanced dataset
data = {
    'url': legitimate_urls + phishing_urls,
    'label': [0] * len(legitimate_urls) + [1] * len(phishing_urls)
}

df = pd.DataFrame(data)

print(f"   ✓ Created dataset with {len(df)} URLs")
print(f"   ✓ Legitimate URLs: {len(legitimate_urls)}")
print(f"   ✓ Phishing URLs: {len(phishing_urls)}")

# Save the corrected dataset
os.makedirs('data', exist_ok=True)
df.to_csv('data/urls.csv', index=False)

# Remove the corrupted sampled file
if os.path.exists('data/urls_sampled.csv'):
    os.remove('data/urls_sampled.csv')
    print("   ✓ Removed corrupted urls_sampled.csv")

print("   ✓ Saved corrected dataset to data/urls.csv")

# Remove old corrupted models
print("\n[2/3] Removing old corrupted models...")
if os.path.exists('models/dt_model.pkl'):
    os.remove('models/dt_model.pkl')
    print("   ✓ Removed old dt_model.pkl")
if os.path.exists('models/xgb_model.pkl'):
    os.remove('models/xgb_model.pkl')
    print("   ✓ Removed old xgb_model.pkl")
if os.path.exists('models/feature_names.pkl'):
    os.remove('models/feature_names.pkl')
    print("   ✓ Removed old feature_names.pkl")
if os.path.exists('models/feature_stats.pkl'):
    os.remove('models/feature_stats.pkl')
    print("   ✓ Removed old feature_stats.pkl")

print("\n[3/3] Ready to retrain with corrected data!")
print("\n" + "=" * 70)
print("  DATASET FIXED!")
print("=" * 70)
print("\nNow run the training:")
print("  python -m src.main")
print("\n" + "=" * 70)
