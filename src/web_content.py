import requests
from bs4 import BeautifulSoup

def fetch_page_features(url):
    try:
        response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        content = response.text
        soup = BeautifulSoup(content, 'html.parser')
        
        num_forms = len(soup.find_all('form'))
        num_scripts = len(soup.find_all('script'))
        has_login_input = bool(soup.find('input', {'type': 'password'}))
        
        return {
            'num_forms': num_forms,
            'num_scripts': num_scripts,
            'has_login_input': int(has_login_input)
        }
    except Exception:
        return {
            'num_forms': 0,
            'num_scripts': 0,
            'has_login_input': 0
        }
