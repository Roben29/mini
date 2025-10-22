try:
    import whois
except ImportError:
    try:
        from pythonwhois import net as whois
    except ImportError:
        whois = None

import datetime

def get_domain_from_url(url):
    try:
        from urllib.parse import urlparse
        netloc = urlparse(url).netloc
        return netloc.lower()
    except Exception:
        return ""

def get_domain_age(url):
    domain = get_domain_from_url(url)
    if not domain or whois is None:
        return -1
    
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date if hasattr(w, 'creation_date') else None
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return -1
        age_days = (datetime.datetime.now() - creation_date).days
        return max(0, age_days)  # Ensure non-negative
    except Exception:
        return -1
