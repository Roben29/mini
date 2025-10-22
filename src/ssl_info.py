import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

def get_ssl_info(url):
    try:
        domain = urlparse(url).netloc
        if not domain:
            return None, None
        
        port = 443
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_before = cert.get('notBefore')
                not_after = cert.get('notAfter')
                return not_before, not_after
    except Exception:
        return None, None

def ssl_validity_days(url):
    not_before, not_after = get_ssl_info(url)
    try:
        if not_before is None or not_after is None:
            return -1
        
        fmt = '%b %d %H:%M:%S %Y %Z'
        nb = datetime.strptime(not_before, fmt)
        na = datetime.strptime(not_after, fmt)
        return max(0, (na - nb).days)  # Ensure non-negative
    except Exception:
        return -1
