import socket

try:
    from ipwhois import IPWhois
    IPWHOIS_AVAILABLE = True
except ImportError:
    IPWHOIS_AVAILABLE = False

def get_hosting_info(url):
    if not IPWHOIS_AVAILABLE:
        return None, None, None
        
    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        if not domain:
            return None, None, None
            
        ip = socket.gethostbyname(domain)
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)
        asn = res.get('asn', None)
        asn_org = res.get('asn_description', None)
        return ip, asn, asn_org
    except Exception:
        return None, None, None
