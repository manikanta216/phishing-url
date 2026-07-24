import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = ['login', 'verify', 'secure', 'account', 'update', 'banking', 'signin', 'confirm', 'password', 'webscr', 'cmd']

def extract_features(url):
    """
    Extracts features from a given URL string for ML classification.
    Returns a dictionary of features.
    """
    if not url.startswith(('http://', 'https://')):
        url_for_parse = 'http://' + url
    else:
        url_for_parse = url

    parsed = urlparse(url_for_parse)
    domain = parsed.netloc

    # 1. URL length
    url_length = len(url)

    # 2. Presence of '@' symbol
    has_at_symbol = 1 if '@' in url else 0

    # 3. Presence of '-' in domain
    has_hyphen_in_domain = 1 if '-' in domain else 0

    # 4. Number of subdomains
    # Split domain by dot, exclude empty strings
    domain_parts = [p for p in domain.split('.') if p]
    # If standard domain like example.com -> 2 parts, subdomain count = 0
    # sub.example.com -> 3 parts, subdomain count = 1
    subdomain_count = max(0, len(domain_parts) - 2) if len(domain_parts) >= 2 else 0

    # 5. Whether it uses HTTPS
    is_https = 1 if url.lower().startswith('https://') else 0

    # 6. Whether the domain is an IP address
    # Match IPv4 pattern
    ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    # Remove port if present
    domain_no_port = domain.split(':')[0]
    is_ip_address = 1 if re.match(ip_pattern, domain_no_port) else 0

    # 7. Number of digits in URL
    digit_count = sum(c.isdigit() for c in url)

    # 8. Presence of suspicious words
    url_lower = url.lower()
    suspicious_word_count = sum(1 for word in SUSPICIOUS_WORDS if word in url_lower)

    # 9. URL depth (number of '/' after domain)
    path = parsed.path
    url_depth = len([p for p in path.split('/') if p])

    return {
        'url_length': url_length,
        'has_at_symbol': has_at_symbol,
        'has_hyphen_in_domain': has_hyphen_in_domain,
        'subdomain_count': subdomain_count,
        'is_https': is_https,
        'is_ip_address': is_ip_address,
        'digit_count': digit_count,
        'suspicious_word_count': suspicious_word_count,
        'url_depth': url_depth
    }
