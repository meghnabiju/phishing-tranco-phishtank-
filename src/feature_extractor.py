import re
import socket
import tldextract
from urllib.parse import urlparse

# Known URL shorteners
SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'is.gd', 'shorte.st', 'adf.ly', 'buff.ly', 'rebrand.ly',
    'cutt.ly', 'tiny.cc', 'shorturl.at', 'rb.gy'
}

# Suspicious keywords commonly in phishing URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update',
    'banking', 'confirm', 'password', 'credential', 'paypal',
    'ebay', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    'support', 'helpdesk', 'alert', 'suspended', 'unusual',
    'webscr', 'cmd=', 'redirect', 'checkout', 'wallet'
]


def extract_features(url: str) -> dict:
    """
    Extract all computable features from a URL.
    Returns a dictionary of feature_name: value.
    """
    features = {}

    try:
        parsed = urlparse(url)
        ext = tldextract.extract(url)

        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full_url = url.lower()

        # ── URL Structure Features ──────────────────────────────────────

        # 1. Has IP address as domain
        ip_pattern = re.compile(
            r'^(\d{1,3}\.){3}\d{1,3}$'
        )
        features['has_ip'] = 1 if ip_pattern.match(
            domain.replace('www.', '')
        ) else 0

        # 2. URL total length
        features['url_length'] = len(url)

        # 3. Domain length
        features['domain_length'] = len(domain)

        # 4. Path length
        features['path_length'] = len(path)

        # 5. Is URL shortener
        features['is_shortener'] = 1 if any(
            s in domain for s in SHORTENERS
        ) else 0

        # 6. Has @ symbol (forces browser to ignore preceding text)
        features['has_at_symbol'] = 1 if '@' in url else 0

        # 7. Has double slash redirect (after protocol)
        clean_url = re.sub(r'^https?://', '', url)
        features['has_double_slash'] = 1 if '//' in clean_url else 0

        # 8. Has dash in domain (prefix-suffix trick)
        features['has_dash_in_domain'] = 1 if '-' in ext.domain else 0

        # 9. Number of subdomains (don't count www as suspicious)
        subdomain = ext.subdomain
        if subdomain == '' or subdomain == 'www':
            features['subdomain_count'] = 0   # www alone is normal
        else:
        # Remove www if present then count remaining
            clean_sub = re.sub(r'^www\.?', '', subdomain)
            features['subdomain_count'] = len(clean_sub.split('.')) if clean_sub else 0

        # 10. Has HTTPS
        features['has_https'] = 1 if parsed.scheme == 'https' else 0

        # 11. HTTPS word appears in domain (deceptive)
        features['https_in_domain'] = 1 if 'https' in domain else 0

        # 12. Non-standard port
        port = parsed.port
        features['has_non_std_port'] = 1 if (
            port and port not in (80, 443)
        ) else 0

        # ── Special Character Features ──────────────────────────────────

        # 13. Number of dots in full URL
        features['dot_count'] = url.count('.')

        # 14. Number of hyphens
        features['hyphen_count'] = url.count('-')

        # 15. Number of underscores
        features['underscore_count'] = url.count('_')

        # 16. Number of slashes
        features['slash_count'] = url.count('/')

        # 17. Number of question marks
        features['question_count'] = url.count('?')

        # 18. Number of equal signs
        features['equal_count'] = url.count('=')

        # 19. Number of & symbols
        features['ampersand_count'] = url.count('&')

        # 20. Number of % (encoded characters)
        features['percent_count'] = url.count('%')

        # 21. Digit ratio in URL
        digits = sum(c.isdigit() for c in url)
        features['digit_ratio'] = round(digits / len(url), 4) if url else 0

        # 22. Number of digits in domain
        features['digits_in_domain'] = sum(c.isdigit() for c in domain)

        # ── Suspicious Content Features ─────────────────────────────────

        # 23. Count of suspicious keywords
        features['suspicious_keyword_count'] = sum(
            1 for kw in SUSPICIOUS_KEYWORDS if kw in full_url
        )

        # 24. Has suspicious keywords (binary)
        features['has_suspicious_keywords'] = 1 if features[
            'suspicious_keyword_count'
        ] > 0 else 0

        # 25. TLD is suspicious (common in phishing)
        suspicious_tlds = {
            'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club',
            'online', 'site', 'icu', 'buzz', 'lat', 'cam', 'surf',
            'monster', 'cyou', 'fit', 'rest'
        }
        features['suspicious_tld'] = 1 if ext.suffix in suspicious_tlds else 0

        # 26. Has www prefix (normal for legitimate sites, not a signal)
        features['has_www'] = 0  # neutralized - not a useful signal

        # 27. Query string length
        query = parsed.query
        features['query_length'] = len(query)

        # 28. Number of query parameters
        features['query_param_count'] = len(query.split('&')) if query else 0

        # 29. Path has encoded characters
        features['has_encoded_chars'] = 1 if '%' in path else 0

        # 30. URL has hexadecimal content
        features['has_hex_content'] = 1 if re.search(r'%[0-9a-fA-F]{2}', url) else 0

        # 31. Domain has repeated characters (e.g. paypaall, gooogle)
        features['has_repeated_chars'] = 1 if re.search(
            r'(.)\1{2,}', ext.domain
        ) else 0

        # 32. Number of special chars total
        special = re.findall(r'[^a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]', url)
        features['special_char_count'] = len(special)

        # 33. Domain token count (how many parts separated by .)
        features['domain_token_count'] = len(domain.split('.'))

        # 34. Is domain purely numeric
        features['numeric_domain'] = 1 if re.match(
            r'^\d+\.\d+\.\d+\.\d+$', domain
        ) else 0

        # 35. Has fragment (#)
        features['has_fragment'] = 1 if parsed.fragment else 0

    except Exception as e:
        # Return zeros if extraction fails
        print(f"Feature extraction error for {url}: {e}")
        features = {k: 0 for k in get_feature_names()}

    return features


def get_feature_names():
    """Returns the list of all feature names in order."""
    return [
        'has_ip', 'url_length', 'domain_length', 'path_length',
        'is_shortener', 'has_at_symbol', 'has_double_slash',
        'has_dash_in_domain', 'subdomain_count', 'has_https',
        'https_in_domain', 'has_non_std_port', 'dot_count',
        'hyphen_count', 'underscore_count', 'slash_count',
        'question_count', 'equal_count', 'ampersand_count',
        'percent_count', 'digit_ratio', 'digits_in_domain',
        'suspicious_keyword_count', 'has_suspicious_keywords',
        'suspicious_tld', 'has_www', 'query_length',
        'query_param_count', 'has_encoded_chars', 'has_hex_content',
        'has_repeated_chars', 'special_char_count',
        'domain_token_count', 'numeric_domain', 'has_fragment'
    ]


def extract_features_batch(urls, batch_size=1000):
    """Extract features for a list of URLs with progress tracking."""
    import pandas as pd
    results = []
    total = len(urls)

    for i, url in enumerate(urls):
        if i % batch_size == 0:
            print(f"  Processing {i}/{total} URLs...")
        results.append(extract_features(url))

    return pd.DataFrame(results)