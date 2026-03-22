import re
import tldextract
from urllib.parse import urlparse, parse_qs

SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'is.gd', 'shorte.st', 'adf.ly', 'buff.ly', 'rebrand.ly',
    'cutt.ly', 'tiny.cc', 'shorturl.at', 'rb.gy', 'v.gd'
}

PHISHING_KEYWORDS = [
    'verify-account', 'confirm-identity', 'suspended-account',
    'unusual-activity', 'secure-update', 'banking-alert',
    'paypal-verify', 'appleid-confirm', 'microsoft-alert',
    'account-suspended', 'verify-now', 'update-billing',
    'credential', 'webscr', 'ebayisapi', 'signin-recover',
    'limited-access', 'unlock-account', 'identity-verify'
]

SPOOFED_BRANDS = [
    'paypal', 'ebay', 'amazon', 'apple', 'microsoft',
    'google', 'facebook', 'netflix', 'instagram', 'twitter',
    'linkedin', 'dropbox', 'chase', 'wellsfargo', 'bankofamerica',
    'citibank', 'dhl', 'fedex', 'ups', 'usps'
]

TRUSTED_TLDS = {
    'com', 'org', 'net', 'edu', 'gov', 'mil',
    'co', 'io', 'in', 'uk', 'de', 'fr', 'jp',
    'ca', 'au', 'br', 'it', 'es', 'nl', 'ru',
    'gov.in', 'nic.in', 'co.in', 'org.in',
    'ac.in', 'edu.in', 'res.in', 'net.in'
}

SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club',
    'online', 'site', 'icu', 'buzz', 'lat', 'cam', 'surf',
    'monster', 'cyou', 'fit', 'rest', 'vip', 'work',
    'party', 'review', 'download', 'cricket', 'science',
    'link', 'racing', 'win', 'loan', 'stream', 'gdn'
}

SUSPICIOUS_PARAM_NAMES = [
    'redirect', 'return_url', 'returnurl', 'next',
    'goto', 'target', 'redir', 'dest', 'destination',
    'cmd', 'action', 'ref_url'
]

SUSPICIOUS_PATH_WORDS = [
    'verify', 'confirm', 'secure', 'update', 'validate',
    'suspend', 'recover', 'unlock', 'alert', 'billing'
]


def extract_features(url: str) -> dict:
    features = {}

    try:
        parsed            = urlparse(url)
        ext               = tldextract.extract(url)
        domain            = parsed.netloc.lower()
        path              = parsed.path.lower()
        query             = parsed.query.lower()
        clean_domain      = domain[4:] if domain.startswith('www.') else domain
        registered_domain = ext.registered_domain.lower()
        subdomain         = ext.subdomain.lower()
        suffix            = ext.suffix.lower()
        sld               = ext.domain.lower()

        # 1. IP as host
        ip_pat = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        features['has_ip'] = 1 if ip_pat.match(
            clean_domain.split(':')[0]
        ) else 0

        # 2. URL shortener — exact match only
        features['is_shortener'] = 1 if any(
            clean_domain == s or clean_domain.endswith('.' + s)
            for s in SHORTENERS
        ) else 0

        # 3. @ symbol
        features['has_at_symbol'] = 1 if '@' in url else 0

        # 4. Double slash after protocol
        after_proto = re.sub(r'^https?://', '', url)
        features['has_double_slash'] = 1 if '//' in after_proto else 0

        # 5. Dash in SLD
        features['dash_in_sld'] = 1 if '-' in sld else 0

        # 6. Subdomain depth
        # KEY FIX: single subdomains (accounts, login, mail) = depth 1 = NOT suspicious
        # Only depth >= 2 is suspicious (secure.login.evil.com)
        # So we store raw depth but model learns that 1 is normal from training data
        # REPLACE WITH:
        if subdomain in ('', 'www'):
            features['subdomain_depth'] = 0
        else:
            clean_sub = subdomain
            if clean_sub.startswith('www.'):
                clean_sub = clean_sub[4:]
            depth = len(clean_sub.split('.')) if clean_sub else 0
            # Only flag depth >= 2 as suspicious
            # Single subdomains (accounts, login, mail) are normal
            features['subdomain_depth'] = 0 if depth <= 1 else depth
        # 7. HTTPS
        features['has_https'] = 1 if parsed.scheme == 'https' else 0

        # 8. "https" in domain name
        features['https_in_domain'] = 1 if 'https' in sld else 0

        # 9. Non-standard port
        port = parsed.port
        features['has_non_std_port'] = 1 if (
            port and port not in (80, 443)
        ) else 0

        # 10. Suspicious TLD
        features['suspicious_tld'] = 1 if suffix in SUSPICIOUS_TLDS else 0

        # 11. Trusted TLD
        features['trusted_tld'] = 1 if suffix in TRUSTED_TLDS else 0

        # 12. Brand spoofing
        # accounts.google.com → registered_domain=google.com → NOT spoofing
        # paypal-secure.tk → registered_domain=paypal-secure.tk → spoofing
        brand_in_url    = any(b in url.lower() for b in SPOOFED_BRANDS)
        brand_is_domain = any(
            sld == b or
            registered_domain == f'{b}.com' or
            registered_domain == f'{b}.net' or
            registered_domain == f'{b}.org' or
            registered_domain == f'{b}.co'  or
            registered_domain == f'{b}.in'  or
            registered_domain.startswith(f'{b}.')
            for b in SPOOFED_BRANDS
        )
        features['brand_spoofing'] = 1 if (
            brand_in_url and not brand_is_domain
        ) else 0

        # 13. Phishing keyword combo
        features['phishing_keyword'] = 1 if any(
            kw in url.lower() for kw in PHISHING_KEYWORDS
        ) else 0

        # 14. Digit ratio in SLD
        digits_sld = sum(c.isdigit() for c in sld)
        features['digit_ratio_sld'] = round(
            digits_sld / len(sld), 4
        ) if sld else 0

        # 15. Long AND hyphenated SLD
        features['long_hyphenated_sld'] = 1 if (
            len(sld) > 12 and sld.count('-') >= 1
        ) else 0

        # 16. Dots in domain (raw count)
        features['dots_in_domain'] = clean_domain.count('.')

        # 17. Hyphens in domain
        features['hyphens_in_domain'] = clean_domain.count('-')

        # 18. Suspicious query params
        params      = parse_qs(query)
        susp_params = sum(
            1 for p in params
            if any(s in p.lower() for s in SUSPICIOUS_PARAM_NAMES)
        )
        features['suspicious_query_params'] = 1 if susp_params >= 1 else 0

        # 19. Encoded chars in path
        features['has_encoded_chars'] = 1 if '%' in path else 0

        # 20. Hex encoding
        features['has_hex'] = 1 if re.search(
            r'%[0-9a-fA-F]{2}', url
        ) else 0

        # 21. Repeated chars in SLD
        features['repeated_chars'] = 1 if re.search(
            r'(.)\1{2,}', sld
        ) else 0

        # 22. Domain token count (raw)
        features['domain_token_count'] = len(clean_domain.split('.'))

        # 23. Numeric domain
        features['numeric_domain'] = 1 if re.match(
            r'^\d+\.\d+\.\d+\.\d+$', clean_domain
        ) else 0

        # 24. Brand + hyphen in SLD (only if not real brand)
        features['brand_hyphen_pattern'] = 1 if (
            not brand_is_domain and
            any(f'{b}-' in sld or f'-{b}' in sld for b in SPOOFED_BRANDS)
        ) else 0

        # 25. Fragment
        features['has_fragment'] = 1 if parsed.fragment else 0

        # 26. Special chars in domain
        special = re.findall(r'[^a-zA-Z0-9\-\.]', clean_domain)
        features['special_chars_in_domain'] = len(special)

        # 27. Suspicious path (2+ words needed)
        path_parts = [p for p in path.split('/') if p]
        path_hits  = sum(
            1 for w in SUSPICIOUS_PATH_WORDS
            if w in ' '.join(path_parts)
        )
        features['suspicious_path'] = 1 if path_hits >= 2 else 0

        # 28. Underscore in domain
        features['underscore_in_domain'] = 1 if '_' in clean_domain else 0

        # 29. Multi-dot suffix
        features['multi_dot_suffix'] = 1 if '.' in suffix else 0

    except Exception as e:
        print(f"Feature extraction error for {url}: {e}")
        features = {k: 0 for k in get_feature_names()}

    return features


def get_feature_names():
    return [
        'has_ip', 'is_shortener', 'has_at_symbol', 'has_double_slash',
        'dash_in_sld', 'subdomain_depth', 'has_https', 'https_in_domain',
        'has_non_std_port', 'suspicious_tld', 'trusted_tld',
        'brand_spoofing', 'phishing_keyword', 'digit_ratio_sld',
        'long_hyphenated_sld', 'dots_in_domain', 'hyphens_in_domain',
        'suspicious_query_params', 'has_encoded_chars', 'has_hex',
        'repeated_chars', 'domain_token_count', 'numeric_domain',
        'brand_hyphen_pattern', 'has_fragment', 'special_chars_in_domain',
        'suspicious_path', 'underscore_in_domain', 'multi_dot_suffix',
    ]


def extract_features_batch(urls, batch_size=1000):
    import pandas as pd
    results = []
    total   = len(urls)
    for i, url in enumerate(urls):
        if i % batch_size == 0:
            print(f"  Processing {i}/{total} URLs...")
        results.append(extract_features(url))
    return pd.DataFrame(results)