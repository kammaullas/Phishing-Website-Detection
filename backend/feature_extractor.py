"""
Feature Extractor for Phishing URL Detection
=============================================
Extracts 30+ features from URL string alone — no WHOIS, no HTTP requests.
This makes predictions instant and reliable.
"""

import re
import math
import string
from urllib.parse import urlparse, parse_qs
import tldextract


# --- Constants ---

SHORTENING_SERVICES = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'j.mp', 'adf.ly', 'tr.im', 'cli.gs', 'yourls.org',
    'su.pr', 'qr.ae', 'cutt.ly', 'rb.gy', 'shorturl.at', 'tiny.cc',
    'v.gd', 'clck.ru', 'bc.vc', 'shrtco.de'
}

SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'xyz', 'top', 'club',
    'work', 'date', 'loan', 'download', 'racing', 'win', 'bid',
    'stream', 'gdn', 'icu', 'cam', 'surf', 'rest', 'fit', 'monster'
}

BRAND_KEYWORDS = {
    'paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix',
    'facebook', 'instagram', 'whatsapp', 'chase', 'wellsfargo',
    'bankofamerica', 'citibank', 'dropbox', 'linkedin', 'twitter',
    'yahoo', 'outlook', 'office365', 'icloud', 'ebay', 'steam',
    'spotify', 'adobe', 'dhl', 'fedex', 'usps', 'ups'
}

SUSPICIOUS_PATH_KEYWORDS = {
    'login', 'signin', 'sign-in', 'verify', 'update', 'confirm',
    'account', 'secure', 'banking', 'password', 'credential',
    'suspend', 'restrict', 'unlock', 'authenticate', 'wallet',
    'recover', 'invoice', 'payment', 'billing', 'upgrade'
}


class FeatureExtractor:
    """
    Extracts purely URL-based features for phishing detection.
    No network calls — all analysis is done on the string itself.
    """

    # Class-level feature order (used by training and prediction)
    FEATURE_NAMES = [
        'url_length', 'domain_length', 'path_length', 'query_length',
        'fragment_length', 'num_dots', 'num_hyphens', 'num_underscores',
        'num_slashes', 'num_digits_in_url', 'num_special_chars',
        'digit_ratio', 'special_char_ratio', 'has_at_symbol',
        'has_double_slash_redirect', 'has_hex_encoding',
        'has_ip_address', 'uses_shortening_service', 'has_punycode',
        'is_https', 'subdomain_depth', 'tld_is_suspicious',
        'domain_has_digits', 'domain_entropy', 'path_depth',
        'has_query_string', 'num_query_params', 'avg_token_length',
        'longest_token_length', 'path_has_suspicious_keyword',
        'contains_brand_keyword', 'brand_in_subdomain',
        'url_has_port', 'domain_hyphen_count'
    ]

    def __init__(self, url: str):
        self.raw_url = url.strip()

        # Normalize: add scheme if missing so urlparse works correctly
        if not self.raw_url.startswith(('http://', 'https://')):
            self.url = 'http://' + self.raw_url
        else:
            self.url = self.raw_url

        self.parsed = urlparse(self.url)
        self.ext = tldextract.extract(self.url)
        self.domain = f"{self.ext.domain}.{self.ext.suffix}"
        self.hostname = self.parsed.netloc.lower()
        self.path = self.parsed.path.lower()
        self.query = self.parsed.query
        self.fragment = self.parsed.fragment

    def extract_all(self) -> dict:
        """
        Extract all features and return as a dictionary.
        Keys match FEATURE_NAMES order exactly.
        """
        f = {}

        # === 1. LENGTH METRICS ===
        f['url_length'] = len(self.url)
        f['domain_length'] = len(self.domain)
        f['path_length'] = len(self.path)
        f['query_length'] = len(self.query)
        f['fragment_length'] = len(self.fragment)

        # === 2. CHARACTER COUNTS ===
        f['num_dots'] = self.url.count('.')
        f['num_hyphens'] = self.url.count('-')
        f['num_underscores'] = self.url.count('_')
        f['num_slashes'] = self.url.count('/')
        f['num_digits_in_url'] = sum(c.isdigit() for c in self.url)
        
        special_chars = set('!@#$%^&*()+=[]{}|;:\'",<>?~`')
        f['num_special_chars'] = sum(1 for c in self.url if c in special_chars)

        url_len_safe = max(len(self.url), 1)  # avoid division by zero
        f['digit_ratio'] = round(f['num_digits_in_url'] / url_len_safe, 4)
        f['special_char_ratio'] = round(f['num_special_chars'] / url_len_safe, 4)

        # === 3. SUSPICIOUS PATTERNS ===
        f['has_at_symbol'] = 1 if '@' in self.url else 0

        # Double-slash redirect (after the protocol ://)
        # e.g., http://legitimate.com//http://evil.com
        after_protocol = self.url.split('://', 1)[-1] if '://' in self.url else self.url
        f['has_double_slash_redirect'] = 1 if '//' in after_protocol else 0

        # Hex/percent encoding (e.g., %20, %3A) — used to obfuscate URLs
        f['has_hex_encoding'] = 1 if re.search(r'%[0-9a-fA-F]{2}', self.url) else 0

        # IP address as hostname
        ip_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
        )
        hostname_no_port = self.hostname.split(':')[0]
        f['has_ip_address'] = 1 if ip_pattern.match(hostname_no_port) else 0

        # URL shortening service
        f['uses_shortening_service'] = 1 if self.domain.lower() in SHORTENING_SERVICES else 0

        # Punycode (Internationalized Domain Names used for homoglyph attacks)
        f['has_punycode'] = 1 if 'xn--' in self.hostname else 0

        # === 4. DOMAIN ANALYSIS ===
        f['is_https'] = 1 if self.parsed.scheme == 'https' else 0

        # Subdomain depth: www.mail.google.com → depth 2 (www, mail)
        if self.ext.subdomain:
            f['subdomain_depth'] = len(self.ext.subdomain.split('.'))
        else:
            f['subdomain_depth'] = 0

        # Suspicious TLD
        f['tld_is_suspicious'] = 1 if self.ext.suffix.lower() in SUSPICIOUS_TLDS else 0

        # Digits in the domain name (e.g., g00gle.com)
        f['domain_has_digits'] = 1 if any(c.isdigit() for c in self.ext.domain) else 0

        # Shannon entropy of domain (high entropy = random/obfuscated)
        f['domain_entropy'] = round(self._shannon_entropy(self.ext.domain), 4)

        # === 5. PATH / QUERY ANALYSIS ===
        # Path depth: /a/b/c → 3
        path_parts = [p for p in self.path.split('/') if p]
        f['path_depth'] = len(path_parts)

        f['has_query_string'] = 1 if self.query else 0
        f['num_query_params'] = len(parse_qs(self.query))

        # Token analysis — split URL into meaningful tokens
        tokens = re.split(r'[/\-_.?&=]', self.url)
        tokens = [t for t in tokens if t and t not in ('http:', 'https:', '')]
        if tokens:
            token_lengths = [len(t) for t in tokens]
            f['avg_token_length'] = round(sum(token_lengths) / len(token_lengths), 2)
            f['longest_token_length'] = max(token_lengths)
        else:
            f['avg_token_length'] = 0
            f['longest_token_length'] = 0

        # === 6. KEYWORD ANALYSIS ===
        url_lower = self.url.lower()
        path_lower = self.path.lower()

        # Suspicious keywords in path
        f['path_has_suspicious_keyword'] = 1 if any(
            kw in path_lower for kw in SUSPICIOUS_PATH_KEYWORDS
        ) else 0

        # Brand keyword anywhere in URL
        f['contains_brand_keyword'] = 1 if any(
            kw in url_lower for kw in BRAND_KEYWORDS
        ) else 0

        # Brand keyword specifically in subdomain (phishing signal)
        # e.g., paypal.evil.com instead of www.paypal.com
        subdomain_lower = self.ext.subdomain.lower()
        f['brand_in_subdomain'] = 1 if any(
            kw in subdomain_lower for kw in BRAND_KEYWORDS
        ) else 0

        # === 7. MISC ===
        # Explicit port in URL (e.g., :8080)
        f['url_has_port'] = 1 if re.search(r':\d+', self.hostname) else 0

        # Hyphens in domain name (e.g., secure-login-paypal.com)
        f['domain_hyphen_count'] = self.ext.domain.count('-')

        return f

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string. Higher = more random."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in prob if p > 0)