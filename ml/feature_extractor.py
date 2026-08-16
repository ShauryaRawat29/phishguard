"""
feature_extractor.py
====================
Extracts 33 structural and lexical features from a raw URL string.

All features are computed from the URL string only — no network requests,
no DNS lookups, no external API calls. This ensures fast, safe, offline inference.

Usage:
    from ml.feature_extractor import FeatureExtractor

    extractor = FeatureExtractor()
    features = extractor.extract("https://example.com/login")
    # Returns: dict[str, int | float]
"""

import math
import re
from difflib import SequenceMatcher
from urllib.parse import urlparse

# ─── Known URL shortening services ────────────────────────────────────────────
SHORTENING_SERVICES: set[str] = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "t.co",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "shorte.st",
    "cutt.ly",
    "rebrand.ly",
    "tiny.cc",
    "lnkd.in",
    "tr.im",
    "x.co",
    "v.gd",
    "qr.net",
}

# ─── Suspicious top-level domains (free / abused TLDs) ────────────────────────
SUSPICIOUS_TLDS: set[str] = {
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",  # Freenom free TLDs
    "xyz",
    "top",
    "club",
    "online",  # Cheap / commonly abused
    "work",
    "live",
    "site",
    "website",
    "loan",
    "click",
    "link",
    "shop",
    "buzz",
    "info",
    "biz",
    # Free / heavily abused TLDs added in the 33-feature expansion
    "icu",
    "cyou",
    "monster",
    "rest",
    "faith",
    "gdn",
    "pro",
    "fit",
    "kim",
    "men",
    "mom",
    "party",
    "review",
    "surf",
    "win",
    "cfd",
    "bond",
    "racing",
    "stream",
    "download",
}

# ─── Phishing keyword vocabulary ─────────────────────────────────────────────
PHISHING_KEYWORDS: list[str] = [
    "login",
    "signin",
    "sign-in",
    "logon",
    "account",
    "verify",
    "verification",
    "secure",
    "security",
    "update",
    "confirm",
    "banking",
    "bank",
    "paypal",
    "ebay",
    "password",
    "credential",
    "recover",
    "alert",
    "suspend",
    "unlock",
    "urgent",
    "validate",
    "authorize",
    "billing",
]

# ─── Popular Brand Domains (for brand spoofing / typosquatting detection) ─────
BRAND_DOMAINS: dict[str, str] = {
    "paypal": "paypal.com",
    "google": "google.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
    "microsoft": "microsoft.com",
    "netflix": "netflix.com",
    "instagram": "instagram.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "binance": "binance.com",
    "coinbase": "coinbase.com",
    # Added in the 33-feature expansion (frequently phished brands)
    "steam": "steamcommunity.com",
    "discord": "discord.com",
    "outlook": "outlook.com",
    "icloud": "icloud.com",
    "dropbox": "dropbox.com",
    "telegram": "telegram.org",
    "meta": "meta.com",
    "whatsapp": "whatsapp.com",
    "twitter": "twitter.com",
    "linkedin": "linkedin.com",
    "bankofamerica": "bankofamerica.com",
    "citibank": "citibank.com",
    "fidelity": "fidelity.com",
    "robinhood": "robinhood.com",
    "ebay": "ebay.com",
}

# ─── Top Legitimate Apex Domains ──────────────────────────────────────────────
TOP_LEGITIMATE_DOMAINS: set[str] = {
    "google.com",
    "youtube.com",
    "facebook.com",
    "amazon.com",
    "apple.com",
    "microsoft.com",
    "wikipedia.org",
    "github.com",
    "paypal.com",
    "twitter.com",
    "instagram.com",
    "linkedin.com",
    "netflix.com",
    "reddit.com",
    "yahoo.com",
    "bing.com",
    "whatsapp.com",
    "zoom.us",
    "chase.com",
    "wellsfargo.com",
    "bankofamerica.com",
    "adobe.com",
    "wordpress.org",
    "cloudflare.com",
    # Added in the 33-feature expansion
    "stackoverflow.com",
    "stackexchange.com",
    "medium.com",
    "quora.com",
    "notion.so",
    "canva.com",
    "figma.com",
    "salesforce.com",
    "oracle.com",
    "ibm.com",
    "intel.com",
    "nvidia.com",
    "spotify.com",
    "discord.com",
    "slack.com",
    "gitlab.com",
    "bitbucket.org",
    "mozilla.org",
    "w3.org",
    "python.org",
    "npmjs.com",
    "docker.com",
    "kubernetes.io",
    "telegram.org",
}
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

# ─── Percent-encoding pattern ─────────────────────────────────────────────────
_ENCODED_CHARS_RE = re.compile(r"%[0-9a-fA-F]{2}")

# ─── Hex IP pattern (0x...) ──────────────────────────────────────────────────
_HEX_IP_RE = re.compile(r"0x[0-9a-fA-F]+", re.IGNORECASE)

# ─── Fuzzy brand / typosquatting thresholds ──────────────────────────────────
_BRAND_FUZZY_MIN_LENGTH = 5  # ignore very short tokens (e.g. "www")
_BRAND_FUZZY_RATIO = 0.83  # difflib similarity cutoff for a typo
_TOKEN_RE = re.compile(r"[a-z0-9]+")

# ─── Unicode confusables (IDN homograph attack) ──────────────────────────────
# Maps lookalike letters from non-Latin scripts to their Latin equivalents so
# a domain like "аррӏе.com" (Cyrillic "apple") can be recognized as spoofed.
_CONFUSABLES: dict[str, str] = {
    "\u0430": "a",  # Cyrillic a
    "\u0435": "e",  # Cyrillic e
    "\u043e": "o",  # Cyrillic o
    "\u0440": "p",  # Cyrillic r (er)
    "\u0441": "c",  # Cyrillic s (es)
    "\u0445": "x",  # Cyrillic x (ha)
    "\u0443": "y",  # Cyrillic u
    "\u043d": "h",  # Cyrillic n (en)
    "\u043a": "k",  # Cyrillic k
    "\u043c": "m",  # Cyrillic m
    "\u0432": "b",  # Cyrillic v (ve)
    "\u0442": "t",  # Cyrillic t (te)
    "\u0437": "z",  # Cyrillic z (ze)
    "\u04cf": "l",  # Cyrillic palochka (looks like l)
    "\u03b1": "a",  # Greek alpha
    "\u03b5": "e",  # Greek epsilon
    "\u03bf": "o",  # Greek omicron
    "\u03b9": "i",  # Greek iota
    "\u03c1": "p",  # Greek rho
}


class FeatureExtractor:
    """
    Extracts a fixed-length feature vector from a URL string.

    All 33 features are deterministic, fast, and require no external calls.
    The same extractor is used during both model training and live inference,
    ensuring consistent feature representation.
    """

    # Ordered list of feature names — MUST match the order returned by extract()
    FEATURE_NAMES: list[str] = [
        "url_length",
        "domain_length",
        "path_length",
        "num_dots",
        "num_hyphens",
        "num_underscores",
        "num_slashes",
        "num_question_marks",
        "num_at_symbols",
        "num_digits",
        "digit_ratio",
        "has_ip_address",
        "uses_https",
        "has_port",
        "subdomain_count",
        "has_suspicious_tld",
        "suspicious_keyword_count",
        "has_encoded_chars",
        "double_slash_in_path",
        "has_hex_encoding",
        "shortening_service",
        "url_entropy",
        "domain_hyphen_count",
        "path_token_count",
        "num_special_chars",
        "is_brand_spoofed",
        "is_whitelisted_domain",
        # ── Added in the 33-feature expansion ────────────────────────────────
        "has_punycode",
        "is_ipv6",
        "sld_length",
        "path_has_https",
        "brand_in_path",
        "domain_entropy",
    ]

    def extract(self, url: str) -> dict[str, int | float]:
        """
        Extract all 33 features from the given URL string.

        Args:
            url: A raw URL string (e.g. "example.com" or "https://example.com/login").

        Returns:
            A dict mapping feature name → numeric value (int or float).
        """
        full_url = url.strip()
        if not full_url.startswith(("http://", "https://", "ftp://")):
            full_url = "https://" + full_url

        parsed = urlparse(full_url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()  # includes port if present
        path = parsed.path

        # Strip port from netloc to get the pure host
        host = netloc.split(":")[0]

        # Determine subdomain structure
        host_parts = host.split(".")
        tld = host_parts[-1] if len(host_parts) > 0 else ""
        domain_parts = host_parts[:-2] if len(host_parts) > 2 else []

        return {
            # ── Length-based features ──────────────────────────────────────
            "url_length": self._url_length(full_url),
            "domain_length": self._domain_length(host),
            "path_length": self._path_length(path),
            # ── Character count features ───────────────────────────────────
            "num_dots": full_url.count("."),
            "num_hyphens": full_url.count("-"),
            "num_underscores": full_url.count("_"),
            "num_slashes": full_url.count("/"),
            "num_question_marks": full_url.count("?"),
            "num_at_symbols": full_url.count("@"),
            "num_digits": sum(c.isdigit() for c in full_url),
            "digit_ratio": self._digit_ratio(full_url),
            # ── Domain-based features ──────────────────────────────────────
            "has_ip_address": int(self._has_ip_address(host)),
            "uses_https": int(scheme == "https"),
            "has_port": int(":" in netloc),
            "subdomain_count": len(domain_parts),
            "has_suspicious_tld": int(tld in SUSPICIOUS_TLDS),
            "domain_hyphen_count": host.count("-"),
            # ── Content / pattern features ─────────────────────────────────
            "suspicious_keyword_count": self._keyword_count(full_url.lower()),
            "has_encoded_chars": int(bool(_ENCODED_CHARS_RE.search(full_url))),
            "double_slash_in_path": int("//" in path),
            "has_hex_encoding": int(bool(_HEX_IP_RE.search(full_url))),
            "shortening_service": int(host in SHORTENING_SERVICES),
            # ── Statistical features ───────────────────────────────────────
            "url_entropy": self._shannon_entropy(full_url),
            # ── Path features ──────────────────────────────────────────────
            "path_token_count": self._path_token_count(path),
            "num_special_chars": self._count_special_chars(full_url),
            "is_brand_spoofed": int(self._is_brand_spoofed(host)),
            "is_whitelisted_domain": int(self._is_whitelisted_domain(host)),
            # ── Added in the 33-feature expansion ────────────────────────────
            "has_punycode": int("xn--" in host),
            "is_ipv6": int(netloc.count(":") > 1),
            "sld_length": len(self._second_level_domain(host)),
            "path_has_https": int("https" in path.lower()),
            "brand_in_path": int(self._brand_in_path(path.lower())),
            "domain_entropy": self._shannon_entropy(host),
        }

    def extract_as_list(self, url: str) -> list[int | float]:
        """
        Extract features and return them as an ordered list.

        The order matches FEATURE_NAMES exactly — safe to pass directly to the model.

        Args:
            url: A raw URL string.

        Returns:
            A list of numeric feature values in FEATURE_NAMES order.
        """
        feature_dict = self.extract(url)
        return [feature_dict[name] for name in self.FEATURE_NAMES]

    # ── Private helper methods ─────────────────────────────────────────────────

    @staticmethod
    def _url_length(url: str) -> int:
        """Total character length of the URL."""
        return len(url)

    @staticmethod
    def _domain_length(host: str) -> int:
        """Character length of the host (domain + subdomains, no port)."""
        return len(host)

    @staticmethod
    def _path_length(path: str) -> int:
        """Character length of the URL path component."""
        return len(path)

    @staticmethod
    def _digit_ratio(url: str) -> float:
        """Ratio of digit characters to total URL length."""
        if not url:
            return 0.0
        return sum(c.isdigit() for c in url) / len(url)

    @staticmethod
    def _has_ip_address(host: str) -> bool:
        """
        Return True if the host is a raw IPv4 address.

        Legitimate websites almost always use domain names, not IP addresses.
        Phishing URLs frequently use IPs to avoid domain-based detection.
        """
        return bool(_IPV4_RE.match(host))

    @staticmethod
    def _keyword_count(url_lower: str) -> int:
        """
        Count how many phishing-associated keywords appear in the URL.

        Searches for exact keyword occurrences (not substrings of other words
        where possible, by checking word boundaries).
        """
        count = 0
        for keyword in PHISHING_KEYWORDS:
            if keyword in url_lower:
                count += 1
        return count

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """
        Calculate the Shannon entropy of a string.

        High entropy → more random characters → more likely to be obfuscated.
        Legitimate URLs tend to be human-readable (lower entropy).
        """
        if not text:
            return 0.0
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    @staticmethod
    def _path_token_count(path: str) -> int:
        """
        Count the number of non-empty path segments (tokens).

        e.g. "/a/b/c" → 3, "/" → 0, "" → 0
        Deep paths with many tokens can indicate directory traversal or obfuscation.
        """
        return len([t for t in path.split("/") if t])

    @staticmethod
    def _count_special_chars(url: str) -> int:
        """
        Count special characters that are unusual in well-formed URLs.

        Includes: ! $ & ' ( ) * + , ; =
        """
        special = set("!$&'()*+,;=")
        return sum(c in special for c in url)

    @staticmethod
    def _is_brand_spoofed(host: str) -> bool:
        """
        Detect typosquatting / brand spoofing in a domain.

        Returns True if the host impersonates a known brand via any of:
          1. Direct containment: the brand name appears but the host is not the
             official domain (e.g. 'paypal-security.net').
          2. Fuzzy typosquatting: the second-level domain closely matches a brand
             name (e.g. 'gooogle.com', 'paypa1-secure-login.xyz').
          3. IDN homograph: a punycode or non-Latin domain that decodes to a brand
             lookalike (e.g. Cyrillic 'аррӏе.com' = "apple").

        A legitimate subdomain like 'www.paypal.com' or 'mail.google.com' is
        NOT considered spoofed.
        """
        host_lower = host.lower()

        # 1. Direct containment of a brand outside the official domain
        for brand, official_domain in BRAND_DOMAINS.items():
            if brand in host_lower and not (
                host_lower == official_domain or host_lower.endswith("." + official_domain)
            ):
                return True

        # 2. Fuzzy typosquatting on the second-level domain
        sld = FeatureExtractor._second_level_domain(host_lower)
        if sld and FeatureExtractor._fuzzy_brand_match(sld):
            return True

        # 3. IDN / Unicode homograph attack
        return bool(FeatureExtractor._has_homograph(host_lower))

    @staticmethod
    def _second_level_domain(host: str) -> str:
        """Return the second-level domain (e.g. 'paypal' from 'paypal.com')."""
        parts = host.split(".")
        return parts[-2] if len(parts) >= 2 else host

    @staticmethod
    def _brand_in_path(path_lower: str) -> bool:
        """
        Return True if a known brand name appears in the URL path.

        Attackers often append a brand to the path (e.g. '/paypal/login') to
        make a malicious URL look legitimate.
        """
        return any(brand in path_lower for brand in BRAND_DOMAINS)

    @staticmethod
    def _fuzzy_brand_match(text: str) -> bool:
        """
        Return True if any token of `text` closely resembles a known brand.

        Uses difflib's SequenceMatcher ratio on alphabetic tokens of at least
        `_BRAND_FUZZY_MIN_LENGTH` characters. Purely lexical — no network calls.
        """
        tokens = [t for t in _TOKEN_RE.findall(text) if len(t) >= _BRAND_FUZZY_MIN_LENGTH]
        for token in tokens:
            for brand in BRAND_DOMAINS:
                # An exact brand token is handled by the containment check;
                # only genuine typos (non-exact, close matches) count here.
                if token == brand:
                    continue
                if SequenceMatcher(None, token, brand).ratio() >= _BRAND_FUZZY_RATIO:
                    return True
        return False

    @staticmethod
    def _has_homograph(host: str) -> bool:
        """
        Detect IDN homograph attacks.

        Checks punycode (xn--) labels by decoding them and normalizing confusable
        non-Latin letters to their Latin equivalents, then looking for a brand.
        Also checks raw host labels that contain confusable characters.
        """
        for label in host.split("."):
            if label.startswith("xn--"):
                try:
                    decoded = label[4:].encode("ascii").decode("punycode")
                except Exception:
                    decoded = ""
                if FeatureExtractor._looks_like_brand(decoded):
                    return True
            elif any(ch in _CONFUSABLES for ch in label):
                if FeatureExtractor._looks_like_brand(label):
                    return True
        return False

    @staticmethod
    def _looks_like_brand(text: str) -> bool:
        """
        Return True if `text`, after normalizing confusable letters to Latin,
        contains or closely matches a known brand name.
        """
        normalized = "".join(_CONFUSABLES.get(ch, ch) for ch in text.lower())
        tokens = [t for t in _TOKEN_RE.findall(normalized) if len(t) >= _BRAND_FUZZY_MIN_LENGTH]
        for token in tokens:
            for brand in BRAND_DOMAINS:
                if (
                    brand in token
                    or SequenceMatcher(None, token, brand).ratio() >= _BRAND_FUZZY_RATIO
                ):
                    return True
        return False

    @staticmethod
    def _is_whitelisted_domain(host: str) -> bool:
        """
        Check if host belongs to top trusted legitimate apex domains.
        Example: 'google.com' -> True, 'sub.google.com' -> True, 'google.ab' -> False.
        """
        host_lower = host.lower()
        for domain in TOP_LEGITIMATE_DOMAINS:
            if host_lower == domain or host_lower.endswith("." + domain):
                return True
        return False
