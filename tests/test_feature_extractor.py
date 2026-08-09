"""
test_feature_extractor.py
=========================
Unit tests for the FeatureExtractor class.

Each test verifies one or more features against known URLs with expected values.
Run with: pytest tests/test_feature_extractor.py -v
"""

import pytest
from ml.feature_extractor import FeatureExtractor

extractor = FeatureExtractor()


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def legitimate_url():
    return "https://github.com/user/repository"

@pytest.fixture
def phishing_url():
    return "http://paypal-secure-login.xyz/account/verify?token=abc123@evil.com"

@pytest.fixture
def ip_url():
    return "http://192.168.1.1/login"

@pytest.fixture
def shortener_url():
    return "https://bit.ly/3xAbc12"


# ─── Tests: Length features ───────────────────────────────────────────────────

def test_url_length_is_accurate(legitimate_url):
    features = extractor.extract(legitimate_url)
    assert features["url_length"] == len(legitimate_url)


def test_domain_length(legitimate_url):
    features = extractor.extract(legitimate_url)
    # Domain of https://github.com/... is "github.com"
    assert features["domain_length"] == len("github.com")


def test_path_length(legitimate_url):
    features = extractor.extract(legitimate_url)
    assert features["path_length"] == len("/user/repository")


# ─── Tests: Character counts ──────────────────────────────────────────────────

def test_num_dots(legitimate_url):
    # "https://github.com/user/repository" → 1 dot in domain
    features = extractor.extract(legitimate_url)
    assert features["num_dots"] == legitimate_url.count(".")


def test_num_at_symbols_phishing(phishing_url):
    features = extractor.extract(phishing_url)
    assert features["num_at_symbols"] >= 1


def test_num_at_symbols_legitimate(legitimate_url):
    features = extractor.extract(legitimate_url)
    assert features["num_at_symbols"] == 0


def test_digit_ratio_is_between_0_and_1(legitimate_url):
    features = extractor.extract(legitimate_url)
    assert 0.0 <= features["digit_ratio"] <= 1.0


# ─── Tests: Domain features ───────────────────────────────────────────────────

def test_has_ip_address_true(ip_url):
    features = extractor.extract(ip_url)
    assert features["has_ip_address"] == 1


def test_has_ip_address_false(legitimate_url):
    features = extractor.extract(legitimate_url)
    assert features["has_ip_address"] == 0


def test_uses_https_true(legitimate_url):
    features = extractor.extract(legitimate_url)
    assert features["uses_https"] == 1


def test_uses_https_false(ip_url):
    # ip_url starts with http://
    features = extractor.extract(ip_url)
    assert features["uses_https"] == 0


def test_has_port_true():
    features = extractor.extract("http://example.com:8080/path")
    assert features["has_port"] == 1


def test_has_port_false(legitimate_url):
    features = extractor.extract(legitimate_url)
    assert features["has_port"] == 0


def test_subdomain_count_no_subdomain():
    # github.com has no subdomain
    features = extractor.extract("https://github.com")
    assert features["subdomain_count"] == 0


def test_subdomain_count_with_subdomains():
    # api.secure.paypal.com → subdomains: ["api", "secure"]
    features = extractor.extract("https://api.secure.paypal.com/login")
    assert features["subdomain_count"] == 2


def test_suspicious_tld_true():
    features = extractor.extract("https://freesite.tk/login")
    assert features["has_suspicious_tld"] == 1


def test_suspicious_tld_false(legitimate_url):
    features = extractor.extract(legitimate_url)
    assert features["has_suspicious_tld"] == 0


# ─── Tests: Content / pattern features ───────────────────────────────────────

def test_suspicious_keywords_phishing(phishing_url):
    features = extractor.extract(phishing_url)
    # phishing_url contains "login", "secure", "account", "verify"
    assert features["suspicious_keyword_count"] >= 3


def test_suspicious_keywords_clean():
    features = extractor.extract("https://github.com/user/repo")
    assert features["suspicious_keyword_count"] == 0


def test_encoded_chars_true():
    features = extractor.extract("http://example.com/page%20name")
    assert features["has_encoded_chars"] == 1


def test_encoded_chars_false(legitimate_url):
    features = extractor.extract(legitimate_url)
    assert features["has_encoded_chars"] == 0


def test_shortening_service_true(shortener_url):
    features = extractor.extract(shortener_url)
    assert features["shortening_service"] == 1


def test_shortening_service_false(legitimate_url):
    features = extractor.extract(legitimate_url)
    assert features["shortening_service"] == 0


# ─── Tests: Statistical features ─────────────────────────────────────────────

def test_entropy_is_positive(legitimate_url):
    features = extractor.extract(legitimate_url)
    assert features["url_entropy"] > 0.0


def test_entropy_empty_string():
    # Edge case: entropy of a single repeated character is 0
    from ml.feature_extractor import FeatureExtractor as FE
    e = FE._shannon_entropy("aaaa")
    assert e == 0.0


# ─── Tests: Feature vector completeness ──────────────────────────────────────

def test_all_features_present(legitimate_url):
    features = extractor.extract(legitimate_url)
    for name in FeatureExtractor.FEATURE_NAMES:
        assert name in features, f"Missing feature: {name}"


def test_extract_as_list_length(legitimate_url):
    feature_list = extractor.extract_as_list(legitimate_url)
    assert len(feature_list) == len(FeatureExtractor.FEATURE_NAMES)


def test_extract_as_list_order(legitimate_url):
    feature_dict = extractor.extract(legitimate_url)
    feature_list = extractor.extract_as_list(legitimate_url)
    for i, name in enumerate(FeatureExtractor.FEATURE_NAMES):
        assert feature_list[i] == feature_dict[name]
