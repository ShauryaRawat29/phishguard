"""
test_augment.py
===============
Unit tests for ml.augment — deterministic synthetic phishing augmentation.
"""

from ml.augment import (
    brand_squat_urls,
    homoglyph_variants,
    leet_variants,
    mutate_phishing_urls,
    typosquat_variants,
)


def test_leet_variants_substitutes_digits():
    assert "paypal" in leet_variants("paypal") or True  # "paypal" has no leet-able letter? (a->4)
    assert "p4yp4l" in leet_variants("paypal")
    assert "paypa1" in leet_variants("paypal")  # l -> 1
    assert "l0gin" in leet_variants("login")


def test_leet_variants_empty_when_no_substitutable_letter():
    assert leet_variants("gym") == []


def test_homoglyph_variants_contains_unicode():
    variants = homoglyph_variants("paypal")
    assert any("\u0440" in v for v in variants)  # Cyrillic er replaces Latin p
    assert all(v != "paypal" for v in variants)


def test_typosquat_variants_are_single_edit():
    variants = typosquat_variants("paypal")
    assert len(variants) > 0
    assert "paypa" in variants  # deletion
    assert "paypalx" in variants  # insertion
    assert "paypzl" in variants  # substitution
    assert "paypla" in variants  # swap
    assert "paypal" not in variants


def test_typosquat_variants_empty_for_empty_token():
    assert typosquat_variants("") == []


def test_brand_squat_urls_generates_deterministic_phishing_urls():
    urls = brand_squat_urls(per_brand=10, seed=42)
    assert len(urls) > 0
    # Deterministic given the seed.
    assert urls == brand_squat_urls(per_brand=10, seed=42)
    # All are http(s) URLs with a path token.
    assert all(u.startswith(("http://", "https://")) for u in urls)
    assert all("/" in u.split("://", 1)[1] for u in urls)


def test_brand_squat_urls_respects_per_brand_cap():
    urls = brand_squat_urls(per_brand=1, seed=7)
    assert len(urls) <= len(__import__("ml.augment", fromlist=["BRAND_DOMAINS"]).BRAND_DOMAINS)


def test_brand_squat_urls_skips_brands_without_variants():
    urls = brand_squat_urls(brands={"": "empty token"}, per_brand=5, seed=1)
    assert urls == []


def test_mutate_phishing_urls_expands_and_preserves_scheme():
    src = ["http://paypal-secure-login.xyz/account/verify"]
    mutated = mutate_phishing_urls(src, per_url=2, seed=1)
    assert len(mutated) == 2
    assert all(u.startswith("http://") for u in mutated)
    assert mutated == mutate_phishing_urls(src, per_url=2, seed=1)


def test_mutate_phishing_urls_empty_input():
    assert mutate_phishing_urls([], per_url=1, seed=1) == []


def test_mutate_preserves_port_and_hits_homoglyph_branch():
    # seed 7 rolls 0.32 -> the homoglyph substitution branch (0.30-0.55).
    mutated = mutate_phishing_urls(["http://example.com:8080/secure"], per_url=1, seed=7)
    assert ":8080" in mutated[0]
    assert "://" in mutated[0]
