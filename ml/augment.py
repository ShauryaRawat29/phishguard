"""
augment.py
==========
Deterministic URL augmentation for training-data expansion.

Generates synthetic phishing URLs that mimic real attacker tricks — leet-speak,
Unicode homoglyphs, and brand typosquatting — so the model sees a wider spread
of obfuscation during training. All transforms are pure string operations with
no network access (SSRF invariant), reusing the brand / confusable signal sets
from ml.feature_extractor so augmentation stays in sync with detection.

Usage (normally driven by scripts/build_dataset.py):

    from ml.augment import brand_squat_urls, mutate_phishing_urls

    squats = brand_squat_urls(per_brand=20)
    mutations = mutate_phishing_urls(phishing_urls, per_url=1)
"""

from __future__ import annotations

import random
import string
from urllib.parse import urlparse

from ml.feature_extractor import _CONFUSABLES, BRAND_DOMAINS

# ─── Lookalike digit substitutions (leet-speak) ─────────────────────────────
LEET_MAP: dict[str, str] = {"o": "0", "i": "1", "l": "1", "e": "3", "a": "4", "s": "5", "t": "7"}

# ─── Invert the confusables table: latin letter -> [unicode lookalikes] ─────
_CONFUSABLE_LATIN: dict[str, list[str]] = {}
for _unicode, _latin in _CONFUSABLES.items():
    _CONFUSABLE_LATIN.setdefault(_latin, []).append(_unicode)

# ─── Suspicious path tokens commonly appended by phishers ───────────────────
SUSPICIOUS_PATH_TOKENS: list[str] = [
    "/login",
    "/verify",
    "/account",
    "/secure",
    "/update",
    "/signin",
    "/auth",
    "/confirm",
    "/unlock",
]

# ─── Benign-looking subdomains attackers prepend ────────────────────────────
BENIGN_SUBDOMAINS: list[str] = ["webmail", "secure", "login", "support", "portal"]

# ─── Common TLDs for synthetic brand squats ─────────────────────────────────
_SQUAT_TLDS: list[str] = ["com", "net", "org", "info", "xyz", "top", "live"]


def leet_variants(token: str) -> list[str]:
    """Return leet-speak variants of a domain token (o->0, i->1, ...).

    Only tokens that actually contain a substitutable letter produce variants.
    """
    token = token.lower()
    results: set[str] = set()
    for char, digit in LEET_MAP.items():
        if char in token:
            results.add(token.replace(char, digit))
    return sorted(results)


def homoglyph_variants(token: str) -> list[str]:
    """Return Unicode homoglyph variants of a domain token (a->а, e->е, ...)."""
    token = token.lower()
    results: set[str] = set()
    for char, confusables in _CONFUSABLE_LATIN.items():
        if char in token:
            for confusable in confusables:
                results.add(token.replace(char, confusable))
    return sorted(results)


def typosquat_variants(token: str) -> list[str]:
    """Return single-edit typosquat variants of a token (delete/substitute/
    swap/insert), excluding the exact token itself."""
    token = token.lower()
    if not token:
        return []
    variants: set[str] = set()

    # Deletion + substitution at every position.
    for i in range(len(token)):
        variants.add(token[:i] + token[i + 1 :])
        for char in string.ascii_lowercase:
            if char != token[i]:
                variants.add(token[:i] + char + token[i + 1 :])

    # Adjacent-character swaps.
    for i in range(len(token) - 1):
        variants.add(token[:i] + token[i + 1] + token[i] + token[i + 2 :])

    # Single-character insertion.
    for i in range(len(token) + 1):
        for char in string.ascii_lowercase:
            variants.add(token[:i] + char + token[i:])

    return sorted(v for v in variants if v != token)


def brand_squat_urls(
    brands: dict[str, str] | None = None,
    per_brand: int = 20,
    seed: int = 42,
) -> list[str]:
    """Generate synthetic phishing URLs by typosquatting, leet-speaking, and
    homoglyph-substituting popular brand domains.

    Each generated URL points at a squatted brand host (never the official
    apex) and carries a suspicious path token — the classic phishing shape.
    """
    rng = random.Random(seed)
    brands = brands or BRAND_DOMAINS
    urls: list[str] = []
    for brand in brands:
        sld = brand.lower()
        pool: list[str] = []
        pool.extend(leet_variants(sld))
        pool.extend(homoglyph_variants(sld))
        pool.extend(typosquat_variants(sld))
        if not pool:
            continue
        chosen = rng.sample(pool, k=min(per_brand, len(pool)))
        for squatted in chosen:
            tld = rng.choice(_SQUAT_TLDS)
            token = rng.choice(SUSPICIOUS_PATH_TOKENS)
            scheme = "https" if rng.random() < 0.7 else "http"
            urls.append(f"{scheme}://{squatted}.{tld}{token}")
    return urls


def mutate_phishing_urls(
    urls: list[str],
    per_url: int = 1,
    seed: int = 42,
) -> list[str]:
    """Expand an existing set of phishing URLs by applying one random
    obfuscation (leet, homoglyph, typosquat, subdomain-prefix, path token) per
    output URL."""
    if not urls:
        return []
    rng = random.Random(seed)
    results: list[str] = []
    for url in urls:
        for _ in range(per_url):
            results.append(_mutate_one(url, rng))
    return results


def _mutate_one(url: str, rng: random.Random) -> str:
    """Apply a single random obfuscation to one URL."""
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    port = ""
    if ":" in host:
        host, _, port = host.partition(":")
        port = ":" + port

    parts = host.split(".")
    if len(parts) >= 2 and parts[-2]:
        sld = parts[-2]
        roll = rng.random()
        if roll < 0.30:
            variants = leet_variants(sld)
            parts[-2] = rng.choice(variants) if variants else sld
        elif roll < 0.55:
            variants = homoglyph_variants(sld)
            parts[-2] = rng.choice(variants) if variants else sld
        elif roll < 0.75:
            variants = typosquat_variants(sld)
            parts[-2] = rng.choice(variants) if variants else sld
        else:
            parts = [rng.choice(BENIGN_SUBDOMAINS)] + parts

    new_host = ".".join(parts) + port
    path = parsed.path.rstrip("/")
    if rng.random() < 0.5:
        path = path + rng.choice(SUSPICIOUS_PATH_TOKENS)
    return parsed._replace(netloc=new_host, path=path).geturl()
