"""
test_build_dataset.py
=====================
Unit tests for scripts.build_dataset — the multi-source dataset extension
pipeline. No network and no committed dataset are required; feeds are
monkeypatched and inputs are small tmp CSVs.
"""

import pandas as pd
import pytest

from scripts.build_dataset import (
    _cc_tld_variants,
    _dedupe,
    _fetch_openphish,
    _fetch_phishtank,
    _load_extra_dir,
    _load_known_feed,
    _read_urls_csv,
    _standardize_urls,
    build_extended_dataset,
)

# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def phiusiil_csv(tmp_path):
    df = pd.DataFrame(
        {"URL": ["http://evil.com/login", "https://github.com/user"], "label": [0, 1]}
    )
    path = tmp_path / "phishing_urls.csv"
    df.to_csv(path, index=False)
    return str(path)


# ─── _read_urls_csv ───────────────────────────────────────────────────────────


def test_read_urls_csv_detects_uppercase_url_column(tmp_path):
    path = tmp_path / "a.csv"
    pd.DataFrame({"URL": ["http://a.com"], "label": [0]}).to_csv(path, index=False)
    df = _read_urls_csv(path)
    assert list(df.columns) == ["url", "label"]
    assert df["url"].iloc[0] == "http://a.com"


def test_read_urls_csv_missing_label_raises(tmp_path):
    path = tmp_path / "b.csv"
    pd.DataFrame({"url": ["http://a.com"]}).to_csv(path, index=False)
    with pytest.raises(ValueError, match="label"):
        _read_urls_csv(path)


def test_read_urls_csv_explicit_label(tmp_path):
    path = tmp_path / "c.csv"
    pd.DataFrame({"url": ["http://a.com"]}).to_csv(path, index=False)
    df = _read_urls_csv(path, label=1)
    assert df["label"].iloc[0] == 1


# ─── Feed fetchers (monkeypatched urllib) ────────────────────────────────────


class _FakeResponse:
    def __init__(self, content: bytes):
        self._content = content

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._content


def test_fetch_openphish_parses_lines(monkeypatch):
    monkeypatch.setattr(
        "scripts.build_dataset.urllib.request.urlopen",
        lambda url, timeout: _FakeResponse(b"http://phish1.com/login\nhttp://phish2.com/\n"),
    )
    urls = _fetch_openphish(timeout=5)
    assert urls == ["http://phish1.com/login", "http://phish2.com/"]


def test_fetch_phishtank_parses_url_column(monkeypatch):
    monkeypatch.setattr(
        "scripts.build_dataset.urllib.request.urlopen",
        lambda url, timeout: _FakeResponse(
            b"phish_id,url\n1,http://phish1.com/login\n2,http://phish2.com/\n"
        ),
    )
    urls = _fetch_phishtank("KEY", timeout=5)
    assert urls == ["http://phish1.com/login", "http://phish2.com/"]


# ─── Extra dir ────────────────────────────────────────────────────────────────


def test_load_extra_dir_reads_all_csvs(tmp_path):
    pd.DataFrame({"url": ["http://extra1.com"], "label": [0]}).to_csv(
        tmp_path / "x1.csv", index=False
    )
    pd.DataFrame({"url": ["http://extra2.com"], "label": [1]}).to_csv(
        tmp_path / "x2.csv", index=False
    )
    df = _load_extra_dir(tmp_path)
    assert len(df) == 2
    assert set(df["url"]) == {"http://extra1.com", "http://extra2.com"}


def test_load_extra_dir_missing_dir_is_empty(tmp_path):
    df = _load_extra_dir(tmp_path / "does-not-exist")
    assert df.empty


# ─── Known feed loader ────────────────────────────────────────────────────────


def test_load_known_feed_phishtank_shape(tmp_path):
    path = tmp_path / "verified_online.csv"
    pd.DataFrame(
        {
            "phish_id": [1, 2],
            "url": ["http://phish1.com", "http://phish2.com"],
            "verified": ["yes", "yes"],
            "target": ["PayPal", "Other"],
        }
    ).to_csv(path, index=False)
    df = _load_known_feed(path)
    assert len(df) == 2
    assert (df["label"] == 0).all()
    assert set(df["url"]) == {"http://phish1.com", "http://phish2.com"}


def test_load_known_feed_urlhaus_shape(tmp_path):
    path = tmp_path / "csv.txt"
    path.write_text(
        "# abuse.ch URLhaus Database Dump (CSV)\n"
        "# Last updated: 2026-08-17\n"
        "3904577,2026-08-17 01:37:26,http://evil1.com/i,online,2026-08-17 01:37:26.1,malware_download,32-bit,https://urlhaus.abuse.ch/url/3904577/,geenensp\n"
        "3904576,2026-08-17 01:35:25,http://evil2.com/x,online,2026-08-17 01:40:16,malware_download,32-bit,https://urlhaus.abuse.ch/url/3904576/,geenensp\n",
        encoding="utf-8",
    )
    df = _load_known_feed(path)
    assert len(df) == 2
    assert (df["label"] == 0).all()
    assert set(df["url"]) == {"http://evil1.com/i", "http://evil2.com/x"}


def test_load_known_feed_unrecognized_raises(tmp_path):
    path = tmp_path / "unknown.csv"
    pd.DataFrame({"foo": [1, 2], "bar": [3, 4]}).to_csv(path, index=False)
    with pytest.raises(ValueError, match="Unrecognized feed"):
        _load_known_feed(path)


# ─── ccTLD variants ───────────────────────────────────────────────────────────


def test_cc_tld_variants_labels_legitimate():
    df = _cc_tld_variants(["in"])
    assert not df.empty
    assert (df["label"] == 1).all()
    assert all(u.endswith(".in/") for u in df["url"])


# ─── Standardize / dedupe ─────────────────────────────────────────────────────


def test_standardize_urls_drops_blanks():
    df = pd.DataFrame({"url": ["http://a.com", "   ", ""], "label": [0, 1, 0]})
    out = _standardize_urls(df)
    assert len(out) == 1
    assert out["url"].iloc[0] == "http://a.com"


def test_dedupe_is_case_insensitive():
    df = pd.DataFrame({"url": ["http://A.com", "http://a.com", "http://b.com"], "label": [0, 1, 1]})
    out = _dedupe(df)
    assert len(out) == 2
    assert out["url"].iloc[0] == "http://A.com"


# ─── Full pipeline (offline) ──────────────────────────────────────────────────


def test_build_extended_dataset_merges_and_augments(tmp_path, phiusiil_csv):
    out = tmp_path / "extended.csv"
    feed_path = tmp_path / "verified_online.csv"
    pd.DataFrame(
        {"phish_id": [1], "url": ["http://feed-phish.com/login"], "verified": ["yes"]}
    ).to_csv(feed_path, index=False)
    result = build_extended_dataset(
        phiusiil_path=phiusiil_csv,
        out_path=str(out),
        extra_dir=str(tmp_path / "no-extra"),
        data_dir=str(tmp_path),
        fetch_openphish=False,
        augment=True,
        augment_per_brand=5,
        mutate_per_url=1,
        cc_tlds=["in"],
        seed=42,
    )
    assert len(result) > 2  # base 2 + feed + ccTLD variants + synthetic
    assert set(result.columns) == {"url", "label"}
    assert out.is_file()
    # No blank URLs and no duplicate URLs survive.
    assert (result["url"].astype(str).str.len() > 0).all()
    assert result["url"].str.lower().is_unique
    assert "http://feed-phish.com/login" in set(result["url"])


def test_build_extended_dataset_writes_report(tmp_path, phiusiil_csv):
    out = tmp_path / "extended.csv"
    build_extended_dataset(
        phiusiil_path=phiusiil_csv,
        out_path=str(out),
        extra_dir=str(tmp_path / "no-extra"),
        augment=False,
        cc_tlds=["in"],
        seed=1,
    )
    assert (tmp_path / "extended.json").is_file()
