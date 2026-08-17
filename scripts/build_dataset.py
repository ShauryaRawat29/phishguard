"""
build_dataset.py
================
Assemble an extended PhishGuard training dataset from multiple sources.

Combines the committed PhiUSIIL dataset with live phishing feeds (PhishTank,
OpenPhish), optional user-supplied CSVs in data/extra/, deterministic synthetic
phishing augmentation (ml.augment), and international ccTLD variants of trusted
apex domains. Output is standardized to two columns — `url`, `label` — where
`0 = phishing` and `1 = legitimate` (same convention as the raw PhiUSIIL CSV).

Network use is limited to fetching known phishing feeds AT BUILD TIME. The
runtime server never makes network requests (SSRF invariant is unchanged).

Usage:
    python scripts/build_dataset.py --out data/phishing_urls_extended.csv
    python scripts/build_dataset.py --phishtank-key <KEY> --openphish
    python scripts/build_dataset.py --no-augment --cc-tlds in br de

Flags:
    --phiusiil PATH     PhiUSIIL CSV (default: data/phishing_urls.csv)
    --out PATH          Output CSV (default: data/phishing_urls_extended.csv)
    --extra-dir PATH    Directory of extra user CSVs (default: data/extra)
    --phishtank-key KEY PhishTank API key (or env PHISHTANK_API_KEY)
    --openphish         Fetch the OpenPhish public feed
    --timeout SEC       Feed fetch timeout (default: 15)
    --augment           Add synthetic phishing URLs from ml.augment
    --augment-per-brand N   Squats per brand (default: 20)
    --mutate-per-url N      Mutations per real phishing URL (default: 0)
    --cc-tlds LIST      Country-code TLDs for legitimate diversity (space-sep)
    --seed N            RNG seed for deterministic augmentation (default: 42)
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.augment import brand_squat_urls, mutate_phishing_urls
from ml.feature_extractor import TOP_LEGITIMATE_DOMAINS

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PHIUSIIL = ROOT / "data" / "phishing_urls.csv"
DEFAULT_OUT = ROOT / "data" / "phishing_urls_extended.csv"
DEFAULT_EXTRA_DIR = ROOT / "data" / "extra"

OPENPHISH_FEED = "https://openphish.com/feed.txt"
PHISHTANK_FEED = "https://data.phishtank.com/data/{key}/online-valid.csv"

_URL_COLUMNS = ("url", "URL")


def _read_urls_csv(path: str | Path, label: int | None = None) -> pd.DataFrame:
    """Load a (url, label) CSV. If the file has no label column and `label` is
    given, every row is assigned that label."""
    df = pd.read_csv(path)
    url_col = next((c for c in df.columns if c in _URL_COLUMNS), df.columns[0])
    df = df.rename(columns={url_col: "url"})
    if "label" not in df.columns:
        if label is None:
            raise ValueError(f"'{path}' has no label column; pass a label explicitly.")
        df["label"] = int(label)
    else:
        df["label"] = df["label"].astype(int)
    return df[["url", "label"]].dropna()


# ─── Known feed files placed directly in the data/ directory ────────────────
# These are downloaded dumps that PhishGuard recognizes by name and shape.
# All rows are phishing (label 0) by definition of the source.
_URLHAUS_COLUMNS = [
    "id",
    "dateadded",
    "url",
    "url_status",
    "last_online",
    "threat",
    "tags",
    "urlhaus_link",
    "reporter",
]


def _load_known_feed(path: str | Path) -> pd.DataFrame:
    """Load a PhishTank or URLhaus dump by detecting its column shape.

    - PhishTank verified_online.csv: has a `url` column, no `label`.
    - URLhaus csv dump: no header (9 columns), `url` is the third column.
    """
    df = pd.read_csv(path, comment="#")
    if "url" in [c.lower() for c in df.columns]:
        url_col = next(c for c in df.columns if c.lower() == "url")
        urls = df[url_col]
    elif df.shape[1] == len(_URLHAUS_COLUMNS) and pd.api.types.is_integer_dtype(df.iloc[:, 0]):
        df = pd.read_csv(path, comment="#", header=None, names=_URLHAUS_COLUMNS)
        urls = df["url"]
    else:
        raise ValueError(f"Unrecognized feed format in '{path}'.")
    return pd.DataFrame({"url": urls.dropna().astype(str), "label": 0}).reset_index(drop=True)


def _fetch_openphish(timeout: int = 15) -> list[str]:
    """Download the OpenPhish feed: one phishing URL per line."""
    with urllib.request.urlopen(OPENPHISH_FEED, timeout=timeout) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    return [line.strip() for line in text.splitlines() if line.strip()]


def _fetch_phishtank(api_key: str, timeout: int = 15) -> list[str]:
    """Download the PhishTank online-valid feed (CSV with a `url` column)."""
    url = PHISHTANK_FEED.format(key=api_key)
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    df = pd.read_csv(io.StringIO(raw))
    url_col = next((c for c in df.columns if c.lower() == "url"), None)
    if url_col is None:
        raise ValueError("PhishTank feed has no 'url' column.")
    return df[url_col].dropna().astype(str).tolist()


def _load_extra_dir(extra_dir: str | Path) -> pd.DataFrame:
    """Load every *.csv in a directory as an (url, label) table. Files without
    a label column are rejected — label ambiguity must be explicit."""
    extra_dir = Path(extra_dir)
    if not extra_dir.is_dir():
        return pd.DataFrame(columns=["url", "label"])
    frames: list[pd.DataFrame] = []
    for csv_file in sorted(extra_dir.glob("*.csv")):
        df = _read_urls_csv(csv_file)
        frames.append(df)
    if not frames:
        return pd.DataFrame(columns=["url", "label"])
    return pd.concat(frames, ignore_index=True)


def _cc_tld_variants(cc_tlds: list[str]) -> pd.DataFrame:
    """Country-code TLD variants of trusted apex domains, labeled legitimate.

    e.g. google.com -> https://www.google.co.in/ — the real international
    endpoints of those brands, giving the legitimate class geographic spread.
    """
    rows: list[dict[str, object]] = []
    for apex in sorted(TOP_LEGITIMATE_DOMAINS):
        sld_tld = apex.rsplit(".", 1)
        if len(sld_tld) != 2:
            continue
        sld, _ = sld_tld
        for cc in cc_tlds:
            rows.append({"url": f"https://www.{sld}.{cc}/", "label": 1})
    return pd.DataFrame(rows, columns=["url", "label"])


def _standardize_urls(df: pd.DataFrame) -> pd.DataFrame:
    """Drop empty / whitespace URLs and make the url column lowercase-safe
    (preserving case, but dropping rows that are blank)."""
    df = df.copy()
    df["url"] = df["url"].astype(str).str.strip()
    return df[df["url"].str.len() > 0]


def _dedupe(df: pd.DataFrame) -> pd.DataFrame:
    """Drop duplicate URLs (case-insensitive), keeping the first occurrence."""
    df = df.copy()
    df["_key"] = df["url"].str.lower()
    df = df.drop_duplicates(subset="_key", keep="first")
    return df.drop(columns="_key").reset_index(drop=True)


def _build_report(df: pd.DataFrame, out_path: str | Path) -> None:
    phishing = int((df["label"] == 0).sum())
    legitimate = int((df["label"] == 1).sum())
    report = {
        "total_urls": int(len(df)),
        "phishing": phishing,
        "legitimate": legitimate,
        "class_ratio_phishing": round(phishing / max(len(df), 1), 4),
        "output_file": str(out_path),
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    report_path = Path(out_path).with_suffix(".json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print("=" * 60)
    print("Extended dataset report")
    print("-" * 60)
    for key, value in report.items():
        print(f"  {key:<22}: {value}")
    print("=" * 60)


def build_extended_dataset(
    phiusiil_path: str | Path = DEFAULT_PHIUSIIL,
    out_path: str | Path = DEFAULT_OUT,
    extra_dir: str | Path = DEFAULT_EXTRA_DIR,
    data_dir: str | Path = ROOT / "data",
    phishtank_key: str | None = None,
    fetch_openphish: bool = False,
    timeout: int = 15,
    augment: bool = False,
    augment_per_brand: int = 20,
    mutate_per_url: int = 0,
    cc_tlds: list[str] | None = None,
    seed: int = 42,
) -> pd.DataFrame:
    """Assemble the extended dataset and write it to `out_path`."""
    if not os.path.exists(phiusiil_path):
        print(f"Error: PhiUSIIL dataset not found at '{phiusiil_path}'.", file=sys.stderr)
        sys.exit(1)

    print(f"[1/6] Loading PhiUSIIL dataset from '{phiusiil_path}'...")
    phiusiil = _read_urls_csv(phiusiil_path)
    print(f"      {len(phiusiil)} rows")

    print(f"[2/6] Loading extra CSVs from '{extra_dir}'...")
    extra = _load_extra_dir(extra_dir)
    print(f"      {len(extra)} rows")

    print(f"[2b/6] Loading known feed dumps from '{data_dir}'...")
    known_feed_frames: list[pd.DataFrame] = []
    for known_name in ("verified_online.csv", "csv.txt"):
        known_path = Path(data_dir) / known_name
        if known_path.is_file():
            try:
                frame = _load_known_feed(known_path)
                known_feed_frames.append(frame)
                print(f"      {known_name}: {len(frame)} phishing URLs")
            except Exception as exc:  # noqa: BLE001 - best-effort feed parsing
                print(f"      WARNING: {known_name} skipped ({exc})")
    print(f"      {sum(len(f) for f in known_feed_frames)} known-feed rows total")

    feed_phishing: list[str] = []
    if phishtank_key:
        print("[3/6] Fetching PhishTank online-valid feed...")
        try:
            feed_phishing.extend(_fetch_phishtank(phishtank_key, timeout))
            print(f"      {len(feed_phishing)} URLs")
        except Exception as exc:  # noqa: BLE001 - feed availability is best-effort
            print(f"      WARNING: PhishTank fetch failed ({exc})")
    if fetch_openphish:
        print("[3/6] Fetching OpenPhish feed...")
        try:
            feed_phishing.extend(_fetch_openphish(timeout))
            print(f"      {len(feed_phishing)} URLs")
        except Exception as exc:  # noqa: BLE001 - feed availability is best-effort
            print(f"      WARNING: OpenPhish fetch failed ({exc})")

    print("[4/6] Applying deterministic augmentation...")
    synthetic: list[str] = []
    if augment:
        synthetic.extend(brand_squat_urls(per_brand=augment_per_brand, seed=seed))
        real_phishing = phiusiil.loc[phiusiil["label"] == 0, "url"].tolist()
        synthetic.extend(mutate_phishing_urls(real_phishing, per_url=mutate_per_url, seed=seed))
    print(f"      {len(synthetic)} synthetic phishing URLs")

    print("[5/6] Adding international ccTLD legitimate variants...")
    cc_df = _cc_tld_variants(cc_tlds or [])
    print(f"      {len(cc_df)} rows")

    print("[6/6] Merging, standardizing, deduplicating...")
    frames = [
        phiusiil,
        extra,
        pd.DataFrame({"url": feed_phishing, "label": 0}),
        pd.DataFrame({"url": synthetic, "label": 0}),
        cc_df,
    ]
    frames.extend(known_feed_frames)
    merged = pd.concat([f for f in frames if len(f) > 0], ignore_index=True)
    merged = _standardize_urls(merged)
    merged = _dedupe(merged)
    merged = merged.sample(frac=1.0, random_state=seed).reset_index(drop=True)

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    merged.to_csv(out_path, index=False)
    print(f"Wrote {len(merged)} URLs to '{out_path}'")

    _build_report(merged, out_path)
    return merged


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phiusiil", default=str(DEFAULT_PHIUSIIL))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument("--extra-dir", default=str(DEFAULT_EXTRA_DIR))
    parser.add_argument("--phishtank-key", default=None)
    parser.add_argument("--openphish", action="store_true")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--augment", action="store_true")
    parser.add_argument("--augment-per-brand", type=int, default=20)
    parser.add_argument("--mutate-per-url", type=int, default=0)
    parser.add_argument("--cc-tlds", nargs="*", default=[])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--data-dir", default=str(ROOT / "data"))
    args = parser.parse_args()

    api_key = args.phishtank_key or os.environ.get("PHISHTANK_API_KEY")
    build_extended_dataset(
        phiusiil_path=args.phiusiil,
        out_path=args.out,
        extra_dir=args.extra_dir,
        data_dir=args.data_dir,
        phishtank_key=api_key,
        fetch_openphish=args.openphish,
        timeout=args.timeout,
        augment=args.augment,
        augment_per_brand=args.augment_per_brand,
        mutate_per_url=args.mutate_per_url,
        cc_tlds=args.cc_tlds,
        seed=args.seed,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
