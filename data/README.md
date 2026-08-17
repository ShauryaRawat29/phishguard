# Dataset — Download Instructions

The base dataset used for training PhishGuard is **PhiUSIIL Phishing URL Dataset** (~235,000 URLs).

It is **not committed to this repository** due to its size. Follow the steps below to download it before running the training notebook.

---

## Option 1: Download from Kaggle (Recommended)

1. Create a free account at [kaggle.com](https://www.kaggle.com) if you don't have one.
2. Visit the dataset page:
   **https://www.kaggle.com/datasets/hemanthd007/phiusiil-phishing-url-dataset**
3. Click **Download** to get the ZIP file.
4. Extract the CSV file and place it in this `data/` directory.
5. Rename it to `phishing_urls.csv` if it has a different name.

## Option 2: Download from UCI ML Repository

1. Visit: **https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset**
2. Download the dataset ZIP.
3. Extract and place the CSV in this `data/` directory as `phishing_urls.csv`.

---

## Expected File After Download

```
data/
└── phishing_urls.csv    ← ~235k rows, columns: url, label
```

## Dataset Details

| Property | Value |
|---|---|
| Total URLs | ~235,795 |
| Legitimate URLs | ~134,850 |
| Phishing URLs | ~100,945 |
| Label column | `label` (0 = phishing, 1 = legitimate) |
| URL column | `url` |

> Note: the raw PhiUSIIL dataset encodes `0 = phishing`, `1 = legitimate`.
> `ml/train.py` converts this so that internally `y = 1` always means phishing.

---

## Extending the Dataset (Phase 7)

PhishGuard can combine the PhiUSIIL base with live phishing feeds, user CSVs,
deterministic synthetic augmentation, and international ccTLD variants into a
single training CSV via `scripts/build_dataset.py`:

```bash
# Offline: PhiUSIIL + any data/extra/*.csv + known dumps + synthetic + ccTLD
python scripts/build_dataset.py --augment --cc-tlds in br de jp

# Online: also pull the OpenPhish feed live (and PhishTank with an API key)
python scripts/build_dataset.py --openphish --phishtank-key <KEY> --augment
```

Output: `data/phishing_urls_extended.csv` (gitignored) plus a JSON report.

### Known feed dumps (dropped straight into `data/`)

These are recognized by filename and parsed automatically (all phishing):

| File | Source | Notes |
|---|---|---|
| `verified_online.csv` | PhishTank verified-online feed | has a `url` column |
| `csv.txt` | URLhaus full dump (abuse.ch) | no header; `#` comment lines skipped |

### Extra CSVs (`data/extra/*.csv`)

Any CSV with `url` + `label` columns (0 = phishing, 1 = legitimate) placed in
`data/extra/` is merged as-is. Other columns are ignored.

### Synthetic augmentation (`ml/augment.py`)

`--augment` adds deterministic, stdlib-only synthetic phishing URLs:
leet-speak (`paypal`→`paypa1`), Unicode homoglyphs (`аpple`), and single-edit
brand typosquats, each with a suspicious path token.

### ccTLD legitimate variants (`--cc-tlds`)

Adds international endpoints of trusted apex domains (e.g. `google.co.in`)
labeled legitimate, giving the legitimate class geographic spread.

### Train on the extended dataset

```bash
python ml/train.py --dataset data/phishing_urls_extended.csv
```

---

## Verification

After downloading, open the Jupyter notebook at `notebooks/phishing_detection.ipynb` and run **Cell 1** to verify the dataset loads correctly.
