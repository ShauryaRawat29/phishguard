# Dataset — Download Instructions

The dataset used for training PhishGuard is **PhiUSIIL Phishing URL Dataset** (~235,000 URLs).

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

## Verification

After downloading, open the Jupyter notebook at `notebooks/phishing_detection.ipynb` and run **Cell 1** to verify the dataset loads correctly.
