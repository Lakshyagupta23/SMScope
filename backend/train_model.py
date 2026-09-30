"""Train an experimental IsolationForest from provenance-bearing input.

Examples:
  python train_model.py --features sessions.json --provenance provenance.json --output models/baseline-v2.pkl
  python train_model.py --pcap baseline.pcapng --provenance provenance.json --output models/baseline-v2.pkl
  python train_model.py --synthetic --seed 42 --output models/experimental-v2.pkl

No validation/accuracy claims are made. No input is jittered or called authentic.
Existing models are protected unless --overwrite is explicitly supplied.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform

from anomaly_detector import (BUNDLE_VERSION, SCHEMA_VERSION, FEATURE_NAMES,
                              MODEL_FEATURE_NAMES, extract_feature_evidence, vectorize)


def _digest(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _provenance(path):
    if not path:
        raise ValueError("Independent input requires --provenance JSON.")
    with open(path, "r", encoding="utf-8") as source:
        provenance = json.load(source)
    if not isinstance(provenance, dict) or any(not isinstance(provenance.get(k), str) or not provenance[k].strip()
                                              for k in ("source", "collected_at", "collection_method", "dataset_id")):
        raise ValueError("Provenance requires source, collected_at, collection_method and dataset_id strings.")
    when = dt.datetime.fromisoformat(provenance["collected_at"].replace("Z", "+00:00"))
    if when.tzinfo is None:
        raise ValueError("Provenance collected_at requires a timezone.")
    if provenance.get("independently_sourced") is not True:
        raise ValueError("Independent input provenance must assert independently_sourced=true; use --synthetic for experiments.")
    return provenance


def _load_features(path):
    with open(path, "r", encoding="utf-8") as source:
        data = json.load(source)
    if isinstance(data, list):
        if any(not isinstance(row, dict) for row in data):
            raise ValueError("Session input must contain dictionaries.")
        return [list(extract_feature_evidence(row)["values"].values()) for row in data]
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION or data.get("feature_names") != FEATURE_NAMES:
        raise ValueError("Feature matrix schema/version mismatch.")
    rows = data.get("rows")
    if not isinstance(rows, list):
        raise ValueError("Feature matrix rows must be an array.")
    return rows


def _synthetic_rows(seed, count=256):
    """Clearly synthetic distributions, with related timing/size features derived."""
    import numpy as np
    rng = np.random.default_rng(seed)
    rows = []
    for _ in range(count):
        packets = int(rng.integers(10, 300))
        duration = float(rng.uniform(0.1, 60))
        average_size = int(rng.integers(80, 1200))
        rows.append([int(rng.integers(5, 25)), int(rng.integers(0, 2)), 0,
                     2048, 1, packets, packets * average_size, duration,
                     duration / (packets - 1), float(rng.uniform(3, 8))])
    return rows


def train_and_save(*, output, features=None, pcap=None, provenance=None,
                   synthetic=False, seed=42, overwrite=False):
    import joblib
    import numpy as np
    import sklearn
    from sklearn.ensemble import IsolationForest
    if sum((bool(features), bool(pcap), bool(synthetic))) != 1:
        raise ValueError("Choose exactly one of features, pcap or synthetic.")
    destination = Path(output)
    if destination.exists() and not overwrite:
        raise FileExistsError("Model exists; explicit --overwrite is required.")
    if synthetic:
        rows = _synthetic_rows(seed)
        source = {"source": "synthetic experimental feature distributions", "independently_sourced": False,
                  "dataset_id": f"synthetic-v2-seed-{seed}", "collection_method": "numpy seeded generator"}
    else:
        source = _provenance(provenance)
        input_path = features or pcap
        before = _digest(input_path)
        if pcap:
            from pcap_parser import parse_pcap
            rows = [list(extract_feature_evidence(s)["values"].values()) for s in parse_pcap(pcap)]
        else:
            rows = _load_features(features)
        if before != _digest(input_path):
            raise ValueError("Training input changed during extraction.")
        source.update(input_sha256=before, input_filename=Path(input_path).name,
                      provenance_sha256=_digest(provenance))
    if len(rows) < 20:
        raise ValueError("At least 20 independently observed feature rows are required (not a validation guarantee).")
    for row in rows:
        if not isinstance(row, (list, tuple)) or len(row) != len(FEATURE_NAMES):
            raise ValueError("Feature row width mismatch.")
        for i, value in enumerate(row):
            if value is not None and (not isinstance(value, (int, float)) or not np.isfinite(value) or value < 0):
                raise ValueError("Features must be finite nonnegative numbers or null.")
            if i in (1, 2) and value not in (None, 0, 1):
                raise ValueError("STARTTLS observations must be 0, 1 or null.")
            if i == 9 and value is not None and value > 8:
                raise ValueError("Byte entropy must be between 0 and 8.")
    imputation, missingness = [], {}
    for i, name in enumerate(FEATURE_NAMES):
        observed = [row[i] for row in rows if row[i] is not None]
        imputation.append(float(np.median(observed)) if observed else 0.0)
        missingness[name] = 1 - len(observed) / len(rows)
    if all(all(v is None for v in row) for row in rows):
        raise ValueError("No observed training features.")
    matrix = np.asarray([vectorize(row, imputation) for row in rows], dtype=float)
    model = IsolationForest(n_estimators=100, contamination="auto", random_state=seed)
    model.fit(matrix)
    bundle = {
        "bundle_version": BUNDLE_VERSION, "schema_version": SCHEMA_VERSION,
        "feature_names": MODEL_FEATURE_NAMES, "model_version": "isolationforest-v2",
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "isolation_forest": model, "imputation": imputation,
        "provenance": source, "experimental": True, "seed": seed, "training_rows": len(rows),
        "training_missingness": missingness,
        "evaluation": {"status": "not_evaluated", "accuracy": None,
                       "limitations": "No independent holdout/labeled evaluation or calibrated threat probability; baseline outliers only."},
        "library_versions": {"sklearn": sklearn.__version__, "numpy": np.__version__,
                             "python": ".".join(platform.python_version_tuple()[:2])},
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive create protects against a concurrent overwrite when not requested.
    with open(destination, "wb" if overwrite else "xb") as target:
        joblib.dump(bundle, target)
    return {"path": str(destination), "sha256": _digest(destination), "training_rows": len(rows),
            "experimental": True, "evaluation": "not_evaluated"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--features")
    inputs.add_argument("--pcap")
    inputs.add_argument("--synthetic", action="store_true")
    parser.add_argument("--provenance")
    parser.add_argument("--output", required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(train_and_save(**vars(args)), indent=2))
    except Exception as exc:
        parser.exit(1, f"Training failed: {exc}\n")


if __name__ == "__main__":
    main()
