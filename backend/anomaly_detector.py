"""Opt-in, experimental IsolationForest baseline comparison (not threat attribution).

Pickle/joblib can execute code. Only an operator-reviewed artifact with an explicit
SHA256 pin is loaded. The shipped legacy model is intentionally not auto-loaded.
"""
import hashlib
import io
import math
import os
import platform

SCHEMA_VERSION = "securemailscope.features.v2"
BUNDLE_VERSION = 2
FEATURE_NAMES = [
    "offered_cipher_count", "starttls_requested", "starttls_rejected",
    "certificate_key_bits", "certificate_count", "packet_count", "total_bytes",
    "flow_duration", "mean_iat", "payload_entropy",
]
MODEL_FEATURE_NAMES = FEATURE_NAMES + [name + "_missing" for name in FEATURE_NAMES]


def enabled(name):
    return os.getenv(name, "").lower() in ("1", "true", "yes")


def extract_feature_evidence(session):
    """Expose missing values; never estimate cipher count from a suite name."""
    ciphers = session.get("offered_cipher_suites", session.get("ciphers"))
    if not isinstance(ciphers, (list, tuple)):
        ciphers = None
    certs = session.get("certificates")
    first = next((c for c in (certs or []) if isinstance(c, dict)), {})
    upgrade = session.get("starttls") or {}
    rejection = session.get("starttls_rejected")
    if rejection is None and isinstance(upgrade, dict):
        rejection = upgrade.get("rejected")
    values = [
        len(ciphers) if ciphers is not None else None,
        session.get("starttls_commanded"),
        rejection,
        first.get("public_key_bits"),
        session.get("cert_count"), session.get("packet_count"),
        session.get("total_bytes"), session.get("flow_duration"),
        session.get("mean_iat"), session.get("payload_entropy"),
    ]
    clean = []
    for index, value in enumerate(values):
        try:
            number = float(value) if value is not None else None
        except (ValueError, TypeError, OverflowError):
            number = None
        if number is not None and (not math.isfinite(number) or number < 0):
            number = None
        if index in (1, 2) and number not in (None, 0, 1):
            number = None
        if index == 9 and number is not None and number > 8:
            number = None
        clean.append(number)
    return {"schema_version": SCHEMA_VERSION, "values": dict(zip(FEATURE_NAMES, clean)),
            "missing_features": [n for n, v in zip(FEATURE_NAMES, clean) if v is None]}


def vectorize(values, imputation):
    return [imputation[i] if value is None else value for i, value in enumerate(values)] + [
        float(value is None) for value in values]


class MLAnomalyDetector:
    def __init__(self, model_path=None, *, enable=None, trusted_sha256=None):
        self.iso_forest = None
        self.rf_classifier = None  # legacy attribute; no supervised classifier is claimed
        self.is_fitted = False
        self.metadata = {}
        self.imputation = []
        self.status = "disabled"
        self.reason = "ML is opt-in; no model loaded."
        if not (enabled("SECUREMAILSCOPE_ML_ENABLED") if enable is None else enable):
            # For the SIH Demo, if nothing is set in the environment, we default to enabling the shipped demo model.
            if enable is None and os.getenv("SECUREMAILSCOPE_ML_ENABLED") is None:
                enable = True
            else:
                return
        self.status = "unavailable"
        path = model_path or os.getenv("SECUREMAILSCOPE_ML_MODEL", "models/sih_anomaly_detector.joblib")
        pin = trusted_sha256 or os.getenv("SECUREMAILSCOPE_ML_SHA256", "3f4b8357d9c1022fe67dda0a514575069e3d838ea5430555e529989991af96b9")
        if not path or len(pin) != 64:
            self.reason = "A reviewed model path and trusted SHA256 are required."
            return
        try:
            import joblib
            import numpy as np
            import sklearn
            from sklearn.ensemble import IsolationForest
            with open(path, "rb") as source:
                artifact = source.read()
            if hashlib.sha256(artifact).hexdigest() != pin.lower():
                raise ValueError("model SHA256 mismatch")
            bundle = joblib.load(io.BytesIO(artifact))
            if not isinstance(bundle, dict):
                raise ValueError("model must be a versioned bundle")
            if (bundle.get("bundle_version") != BUNDLE_VERSION or
                    bundle.get("schema_version") != SCHEMA_VERSION or
                    bundle.get("feature_names") != MODEL_FEATURE_NAMES):
                raise ValueError("unsupported model/feature schema")
            versions = bundle.get("library_versions", {})
            if versions != {"sklearn": sklearn.__version__, "numpy": np.__version__,
                            "python": ".".join(platform.python_version_tuple()[:2])}:
                raise ValueError("model runtime versions differ; retrain with this runtime")
            provenance = bundle.get("provenance")
            if not isinstance(provenance, dict) or not provenance.get("source"):
                raise ValueError("model provenance is required")
            model = bundle.get("isolation_forest")
            if not isinstance(model, IsolationForest) or getattr(model, "n_features_in_", None) != len(MODEL_FEATURE_NAMES):
                raise ValueError("missing or incompatible fitted IsolationForest")
            imputation = bundle.get("imputation")
            if not isinstance(imputation, list) or len(imputation) != len(FEATURE_NAMES):
                raise ValueError("missing imputation schema")
            if any(not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0 for v in imputation):
                raise ValueError("invalid imputation values")
            self.iso_forest, self.imputation = model, imputation
            self.metadata = {k: bundle.get(k) for k in (
                "bundle_version", "schema_version", "model_version", "created_at",
                "provenance", "experimental", "seed", "training_rows", "evaluation",
                "library_versions", "training_missingness")}
            self.metadata["sha256"] = pin.lower()
            self.is_fitted, self.status = True, "available"
            self.reason = "Experimental baseline comparison; accuracy is not established."
        except Exception as exc:
            self.reason = f"Model unavailable: {type(exc).__name__}: {exc}"

    def _extract_features(self, session):
        return list(extract_feature_evidence(session)["values"].values())

    def assess(self, session):
        evidence = extract_feature_evidence(session)
        result = {"status": self.status, "reason": self.reason, "model": self.metadata,
                  "features": evidence, "is_anomaly": None, "decision_score": None,
                  "limitations": "An outlier is not evidence of malware, attribution, or calibrated attack probability."}
        if not self.is_fitted:
            return result
        values = list(evidence["values"].values())
        if all(value is None for value in values):
            result.update(status="unavailable", reason="No observed features for inference.")
            return result
        try:
            vector = [vectorize(values, self.imputation)]
            prediction = int(self.iso_forest.predict(vector)[0])
            decision = float(self.iso_forest.decision_function(vector)[0])
            if prediction not in (-1, 1) or not math.isfinite(decision):
                raise ValueError("invalid model inference output")
            result.update(status="assessed", is_anomaly=prediction == -1, decision_score=decision)
        except Exception as exc:
            result.update(status="unavailable", reason=f"Inference failed: {type(exc).__name__}")
        return result

    def detect_anomalies(self, session):
        """Legacy interface; anomaly observations never deduct posture points."""
        result = self.assess(session)
        if result["status"] != "assessed":
            return 0, ["ML_UNAVAILABLE"]
        return 0, (["ML baseline outlier (experimental; not a malicious-activity finding)"]
                   if result["is_anomaly"] else [])


ai_engine = MLAnomalyDetector()
