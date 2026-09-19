"""
SentinelX — Unit Test Suite
Tests for: deterministic detection, entropy, risk engine, redactor, policy engine, ML pipeline
Run with: python -m pytest backend/tests/ -v
"""

import sys, os, math, json, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ──────────────────────────────────────────────────────────────────────
# Fix 2 — Shannon Entropy (from train_eval)
# ──────────────────────────────────────────────────────────────────────

from train_eval import shannon_entropy

class TestShannonEntropy:
    def test_empty_string_returns_zero(self):
        assert shannon_entropy("") == 0.0

    def test_uniform_string_max_entropy(self):
        # "abcd" — 4 unique chars, each p=0.25
        H = shannon_entropy("abcd")
        assert abs(H - 2.0) < 0.001

    def test_repeated_char_zero_entropy(self):
        H = shannon_entropy("aaaaaaaaaa")
        assert H == 0.0

    def test_aws_key_high_entropy(self):
        # Real AWS key has high entropy
        H = shannon_entropy("AKIAIOSFODNN7EXAMPLEwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        assert H > 4.0, f"AWS key entropy too low: {H}"

    def test_benign_text_moderate_entropy(self):
        H = shannon_entropy("explain the difference between bfs and dfs algorithms")
        assert 3.0 < H < 5.5

# ──────────────────────────────────────────────────────────────────────
# Fix 3 — ML Pipeline (train_eval)
# ──────────────────────────────────────────────────────────────────────

from train_eval import train_and_evaluate, predict, CORPUS

class TestMLPipeline:
    @pytest.fixture(scope="class")
    def report(self):
        return train_and_evaluate()

    def test_report_has_required_keys(self, report):
        assert "metrics" in report
        assert "confusion_matrix" in report
        assert "train_size" in report
        assert "test_size" in report

    def test_80_20_split(self, report):
        # test_size should be ~20% of total corpus
        total = report["sample_size"]
        test  = report["test_size"]
        ratio = test / total
        assert 0.18 <= ratio <= 0.22, f"Split ratio off: {ratio}"

    def test_cv_f1_reported(self, report):
        assert "cv_f1_mean" in report["metrics"]
        assert "cv_f1_std"  in report["metrics"]
        cv_mean = report["metrics"]["cv_f1_mean"]
        assert cv_mean >= 0.80, f"CV F1 too low: {cv_mean}"

    def test_precision_no_false_positives(self, report):
        fp = report["confusion_matrix"]["false_positives"]
        assert fp == 0, f"False positives on test set: {fp}"

    def test_f1_above_threshold(self, report):
        f1 = report["metrics"]["f1_score"]
        assert f1 >= 0.85, f"F1 score too low: {f1}"

    def test_model_file_exists(self, report):
        model_path = report["model_metadata"]["model_file"]
        assert os.path.exists(model_path), f"Model file not found: {model_path}"

    def test_predict_aws_key_sensitive(self):
        result = predict("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE secret=wJalrXUtnFEMI/K7MDENG")
        assert result["sensitive"] is True, "AWS key must be classified sensitive"
        assert result["confidence"] >= 0.5

    def test_predict_benign_not_sensitive(self):
        result = predict("How does Dijkstra's algorithm work with a priority queue?")
        assert result["sensitive"] is False, "Benign text must not be classified sensitive"

    def test_predict_private_key_sensitive(self):
        result = predict("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----")
        assert result["sensitive"] is True

    def test_predict_returns_entropy(self):
        result = predict("some text here")
        assert "entropy" in result
        assert isinstance(result["entropy"], float)

    def test_corpus_has_min_samples(self):
        assert len(CORPUS) >= 150, f"Corpus too small: {len(CORPUS)} samples"

    def test_corpus_label_balance(self):
        labels = [d["label"] for d in CORPUS]
        pos = sum(labels)
        neg = len(labels) - pos
        ratio = pos / neg
        assert 0.5 <= ratio <= 2.0, f"Dataset too imbalanced: {pos} positive / {neg} negative"

# ──────────────────────────────────────────────────────────────────────
# Fix 4 — SecurityEvent model (main.py)
# ──────────────────────────────────────────────────────────────────────

from main import SecurityEvent, app
from fastapi.testclient import TestClient

client = TestClient(app)

class TestSecurityEventModel:
    def test_event_with_identity_fields(self):
        evt = SecurityEvent(
            timestamp=1700000000000,
            destination_category="EXTERNAL_AI",
            risk_score=97,
            action="BLOCK",
            employee_id="anmol@company.com",
            device_id="LAPTOP-ANMOL-001",
        )
        assert evt.employee_id == "anmol@company.com"
        assert evt.device_id   == "LAPTOP-ANMOL-001"

    def test_event_identity_fields_optional(self):
        # Identity fields must be optional for backwards compat
        evt = SecurityEvent(
            timestamp=1700000000000,
            destination_category="EXTERNAL_AI",
            risk_score=50,
            action="WARN",
        )
        assert evt.employee_id is None
        assert evt.device_id   is None

    def test_risk_score_range_valid(self):
        evt = SecurityEvent(
            timestamp=1700000000000,
            destination_category="INTERNAL",
            risk_score=0,
            action="ALLOW",
        )
        assert 0 <= evt.risk_score <= 100

    def test_risk_score_out_of_range_rejected(self):
        with pytest.raises(Exception):
            SecurityEvent(
                timestamp=1700000000000,
                destination_category="INTERNAL",
                risk_score=150,  # Invalid: > 100
                action="ALLOW",
            )

    def test_event_id_auto_generated(self):
        evt = SecurityEvent(
            timestamp=1700000000000,
            destination_category="EXTERNAL_AI",
            risk_score=80,
            action="BLOCK",
        )
        assert evt.event_id.startswith("evt_")
        assert len(evt.event_id) > 5

# ──────────────────────────────────────────────────────────────────────
# Fix 5 — API Endpoints
# ──────────────────────────────────────────────────────────────────────

class TestAPIEndpoints:
    def test_health_endpoint(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "operational"
        assert "database" in data
        assert data["identity_layer"] is True

    def test_ingest_event_accepted(self):
        resp = client.post("/events", json={
            "timestamp": 1700000000000,
            "destination_category": "EXTERNAL_AI",
            "detected_tags": ["CREDENTIAL", "AWS_KEY"],
            "risk_score": 97,
            "action": "BLOCK",
            "employee_id": "test.user@company.com",
            "device_id": "TEST-MACHINE-001",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "accepted"
        assert "event_id" in data

    def test_list_events_returns_list(self):
        resp = client.get("/events?limit=5")
        assert resp.status_code == 200
        data = resp.json()
        assert "events" in data
        assert isinstance(data["events"], list)

    def test_risk_summary_has_required_fields(self):
        resp = client.get("/risk/summary")
        assert resp.status_code == 200
        data = resp.json()
        for field in ["total", "allowed", "warned", "blocked", "high_risk", "critical"]:
            assert field in data, f"Missing field: {field}"

    def test_by_employee_endpoint_exists(self):
        resp = client.get("/risk/by-employee")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_webhook_config_get(self):
        resp = client.get("/webhook")
        assert resp.status_code == 200
        data = resp.json()
        assert "configured" in data

    def test_webhook_config_post(self):
        resp = client.post("/webhook", json={"url": "https://hooks.slack.com/test/abc123"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "configured"
