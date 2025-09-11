import io
import pytest
from fastapi.testclient import TestClient
from AI_Threat_Backend.main import app
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from AI_Threat_Backend.main import app

client = TestClient(app)


def test_train_endpoint():
    """Check if training endpoint runs and returns success message."""
    response = client.post("/train")
    assert response.status_code == 200

    data = response.json()
    assert "status" in data
    assert "models_saved_to" in data
    assert data["status"] == "success"


def test_upload_and_predict():
    """Upload a dummy CSV and check prediction results."""
    csv_content = (
        "feature1,feature2\n"
        "1.0,0.5\n"
        "2.0,1.5\n"
    )
    files = {
        "file": ("test.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")
    }

    response = client.post("/upload", files=files)
    assert response.status_code == 200

    data = response.json()
    assert "results" in data
    assert isinstance(data["results"], list)
    assert len(data["results"]) == 2

    row = data["results"][0]
    assert "index" in row
    assert "prediction" in row
    assert "anomaly_score" in row


def test_alerts_endpoint():
    """Check alerts endpoint returns a list."""
    response = client.get("/alerts")
    assert response.status_code == 200

    data = response.json()
    assert isinstance(data, list)

    if data:  # if alerts exist, check structure
        alert = data[0]
        assert "prediction" in alert
        assert "anomaly_score" in alert
