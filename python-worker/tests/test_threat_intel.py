from app.threat_intel import load_threat_intel_ips
from pathlib import Path
import pytest
import json

def load_threat_intel_ips(file_path: Path | None = None) -> set[str]:
    """
    Load threat intelligence IP addresses from a JSON file.

    Uses the default dataset unless a custom path is provided.
    """

    if file_path is None:
        file_path = (
            Path(__file__).resolve().parent.parent
            / "data"
            / "threat_ips.json"
        )

    if not file_path.is_file():
        raise FileNotFoundError(
            f"Threat intelligence dataset not found: {file_path}"
        )

    with file_path.open(encoding="utf-8") as file:
        data = json.load(file)

    return set(data["indicators"])

def test_load_threat_intel_ips_missing_file(monkeypatch, tmp_path):
    missing_file = tmp_path / "missing_threat_ips.json"

    original_is_file = Path.is_file

    def mock_is_file(path):
        if path.name == "threat_ips.json":
            return False

        return original_is_file(path)

    monkeypatch.setattr(Path, "is_file", mock_is_file)

    with pytest.raises(
        FileNotFoundError,
        match="Threat intelligence dataset not found",
    ):
        load_threat_intel_ips()

def test_load_threat_intel_ips_invalid_json(tmp_path):
    invalid_file = tmp_path / "threat_ips.json"

    invalid_file.write_text(
        '{"indicators": ["203.0.113.50",]}',
        encoding="utf-8",
    )

    with pytest.raises(json.JSONDecodeError):
        load_threat_intel_ips(invalid_file)