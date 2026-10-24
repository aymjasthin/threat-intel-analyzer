import json
from pathlib import Path

"""
Local threat intelligence indicators.

These IP addresses are reserved for documentation
and testing. They are not real threat indicators.
"""

THREAT_INTEL_IPS = {
    "203.0.113.50",
    "198.51.100.25",
}

def load_threat_intel_ips() -> set[str]:
    """
    Load threat intelligence IP addresses from a JSON file.
    """

    file_path = (
        Path(__file__).resolve().parent.parent
        / "data"
        / "threat_ips.json"
    )

    with file_path.open(encoding="utf-8") as file:
        data = json.load(file)

    return set(data["indicators"])