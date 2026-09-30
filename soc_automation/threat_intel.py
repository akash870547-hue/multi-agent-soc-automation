import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .models import SecurityEvent

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH = re.compile(r"\b[a-fA-F0-9]{64}\b")


def extract_iocs(event: SecurityEvent) -> dict[str, list[str]]:
    text = event.message
    ips = set(IPV4.findall(text))
    hashes = set(HASH.findall(text))
    if event.source_ip:
        ips.add(event.source_ip)
    if event.destination_ip:
        ips.add(event.destination_ip)
    return {"ipv4": sorted(ips), "sha256": sorted(hashes)}


def map_attack_technique(event: SecurityEvent) -> dict:
    message = event.message.lower()
    mappings = [
        ("sql injection", "T1190", "Exploit Public-Facing Application"),
        ("failed login", "T1110", "Brute Force"),
        ("ransomware", "T1486", "Data Encrypted for Impact"),
        ("malware", "T1204", "User Execution"),
    ]
    for indicator, technique_id, technique_name in mappings:
        if indicator in message:
            return {"technique_id": technique_id, "technique_name": technique_name}
    return {"technique_id": None, "technique_name": None}


def lookup_virustotal(indicator: str, timeout: float = 5.0) -> dict:
    """Optional VirusTotal enrichment. Returns unavailable when no API key is configured."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"provider": "virustotal", "status": "not_configured", "indicator": indicator}

    url = "https://www.virustotal.com/api/v3/search?query=" + indicator
    request = Request(url, headers={"x-apikey": api_key, "Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return {"provider": "virustotal", "status": "ok", "indicator": indicator, "data": payload.get("data", [])[:5]}
    except HTTPError as exc:
        return {"provider": "virustotal", "status": "error", "indicator": indicator, "detail": f"HTTP {exc.code}"}
    except (URLError, TimeoutError, ValueError) as exc:
        return {"provider": "virustotal", "status": "error", "indicator": indicator, "detail": str(exc)}


def enrich_indicator(indicator: str) -> dict:
    return lookup_virustotal(indicator)


def enrich_event(event: SecurityEvent) -> dict:
    iocs = extract_iocs(event)
    results = []
    for indicator in iocs["ipv4"] + iocs["sha256"]:
        results.append(enrich_indicator(indicator))
    return {"iocs": iocs, "lookups": results}
