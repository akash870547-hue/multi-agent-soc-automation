import re

from .models import SecurityEvent


IPV4 = re.compile(r"\b(?:\d{1,3}\\.){3}\d{1,3}\\b")
HASH = re.compile(r"\b[a-fA-F0-9]{64}\\b")


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
