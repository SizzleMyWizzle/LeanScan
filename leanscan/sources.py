from __future__ import annotations

import json
import re
from typing import Callable

from colorama import Fore

from .config import ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY
from .utils import fetch_and_process, is_hash


def check_virustotal(indicator: str, debug: bool = False) -> bool:
    """Query VirusTotal for an indicator."""
    if not VIRUSTOTAL_API_KEY:
        return False

    if is_hash(indicator):
        url = f"https://www.virustotal.com/api/v3/files/{indicator}"
    else:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    def parse(resp):
        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return stats.get("malicious", 0) > 1

    return fetch_and_process(url, parse, headers=headers, sleep=10, debug=debug)


def check_abuseipdb(indicator: str, debug: bool = False) -> bool:
    """Query AbuseIPDB for an IP."""
    if not ABUSEIPDB_API_KEY:
        return False

    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": indicator, "maxAgeInDays": 90}

    def parse(resp):
        data = resp.json()
        return data.get("data", {}).get("abuseConfidenceScore", 0) > 0

    return fetch_and_process("https://api.abuseipdb.com/api/v2/check", parse, headers=headers, params=params, debug=debug)


def check_otx(indicator: str, debug: bool = False) -> bool:
    """Query OTX for indicator."""
    if is_hash(indicator):
        url = f"https://otx.alienvault.com/api/v1/indicator/file/{indicator}/general"
        threshold = 2
    else:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general"
        threshold = 0

    def parse(resp):
        data = resp.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        return pulse_count > threshold

    return fetch_and_process(url, parse, sleep=5, debug=debug)


def check_spur_us(indicator: str, debug: bool = False) -> bool:
    """Query spur.us for TOR proxy detection."""
    url = f"https://spur.us/context/{indicator}"

    def parse(resp):
        return "TOR_PROXY" in resp.text

    return fetch_and_process(url, parse, sleep=15, debug=debug)


def check_easydmarc(indicator: str, debug: bool = False) -> bool:
    """Query EasyDMARC for indicator."""
    url = f"https://easydmarc.com/tools/ip-domain-reputation-check?term={indicator}"

    def parse(resp):
        return "eas-tag--standard eas-tag--red" in resp.text

    return fetch_and_process(url, parse, debug=debug)


def check_scamalytics(indicator: str, debug: bool = False) -> bool:
    """Query Scamalytics for indicator."""
    url = f"https://scamalytics.com/ip/{indicator}"
    headers = {"User-Agent": "Mozilla/5.0"}

    def parse(resp):
        match = re.search(r'"score":"(\d+)"', resp.text)
        return bool(match and int(match.group(1)) >= 20)

    return fetch_and_process(url, parse, headers=headers, debug=debug)


def check_shadowserver(indicator: str, debug: bool = False) -> bool:
    """Query Shadowserver for file hash."""
    url = f"https://api.shadowserver.org/malware/info?sample={indicator}"

    def parse(resp):
        return "malicious" in resp.text.lower()

    return fetch_and_process(url, parse, debug=debug)


def check_criminalip(indicator: str, debug: bool = False) -> bool:
    """Query CriminalIP for indicator."""
    url = f"https://www.criminalip.io/asset/report/{indicator}"
    headers = {"User-Agent": "Mozilla/5.0"}

    def parse(resp):
        return "IP Scoring: Inbound critical" in resp.text

    return fetch_and_process(url, parse, headers=headers, debug=debug)


ALL_SOURCES: dict[str, Callable[[str, bool], bool]] = {
    "abuseipdb": check_abuseipdb,
    "virustotal": check_virustotal,
    "otx": check_otx,
    "spur.us": check_spur_us,
    "easydmarc": check_easydmarc,
    "scamalytics": check_scamalytics,
    "shadowserver": check_shadowserver,
    "criminalip": check_criminalip,
}
