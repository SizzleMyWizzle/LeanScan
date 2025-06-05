from __future__ import annotations

import ipaddress
import re
import requests
import time
from typing import Callable, Optional
from colorama import Fore

from .config import RESERVED_NETWORKS


def is_hash(value: str) -> bool:
    """Return True if the provided value looks like a hash string."""
    return bool(re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value))


def validate_input(value: str, debug: bool = False) -> bool:
    """Validate an IP address or hash ensuring it is public."""
    if is_hash(value):
        return True
    try:
        ip_obj = ipaddress.ip_address(value)
        if ip_obj.is_private or any(ip_obj in net for net in RESERVED_NETWORKS):
            if debug:
                print(f"Skipping non-public or special-use IP: {value}")
            return False
        if ip_obj.version == 6 and (ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified):
            if debug:
                print(f"Skipping special IPv6 address: {value}")
            return False
        return True
    except ValueError:
        if debug:
            print(f"Invalid IP or hash: {value}")
        return False


def build_result(value: str, source: str, report_links: dict[str, str]) -> dict[str, str]:
    """Create a result dictionary for output."""
    normalized_source = source.replace(".", "_")
    type_label = "Hash" if is_hash(value) else "IP"
    return {
        "type": type_label,
        "value": value,
        "sources": source,
        "link": report_links.get(normalized_source, "Unknown source"),
    }


def request_with_retries(
    url: str,
    headers: Optional[dict[str, str]] = None,
    params: Optional[dict[str, str]] = None,
    timeout: int = 10,
    max_retries: int = 3,
    debug: bool = False,
) -> Optional[requests.Response]:
    """Issue a GET request retrying on timeout."""
    retries = 0
    while retries < max_retries:
        try:
            response = requests.get(url, headers=headers, params=params, timeout=timeout)
            if response.status_code == 429:
                if debug:
                    print(Fore.RED + "failure: Rate Limit Exceeded.")
                return None
            return response
        except requests.exceptions.ReadTimeout:
            retries += 1
            if debug:
                print(Fore.YELLOW + f"Timeout while querying {url}. Retrying {retries}/{max_retries}...")
        except requests.exceptions.RequestException as e:
            if debug:
                print(Fore.RED + f"Request failed: {e}")
            return None
    if debug:
        print(Fore.RED + "Retry limit exceeded. Skipping...")
    return None


def fetch_and_process(
    url: str,
    parse_fn: Callable[[requests.Response], bool],
    headers: Optional[dict[str, str]] = None,
    params: Optional[dict[str, str]] = None,
    sleep: int = 0,
    debug: bool = False,
) -> bool:
    """Helper to fetch a URL and process the response."""
    if sleep:
        time.sleep(sleep)
    response = request_with_retries(url, headers=headers, params=params, timeout=10, debug=debug)
    if not response:
        if debug:
            print(Fore.RED + "API Request Failed (No Response)")
        return False
    if response.status_code != 200:
        if debug:
            print(Fore.RED + f"API Failed ({response.status_code})")
        return False
    try:
        return parse_fn(response)
    except Exception as e:
        if debug:
            print(Fore.RED + f"Parsing error: {e}")
        return False
