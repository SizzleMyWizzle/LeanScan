import sys
import re
import requests
import time
import json
import ipaddress
import argparse
import csv
from tqdm import tqdm
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Argument parsing
parser = argparse.ArgumentParser(
    description="Check IP reputation using various sources.",
    epilog="Example: python3 leanscan.py ips.txt -s virustotal abuseipdb -o csv txt --debug"
)
parser.add_argument("file", help="File containing IP addresses / hashes to check.")
parser.add_argument("--debug", action="store_true", help="Enable debug output.")
parser.add_argument("-s", "--source", nargs='+', choices=["abuseipdb", "virustotal", "otx", "spur.us", "easydmarc", "scamalytics", "shadowserver", "criminalip"], help="Specify one or more sources to query.")
parser.add_argument("-o", "--output", nargs='+', choices=["csv", "txt"], help="Specify one or more output formats: csv, txt.")
args = parser.parse_args()

# API keys (replace these with actual keys)
VIRUSTOTAL_API_KEY = "XXXXX"
ABUSEIPDB_API_KEY = "XXXXX"

# Check that the API Keys are present. If not, warn user.
def validate_and_warn_api_keys(debug=False):
    missing_keys = []
    if VIRUSTOTAL_API_KEY == "XXXXX":
        missing_keys.append("VirusTotal")
    if ABUSEIPDB_API_KEY == "XXXXX":
        missing_keys.append("AbuseIPDB")

    if missing_keys:
        proceed = input(f" WARNING!: API Keys not detected for {', '.join(missing_keys)}. Proceed using remaining sources? Please note results may be slower to mitigate server-side rate limiting. (y/n): ").strip().lower()
        if proceed != 'y':
            print("Exiting due to missing API keys.")
            sys.exit(1)

        if debug:
            for key in missing_keys:
                print(Fore.YELLOW + f"No API key for {key}. Skipping...")
            if len(missing_keys) == 2:
                print(Fore.YELLOW + "Global rate limiting enforced (2 seconds per query).")
                time.sleep(2)
# Throw error is source requested as no API Key
def validate_selected_sources(debug=False):
    if "abuseipdb" in args.source and ABUSEIPDB_API_KEY == "XXXXX":
        print(Fore.RED + "Error: AbuseIPDB source selected but API key is not configured.")
        sys.exit(1)
    if "virustotal" in args.source and VIRUSTOTAL_API_KEY == "XXXXX":
        print(Fore.RED + "Error: VirusTotal source selected but API key is not configured.")
        sys.exit(1)


validate_and_warn_api_keys(args.debug)


if args.source:
    validate_selected_sources(args.debug)

# Input file containing indicators
INPUT_FILE = args.file
DEBUG = args.debug
SELECTED_SOURCES = args.source
OUTPUT_FORMATS = args.output if args.output else []

# Validate the input file
try:
    with open(INPUT_FILE, 'r') as file:
        indicators = [line.strip() for line in file if line.strip()]
except FileNotFoundError:
    print(f"Error: File '{INPUT_FILE}' not found.")
    sys.exit(1)

TOTAL_INDICATORS = len(indicators)

# Universal validator for IPs and Hashes
def validate_input(value):
    # Check if it's a hash first
    if is_hash(value):
        return True

    # ignore reserved or internal IPs
    try:
        ip_obj = ipaddress.ip_address(value)

        if ip_obj.is_private or any(ip_obj in net for net in [
            ipaddress.ip_network("0.0.0.0/8"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
            ipaddress.ip_network("192.0.0.0/24"),
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("192.88.99.0/24"),
            ipaddress.ip_network("198.18.0.0/15"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
            ipaddress.ip_network("224.0.0.0/4"),
            ipaddress.ip_network("240.0.0.0/4"),
            ipaddress.ip_network("100.64.0.0/10"),
            ipaddress.ip_network("255.255.255.255/32"),
        ]):
            if DEBUG:
                print(f"Skipping non-public or special-use IP: {value}")
            return False

        if ip_obj.version == 6 and (ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified):
            if DEBUG:
                print(f"Skipping special IPv6 address: {value}")
            return False

        return True
    except ValueError:
        if DEBUG:
            print(f"Invalid IP or hash: {value}")
        return False

def is_hash(value):
    return bool(re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value))

# Build result dictionary for output report
def build_result(value, source, report_links):
    normalized_source = source.replace(".", "_")
    type_label = "Hash" if is_hash(value) else "IP"
    return {
        "type": type_label,
        "value": value,
        "sources": source,
        "link": report_links.get(normalized_source, "Unknown source")
    }

# Retry wrapper for network requests
def request_with_retries(url, headers=None, params=None, timeout=10, max_retries=3):
    retries = 0
    while retries < max_retries:
        try:
            response = requests.get(url, headers=headers, params=params, timeout=timeout)
            if response.status_code == 429:  # Rate Limit Exceeded
                if DEBUG:
                    print(Fore.RED + "failure: Rate Limit Exceeded.")
                return None
            return response
        except requests.exceptions.ReadTimeout:
            retries += 1
            if DEBUG:
                print(Fore.YELLOW + f"Timeout while querying {url}. Retrying {retries}/{max_retries}...")
        except requests.exceptions.RequestException as e:
            if DEBUG:
                print(Fore.RED + f"Request failed: {e}")
            return None
    if DEBUG:
        print(Fore.RED + "Retry limit exceeded. Skipping...")
    return None

# Check IP reputation using VirusTotal
def check_virustotal(value):
    if VIRUSTOTAL_API_KEY == "XXXXX":
        return False

    if is_hash(value):
        if DEBUG:
            print(f"Trying VirusTotal for hash {value}...", end=" ")
        url = f"https://www.virustotal.com/api/v3/files/{value}"
        time.sleep(10)
    else:
        if DEBUG:
            print(f"Trying VirusTotal for IP {value}...", end=" ")
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
        time.sleep(10)

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = request_with_retries(url, headers=headers, timeout=10)

    if response:
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if stats.get("malicious", 0) > 1:
                if DEBUG:
                    print(Fore.GREEN + "API Success (200) - Results Found!")
                return True
            else:
                if DEBUG:
                    print(Fore.GREEN + "API Success (200) - No results found")
                return False
        else:
            if DEBUG:
                print(Fore.RED + f"API Failed ({response.status_code})")
            return False
    else:
        if DEBUG:
            print(Fore.RED + "API Request Failed (No Response)")
        return False


# Check IP reputation using AbuseIPDB
def check_abuseipdb(indicator):
    if ABUSEIPDB_API_KEY == "XXXXX":
        return False

    if DEBUG:
        print(f"Trying AbuseIPDB for {indicator}...", end=" ")
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": indicator,
        "maxAgeInDays": 90
    }
    response = request_with_retries(url, headers=headers, params=params, timeout=10)

    if response:
        if response.status_code == 200:
            data = response.json()
            if data.get("data", {}).get("abuseConfidenceScore", 0) > 0:
                if DEBUG:
                    print(Fore.GREEN + "API Success (200) - Results Found!")
                return True
            else:
                if DEBUG:
                    print(Fore.GREEN + "API Success (200) - No results found")
                return False
        else:
            if DEBUG:
                print(Fore.RED + f"API Failed ({response.status_code})")
            return False
    else:
        if DEBUG:
            print(Fore.RED + "API Request Failed (No Response)")
        return False


# Check IP reputation using OTX
def check_otx(value):
    if is_hash(value):
        if DEBUG:
            print(f"Trying OTX for hash {value}...", end=" ")
        url = f"https://otx.alienvault.com/api/v1/indicator/file/{value}/general"
        threshold = 2 # Accept only if 2 or more pulses for a hash
    else:
        if DEBUG:
            print(f"Trying OTX for IP {value}...", end=" ")
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{value}/general"
        threshold = 0  # Accept any pulse count for IPs

    time.sleep(5)
    response = request_with_retries(url, timeout=10)

    if response:
        if response.status_code == 200:
            try:
                data = response.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                if pulse_count > threshold:
                    if DEBUG:
                        print(Fore.GREEN + "API Success (200) - Results Found!")
                    return True
                else:
                    if DEBUG:
                        print(Fore.GREEN + "API Success (200) - No results found")
                    return False
            except Exception as e:
                if DEBUG:
                    print(Fore.RED + f"JSON Parsing Failed: {e}")
                return False
        else:
            if DEBUG:
                print(Fore.RED + f"API Failed ({response.status_code})")
            return False
    else:
        if DEBUG:
            print(Fore.RED + "API Request Failed (No Response)")
        return False


# Check IP reputation using Spur.us
def check_spur_us(indicator):
    if DEBUG:
        print(f"Trying Spur.us for {indicator}...", end=" ")
    url = f"https://spur.us/context/{indicator}"
    time.sleep(15)
    response = request_with_retries(url, timeout=10)

    if response:
        if response.status_code == 200:
            if "TOR_PROXY" in response.text:
                if DEBUG:
                    print(Fore.GREEN + "API Success (200) - Results Found!")
                return True
            else:
                if DEBUG:
                    print(Fore.GREEN + "API Success (200) - No results found")
                return False
        else:
            if DEBUG:
                print(Fore.RED + f"API Failed ({response.status_code})")
            return False
    else:
        if DEBUG:
            print(Fore.RED + "API Request Failed (No Response)")
        return False

# Check IP reputation using EasyDMARC
def check_easydmarc(indicator):
    if DEBUG:
        print(f"Trying EasyDMARC for {indicator}...", end=" ")
    url = f"https://easydmarc.com/tools/ip-domain-reputation-check?term={indicator}"
    response = request_with_retries(url, timeout=10)

    if response:
        if response.status_code == 200:
            if "eas-tag--standard eas-tag--red" in response.text:
                if DEBUG:
                    print(Fore.GREEN + "API Success (200) - Results Found!")
                return True
            else:
                if DEBUG:
                    print(Fore.GREEN + "API Success (200) - No results found")
                return False
        else:
            if DEBUG:
                print(Fore.RED + f"API Failed ({response.status_code})")
            return False
    else:
        if DEBUG:
            print(Fore.RED + "API Request Failed (No Response)")
        return False

# Check IP reputation using Scamalytics
def check_scamalytics(indicator):
    if DEBUG:
        print(f"Trying Scamalytics for {indicator}...", end=" ")
    url = f"https://scamalytics.com/ip/{indicator}"
    headers = {
        "User-Agent": "Mozilla/5.0"
    }
    response = request_with_retries(url, headers=headers, timeout=10)
    if response:
        if response.status_code == 200:
            try:
                data = response.text
                match = re.search(r'"score":"(\d+)"', data)
                if match and int(match.group(1)) >= 20:
                    if DEBUG:
                        print(Fore.GREEN + "API Success (200) - Results Found!")
                    return True
                else:
                    if DEBUG:
                        print(Fore.GREEN + "API Success (200) - No results found")
                    return False
            except Exception as e:
                if DEBUG:
                    print(Fore.RED + f"Parsing error: {e}")
                return False
        else:
            if DEBUG:
                print(Fore.RED + f"API Failed ({response.status_code})")
            return False
    else:
        if DEBUG:
            print(Fore.RED + "API Request Failed (No Response)")
        return False

# Check hash reputation using Shadowserver
def check_shadowserver(hash_value):
    if DEBUG:
        print(f"Trying Shadowserver for hash {hash_value}...", end=" ")
    url = f"https://api.shadowserver.org/malware/info?sample={hash_value}"
    response = request_with_retries(url, timeout=10)

    if response:
        if response.status_code == 200:
            if "malicious" in response.text.lower():
                if DEBUG:
                    print(Fore.GREEN + "API Success (200) - Results Found!")
                return True
            else:
                if DEBUG:
                    print(Fore.GREEN + "API Success (200) - No results found")
                return False
        else:
            if DEBUG:
                print(Fore.RED + f"API Failed ({response.status_code})")
            return False
    else:
        if DEBUG:
            print(Fore.RED + "API Request Failed (No Response)")
        return False

def check_criminalip(indicator):
    if DEBUG:
        print(f"Trying CriminalIP for {indicator}...", end=" ")
    url = f"https://www.criminalip.io/asset/report/{indicator}"
    headers = {
        "User-Agent": "Mozilla/5.0"
    }
    response = request_with_retries(url, headers=headers, timeout=10)

    if response:
        if response.status_code == 200:
            if "IP Scoring: Inbound critical" in response.text:
                if DEBUG:
                    print(Fore.GREEN + "API Success (200) - Results Found!")
                return True
            else:
                if DEBUG:
                    print(Fore.GREEN + "API Success (200) - No results found")
                return False
        else:
            if DEBUG:
                print(Fore.RED + f"API Failed ({response.status_code})")
            return False
    else:
        if DEBUG:
            print(Fore.RED + "API Request Failed (No Response)")
        return False


# Mapping sources to their respective functions
all_sources = {
    "abuseipdb": check_abuseipdb,
    "virustotal": check_virustotal,
    "otx": check_otx,
    "spur.us": check_spur_us,
    "easydmarc": check_easydmarc,
    "scamalytics": check_scamalytics,
    "shadowserver": check_shadowserver,
    "criminalip": check_criminalip
}



# Determine the sources to use
default_sources = [
    "abuseipdb",
    "virustotal",
    "otx",
    "easydmarc",
    "scamalytics",
    "criminalip",
]

# Resolve the functions for the user requested or default sources
selected_functions = (
    [all_sources[name] for name in SELECTED_SOURCES]
    if SELECTED_SOURCES
    else [all_sources[name] for name in default_sources]
)


# Main processing loop
source_index = 0
results = []
last_update_time = time.time()
start_time = time.time()

progress_bar = None
if not DEBUG:
    progress_bar = tqdm(
        total=TOTAL_INDICATORS,
        desc="Processing...",
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} | {postfix}",
    )

# Exclude the Spur.us fallback from the primary rotation
unified_pool = [
    func for func in selected_functions if func.__name__ != "check_spur_us"
]
rotation_index = 0

for indicator in indicators:
    if not validate_input(indicator):
        if progress_bar:
            progress_bar.update(1)
        continue

    malicious_sources = []
    if is_hash(indicator):
        report_links = {
            "abuseipdb": "N/A",
            "virustotal": f"https://www.virustotal.com/gui/file/{indicator}",
            "otx": f"https://otx.alienvault.com/indicator/file/{indicator}",
            "spur_us": "N/A",
            "easydmarc": "N/A",
            "scamalytics": "N/A",
            "shadowserver": f"https://api.shadowserver.org/malware/info?sample={indicator}",
            "criminalip": "N/A"
        }
    else:
        report_links = {
            "abuseipdb": f"https://www.abuseipdb.com/check/{indicator}",
            "virustotal": f"https://www.virustotal.com/gui/ip-address/{indicator}",
            "otx": f"https://otx.alienvault.com/indicator/ip/{indicator}",
            "spur_us": f"https://spur.us/context/{indicator}",
            "easydmarc": f"https://easydmarc.com/tools/ip-domain-reputation-check?term={indicator}",
            "scamalytics": f"https://scamalytics.com/ip/{indicator}",
            "shadowserver": f"N/A",
            "criminalip": "https://www.criminalip.io/asset/report/{indicator}"
        }


    malicious_sources = []
    result_found = False

    # Unified rotation with input type filtering
    for _ in range(len(unified_pool)):  # Prevent infinite loop
        selected_source = unified_pool[rotation_index % len(unified_pool)]
        rotation_index += 1

        # Skip invalid sources based on input type
        if is_hash(indicator) and selected_source.__name__ not in ["check_virustotal", "check_shadowserver", "check_otx"]:
            continue
        if not is_hash(indicator) and selected_source.__name__ in ["check_shadowserver"]:
            continue

        # Call the valid source
        if selected_source(indicator):
            malicious_sources.append(selected_source.__name__.replace("check_", "").capitalize())
            results.append(build_result(indicator, selected_source.__name__.replace("check_", "").lower(), report_links))
            result_found = True
            break  


    # Fallback to Spur if no results found and it's an IP
    if not result_found and not is_hash(indicator) and "check_spur_us" in [f.__name__ for f in selected_functions]:
        if check_spur_us(indicator):
            malicious_sources.append("Spur.us")
            results.append(build_result(indicator, "spur_us", report_links))


    # If no results were found and debug mode is enabled, print a message
    if not malicious_sources and DEBUG:
        print(Fore.YELLOW + f"No results found for {indicator} across all selected sources. Skipping...")

    # Update progress bar
    if progress_bar:
        progress_bar.update(1)

    current_time = time.time()
    elapsed_time = current_time - start_time
    processed = progress_bar.n if progress_bar else len(results)
    if processed > 0:
        estimated_total_time = (elapsed_time / processed) * TOTAL_INDICATORS
        remaining_time = int(estimated_total_time - elapsed_time)
    else:
        remaining_time = 0

    if progress_bar and current_time - last_update_time >= 1:  # Update "Estimated Time Remaining" every 1 second
        hours, remainder = divmod(remaining_time, 3600)
        minutes, seconds = divmod(remainder, 60)
        eta_formatted = f"{hours}h {minutes}m {seconds}s" if hours > 0 else f"{minutes}m {seconds}s"
        progress_bar.set_postfix_str(f"Estimated Time Remaining: {eta_formatted}")
        last_update_time = current_time

if progress_bar:
    progress_bar.close()

# Output all results at the end
if "csv" in OUTPUT_FORMATS:
    csv_file = "results.csv"
    with open(csv_file, "w", newline="") as csvfile:
        fieldnames = ["Type", "Value", "Sources", "Link"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for result in results:
            writer.writerow({"Type": result["type"], "Value": result["value"], "Sources": result["sources"], "Link": result["link"]})
    print(f"Results saved to {csv_file}")

if "txt" in OUTPUT_FORMATS:
    txt_file = "results.txt"
    with open(txt_file, "w") as txtfile:
        txtfile.write(f"{'Type':<10} | {'Value':<75} | {'Sources':<30} | Link\n")
        txtfile.write("=" * 130 + "\n\n")
        for result in results:
            txtfile.write(f"{result['type']:<10} | {result['value']:<75} | {result['sources']:<30} | {result['link']}\n")
            txtfile.write("-" * 130 + "\n\n")
    print(f"Results saved to {txt_file}")

# Print the results to the console if no specific output formats are requested
if not OUTPUT_FORMATS:
    print("\nResults:\n")
    print(f"{'Type':<10} | {'Value':<75} | {'Sources':<30} | Link")
    print("-" * 130)
    for result in results:
        print(f"{result['type']:<10} | {result['value']:<75} | {result['sources']:<30} | {result['link']}")
        print("-" * 130)
