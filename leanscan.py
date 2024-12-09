import sys
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
    epilog="Example: python3 bad-ip-checker.py ips.txt -s virustotal abuseipdb -o csv txt --debug"
)
parser.add_argument("file", help="File containing IP addresses to check.")
parser.add_argument("--debug", action="store_true", help="Enable debug output.")
parser.add_argument("-s", "--source", nargs='+', choices=["abuseipdb", "virustotal", "otx", "spur.us"], help="Specify one or more sources to query.")
parser.add_argument("-o", "--output", nargs='+', choices=["csv", "txt"], help="Specify one or more output formats: csv, txt.")
args = parser.parse_args()

# API keys (replace these with actual keys)
VIRUSTOTAL_API_KEY = "XXXX"
ABUSEIPDB_API_KEY = "XXXX"

# Check that the API Keys are present. If not, warn user.
def validate_and_warn_api_keys(debug=False):
    missing_keys = []
    if VIRUSTOTAL_API_KEY == "XXXX":
        missing_keys.append("VirusTotal")
    if ABUSEIPDB_API_KEY == "XXXX":
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
    if "abuseipdb" in args.source and ABUSEIPDB_API_KEY == "XXXX":
        print(Fore.RED + "Error: AbuseIPDB source selected but API key is not configured.")
        sys.exit(1)
    if "virustotal" in args.source and VIRUSTOTAL_API_KEY == "XXXX":
        print(Fore.RED + "Error: VirusTotal source selected but API key is not configured.")
        sys.exit(1)


validate_and_warn_api_keys(args.debug)


if args.source:
    validate_selected_sources(args.debug)

# Input file containing IP addresses
IP_FILE = args.file
DEBUG = args.debug
SELECTED_SOURCES = args.source
OUTPUT_FORMATS = args.output if args.output else []

# Validate the input file
try:
    with open(IP_FILE, 'r') as file:
        ip_addresses = [line.strip() for line in file if line.strip()]
except FileNotFoundError:
    print(f"Error: File '{IP_FILE}' not found.")
    sys.exit(1)

TOTAL_IPS = len(ip_addresses)

# Validate the format of the input file
def validate_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)

        # Skip private-use IPs 
        if ip_obj.is_private:
            if DEBUG:
                print(f"Skipping private-use IP: {ip}")
            return False

        # Skip special-use IPs 
        special_use_networks = [
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
        ]
        if any(ip_obj in net for net in special_use_networks):
            if DEBUG:
                print(f"Skipping special-use IP: {ip}")
            return False

        # Skip certain IPv6 addresses (e.g., multicast, reserved)
        if ip_obj.version == 6 and (ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified):
            if DEBUG:
                print(f"Skipping internal IPv6 address: {ip}")
            return False

        return True
    except ValueError:
        if DEBUG:
            print(f"Invalid IP address: {ip}")
        return False

# Build result dictionary for output report
def build_result(ip, source, report_links):
    normalized_source = source.replace(".", "_")
    return {
        "ip": ip,
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
def check_virustotal(ip):
    if VIRUSTOTAL_API_KEY == "XXXX":
        return False

    if DEBUG:
        print(f"Trying VirusTotal for {ip}...", end=" ")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = request_with_retries(url, headers=headers, timeout=10)

    if response and response.status_code == 200:
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        if stats.get("malicious", 0) > 0:
            if DEBUG:
                print(Fore.GREEN + "success!")
            return True
    if DEBUG:
        print(Fore.RED + "failure")
    return False

# Check IP reputation using AbuseIPDB
def check_abuseipdb(ip):
    if ABUSEIPDB_API_KEY == "XXXX":
        return False

    if DEBUG:
        print(f"Trying AbuseIPDB for {ip}...", end=" ")
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    response = request_with_retries(url, headers=headers, params=params, timeout=10)

    if response and response.status_code == 200:
        data = response.json()
        if data.get("data", {}).get("abuseConfidenceScore", 0) > 0:
            if DEBUG:
                print(Fore.GREEN + "success!")
            return True
    if DEBUG:
        print(Fore.RED + "failure")
    return False

# Check IP reputation using OTX (AlienVault)
def check_otx(ip):
    if DEBUG:
        print(f"Trying OTX for {ip}...", end=" ")
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    time.sleep(2) if SELECTED_SOURCES == ["otx"] else None
    response = request_with_retries(url, timeout=10)

    if response and response.status_code == 200:
        data = response.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        if pulse_count > 0:
            if DEBUG:
                print(Fore.GREEN + "success!")
            return True
    if DEBUG:
        print(Fore.RED + "failure")
    return False

# Check IP reputation using Spur.us
def check_spur_us(ip):
    if DEBUG:
        print(f"Trying Spur.us for {ip}...", end=" ")
    url = f"https://spur.us/context/{ip}"
    time.sleep(2) if SELECTED_SOURCES == ["spur.us"] else None
    response = request_with_retries(url, timeout=10)

    if response and response.status_code == 200:
        if "TOR_PROXY" in response.text:
            if DEBUG:
                print(Fore.GREEN + "success!")
            return True
    if DEBUG:
        print(Fore.RED + "failure")
    return False

# Mapping sources to their respective functions
all_sources = {
    "abuseipdb": check_abuseipdb,
    "virustotal": check_virustotal,
    "otx": check_otx,
    "spur.us": check_spur_us
}

# Determine the sources to use
sources = [all_sources[source] for source in SELECTED_SOURCES] if SELECTED_SOURCES else [check_abuseipdb, check_virustotal, check_otx, check_spur_us]

# Main processing loop
source_index = 0
results = []
last_update_time = time.time()
start_time = time.time()

progress_bar = None
if not DEBUG:
    progress_bar = tqdm(total=TOTAL_IPS, desc="Processing IPs", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} | {postfix}")

for ip in ip_addresses:
    if not validate_ip(ip):
        if progress_bar:
            progress_bar.update(1)
        continue

    malicious_sources = []
    report_links = {
        "abuseipdb": f"https://www.abuseipdb.com/check/{ip}",
        "virustotal": f"https://www.virustotal.com/gui/ip-address/{ip}",
        "otx": f"https://otx.alienvault.com/indicator/ip/{ip}",
        "spur_us": f"https://spur.us/context/{ip}"
    }

    for _ in range(len(sources)):
        # Select the current source based on the rotation
        source = sources[source_index]
        source_index = (source_index + 1) % len(sources)

        # Check the IP using the selected source
        if source(ip):
            malicious_sources.append(source.__name__.replace("check_", "").capitalize())
            results.append(build_result(ip, source.__name__.replace("check_", "").lower(), report_links))
            break

    # If no results were found and debug mode is enabled, print a message
    if not malicious_sources and DEBUG:
        print(Fore.YELLOW + f"No results found for {ip}. Skipping...")

    # Update progress bar
    if progress_bar:
        progress_bar.update(1)

    current_time = time.time()
    elapsed_time = current_time - start_time
    processed = progress_bar.n if progress_bar else len(results)
    if processed > 0:
        estimated_total_time = (elapsed_time / processed) * TOTAL_IPS
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
        fieldnames = ["IP Address", "Sources", "Link"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for result in results:
            writer.writerow({"IP Address": result["ip"], "Sources": result["sources"], "Link": result["link"]})
    print(f"Results saved to {csv_file}")

if "txt" in OUTPUT_FORMATS:
    txt_file = "results.txt"
    with open(txt_file, "w") as txtfile:
        txtfile.write(f"{'IP Address':<20} | {'Sources':<30} | Link\n")
        txtfile.write("-" * 80 + "\n")
        for result in results:
            txtfile.write(f"{result['ip']:<20} | {result['sources']:<30} | {result['link']}\n")
            txtfile.write("-" * 80 + "\n")
    print(f"Results saved to {txt_file}")

# Print the results to the console if no specific output formats are requested
if not OUTPUT_FORMATS:
    print("\nResults:\n")
    print(f"{'IP Address':<20} | {'Sources':<30} | Link")
    print("-" * 80)
    for result in results:
        print(f"{result['ip']:<20} | {result['sources']:<30} | {result['link']}")
        print("-" * 80)
