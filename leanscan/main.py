from __future__ import annotations

import argparse
import csv
import sys
import time
from typing import Iterable, List

from colorama import Fore, Style, init
from tqdm import tqdm

from .config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY
from .utils import build_result, is_hash, validate_input
from .sources import ALL_SOURCES

init(autoreset=True)


def _validate_and_warn_api_keys(debug: bool = False) -> None:
    missing_keys = []
    if not VIRUSTOTAL_API_KEY:
        missing_keys.append("VirusTotal")
    if not ABUSEIPDB_API_KEY:
        missing_keys.append("AbuseIPDB")

    if missing_keys:
        proceed = input(
            f" WARNING!: API Keys not detected for {', '.join(missing_keys)}. Proceed using remaining sources? Please note results may be slower to mitigate server-side rate limiting. (y/n): "
        ).strip().lower()
        if proceed != "y":
            print("Exiting due to missing API keys.")
            sys.exit(1)

        if debug:
            for key in missing_keys:
                print(Fore.YELLOW + f"No API key for {key}. Skipping...")
            if len(missing_keys) == 2:
                print(Fore.YELLOW + "Global rate limiting enforced (2 seconds per query).")


def _validate_selected_sources(sources: Iterable[str], debug: bool = False) -> None:
    if "abuseipdb" in sources and not ABUSEIPDB_API_KEY:
        print(Fore.RED + "Error: AbuseIPDB source selected but API key is not configured.")
        sys.exit(1)
    if "virustotal" in sources and not VIRUSTOTAL_API_KEY:
        print(Fore.RED + "Error: VirusTotal source selected but API key is not configured.")
        sys.exit(1)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check IP reputation using various sources.",
        epilog="Example: python3 leanscan.py ips.txt -s virustotal abuseipdb -o csv txt --debug",
    )
    parser.add_argument("file", help="File containing IP addresses / hashes to check.")
    parser.add_argument("--debug", action="store_true", help="Enable debug output.")
    parser.add_argument(
        "-s",
        "--source",
        nargs="+",
        choices=list(ALL_SOURCES.keys()),
        help="Specify one or more sources to query.",
    )
    parser.add_argument(
        "-o",
        "--output",
        nargs="+",
        choices=["csv", "txt"],
        help="Specify one or more output formats: csv, txt.",
    )
    return parser.parse_args()


def run(
    indicators: List[str],
    debug: bool = False,
    selected_sources: Iterable[str] | None = None,
    output_formats: Iterable[str] | None = None,
) -> None:
    total_indicators = len(indicators)
    selected_funcs = (
        [ALL_SOURCES[name] for name in selected_sources]
        if selected_sources
        else [ALL_SOURCES[name] for name in [
            "abuseipdb",
            "virustotal",
            "otx",
            "easydmarc",
            "scamalytics",
            "criminalip",
        ]]
    )

    unified_pool = [func for func in selected_funcs if func.__name__ != "check_spur_us"]
    rotation_index = 0

    progress_bar = None
    if not debug:
        progress_bar = tqdm(
            total=total_indicators,
            desc="Processing...",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} | {postfix}",
        )

    results = []
    last_update_time = 0.0
    start_time = time.time()

    for indicator in indicators:
        if not validate_input(indicator, debug=debug):
            if progress_bar:
                progress_bar.update(1)
            continue

        report_links = {
            "abuseipdb": f"https://www.abuseipdb.com/check/{indicator}" if not is_hash(indicator) else "N/A",
            "virustotal": f"https://www.virustotal.com/gui/{'file' if is_hash(indicator) else 'ip-address'}/{indicator}",
            "otx": f"https://otx.alienvault.com/indicator/{'file' if is_hash(indicator) else 'ip'}/{indicator}",
            "spur_us": f"https://spur.us/context/{indicator}" if not is_hash(indicator) else "N/A",
            "easydmarc": f"https://easydmarc.com/tools/ip-domain-reputation-check?term={indicator}" if not is_hash(indicator) else "N/A",
            "scamalytics": f"https://scamalytics.com/ip/{indicator}" if not is_hash(indicator) else "N/A",
            "shadowserver": f"https://api.shadowserver.org/malware/info?sample={indicator}" if is_hash(indicator) else "N/A",
            "criminalip": f"https://www.criminalip.io/asset/report/{indicator}" if not is_hash(indicator) else "N/A",
        }

        malicious_sources = []
        result_found = False

        for _ in range(len(unified_pool)):
            selected_source = unified_pool[rotation_index % len(unified_pool)]
            rotation_index += 1

            if is_hash(indicator) and selected_source.__name__ not in {
                "check_virustotal",
                "check_shadowserver",
                "check_otx",
            }:
                continue
            if not is_hash(indicator) and selected_source.__name__ in {"check_shadowserver"}:
                continue

            if selected_source(indicator, debug=debug):
                malicious_sources.append(selected_source.__name__.replace("check_", "").capitalize())
                results.append(build_result(indicator, selected_source.__name__.replace("check_", "").lower(), report_links))
                result_found = True
                break

        if (
            not result_found
            and not is_hash(indicator)
            and "check_spur_us" in [f.__name__ for f in selected_funcs]
        ):
            from .sources import check_spur_us

            if check_spur_us(indicator, debug=debug):
                malicious_sources.append("Spur.us")
                results.append(build_result(indicator, "spur_us", report_links))

        if not malicious_sources and debug:
            print(Fore.YELLOW + f"No results found for {indicator} across all selected sources. Skipping...")

        if progress_bar:
            progress_bar.update(1)

        current_time = time.time()
        elapsed_time = current_time - start_time
        processed = progress_bar.n if progress_bar else len(results)
        remaining_time = 0
        if processed > 0:
            estimated_total_time = (elapsed_time / processed) * total_indicators
            remaining_time = int(estimated_total_time - elapsed_time)

        if progress_bar and current_time - last_update_time >= 1:
            hours, remainder = divmod(remaining_time, 3600)
            minutes, seconds = divmod(remainder, 60)
            eta_formatted = f"{hours}h {minutes}m {seconds}s" if hours > 0 else f"{minutes}m {seconds}s"
            progress_bar.set_postfix_str(f"Estimated Time Remaining: {eta_formatted}")
            last_update_time = current_time

    if progress_bar:
        progress_bar.close()

    if output_formats and "csv" in output_formats:
        csv_file = "results.csv"
        with open(csv_file, "w", newline="") as csvfile:
            fieldnames = ["Type", "Value", "Sources", "Link"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for result in results:
                writer.writerow({"Type": result["type"], "Value": result["value"], "Sources": result["sources"], "Link": result["link"]})
        print(f"Results saved to {csv_file}")

    if output_formats and "txt" in output_formats:
        txt_file = "results.txt"
        with open(txt_file, "w") as txtfile:
            txtfile.write(f"{'Type':<10} | {'Value':<75} | {'Sources':<30} | Link\n")
            txtfile.write("=" * 130 + "\n\n")
            for result in results:
                txtfile.write(f"{result['type']:<10} | {result['value']:<75} | {result['sources']:<30} | {result['link']}\n")
                txtfile.write("-" * 130 + "\n\n")
        print(f"Results saved to {txt_file}")

    if not output_formats:
        print("\nResults:\n")
        print(f"{'Type':<10} | {'Value':<75} | {'Sources':<30} | Link")
        print("-" * 130)
        for result in results:
            print(f"{result['type']:<10} | {result['value']:<75} | {result['sources']:<30} | {result['link']}")
            print("-" * 130)


def main() -> None:
    args = parse_arguments()

    _validate_and_warn_api_keys(args.debug)
    if args.source:
        _validate_selected_sources(args.source, args.debug)

    try:
        with open(args.file, "r") as file:
            indicators = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"Error: File '{args.file}' not found.")
        sys.exit(1)

    run(indicators, debug=args.debug, selected_sources=args.source, output_formats=args.output)


if __name__ == "__main__":
    main()
