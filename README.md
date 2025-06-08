# LeanScan

```
   __                 ____            
  / /  ___ ___ ____  / __/______ ____ 
 / /__/ -_) _ `/ _ \_\ \/ __/ _ `/ _ \
/____/\__/\_,_/_//_/___/\__/\_,_/_//_/
```

**LeanScan** is an IP reputation checker written in Python designed specifically to leverage free lookups and APIs to conduct a base-level reputation check. This tool is designed to provide a quick insight to assist security teams in determining if an IP address has been reported to one of the Intelligence sources and needs to be examined closer. If you're looking for a no-frills solution to quickly assess potential threats, LeanScan has you covered.

---

## But what does it do?
LeanScan takes a list of IP addresses from a .txt file and uses that information to query multiple free reputation sources to determine if any of those IPs are potentially associated with malicious activity, abuse, or other threats. It is designed to maximize the information you're able to gather with your free APIs by using a round-robin approach. LeanScan provides concise insights that are especially useful for small-to-medium-scale investigations or basic threat intelligence workflows. It works without paid subscriptions, making it an accessible option for budget-conscious users.

---

## Features
- Supports multiple reputation sources: **AbuseIPDB**, **VirusTotal**, **OTX (AlienVault)**, **EasyDMARC**, **Scamalytics**, **Shadowserver**, **CriminalIP**, and **Spur.us**.
- Customizable output formats: CSV and TXT.
- Debug mode for detailed logging.
- Lightweight design.

---

## Requirements
- Python 3.7 or newer
- API keys for AbuseIPDB and VirusTotal provided via environment variables (not required but strongly recommended.)
  - [AbuseIPDB](https://www.abuseipdb.com/)
  - [VirusTotal](https://www.virustotal.com/)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/SizzleMyWizzle/leanscan.git
   cd leanscan
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set your API keys as environment variables:
   ```bash
   export VIRUSTOTAL_API_KEY=<your_key>
   export ABUSEIPDB_API_KEY=<your_key>
   ```

---

## Usage
```bash
python3 leanscan.py <file> [-s SOURCES] [-o OUTPUT_FORMATS] [--debug]
```

### Parameters
- `<file>`: File containing a list of IP addresses or hashes to check.
- `-s, --source`: Specify one or more sources to query (e.g., `virustotal abuseipdb`).
- `-o, --output`: Specify output formats (`csv`, `txt` or both).
- `--debug`: Enable debug mode for detailed logs.

### Examples
1. Check IPs with all sources and output as CSV and TXT:
   ```bash
   python3 leanscan.py ips.txt -o csv txt
   ```

2. Use specific sources only (e.g., VirusTotal and OTX) in debug mode:
   ```bash
   python3 leanscan.py ips.txt -s virustotal otx --debug
   ```

3. Run in debug mode for troubleshooting:
   ```bash
   python3 leanscan.py ips.txt --debug
   ```

_Note: If `-o` is not specified, the results will be written to the terminal and not outputted to a file. It is strongly recommended to output to a file with larger datasets. Currently, debug output cannot be written out to a file and will be displayed to the terminal. Input file must contain valid external IP addresses, one per line._

---

## Output
- **CSV**: Results are saved to `results.csv`.
- **TXT**: Results are saved to `results.txt`.
- **Terminal**: If no output format is specified, results are printed to the terminal.

---

## Limitations
- Free API limits will apply.
- Highly recommended to use API keys for AbuseIPDB and VirusTotal, both of which can be obtained by simply creating an account.
- Designed for small-to-medium batch processing. Larger datasets will likely introduce server-side rate limiting. Leanscan has been tuned to mitigate this as much as possible. 


---

## License
This project is licensed under the [MIT License](LICENSE).

---

## Disclaimer
LeanScan relies on free resources and is intended for informational purposes only. Use responsibly and ensure compliance with the terms of service of each queried source.
