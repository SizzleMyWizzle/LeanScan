# LeanScan

```
   __                 ____            
  / /  ___ ___ ____  / __/______ ____ 
 / /__/ -_) _ `/ _ \_\ \/ __/ _ `/ _ \
/____/\__/\_,_/_//_/___/\__/\_,_/_//_/
```

**LeanScan** is an IP reputation checker witten in Python designed specifically to leverage free lookups and APIs to conduct a base-level reputation check. This tool is designed to provide a quick insight to assist security teams in determining if an IP address has been reported to one of the Intelligence sources and needs to be examined closer. If you're looking for a no-frills solution to quickly assess potential threats, LeanScan has you covered.

---

## But what does it do?
LeanScan takes a list of IP addresses from a .txt file and uses that information to query multiple free reputation sources to determine if any of those IPs are potentially associated with malicious activity, abuse, or other threats. It is designed to maximize the information you're able to gather with your free APIs by using a round-robin approach. LeanScan provides concise,  insights that are especially useful for small-to-medium-scale investigations or basic threat intelligence workflows. It works without paid subscriptions, making it an accessible option for budget-conscious users.

---

## Features
- Supports multiple reputation sources: **AbuseIPDB**, **VirusTotal**, **OTX (AlienVault)**, and **Spur.us**.
- Customizable output formats: CSV and TXT.
- Debug mode for detailed logging.
- Lightweight design with a focus on minimal dependencies.

---

## Requirements
- Python 3.7 or newer
- API keys for AbuseIPDB and VirusTotal
  - [AbuseIPDB](https://www.abuseipdb.com/)
  - [VirusTotal](https://www.virustotal.com/)

### Python Dependencies
Install required libraries using:
```bash
pip install requests tqdm colorama
```

Required libraries include:
- `requests`
- `tqdm`
- `colorama`

---

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/SizzleMyWizzle/leanscan.git
   cd leanscan
   ```
2. Install dependencies:
   ```bash
   pip install requests tqdm colorama
   ```
3. Update API keys in the script:
   Replace `XXXX` in the `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` variables with your actual API keys.

---

## Usage
```bash
python3 leanscan.py <file> [-s SOURCES] [-o OUTPUT_FORMATS] [--debug]
```

### Parameters
- `<file>`: File containing a list of IP addresses to check.
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

_Note: If `-o` is not specified, the results will be written to the terminal and not outputted to a file. It is strongly reccomended to output to a file with larger datasets. Currently, debug output cannot be written out to a file and will be displayed to the terminal. Input file post contain valid external IP addresses, one per line._

---

## Output
- **CSV**: Results are saved to `results.csv`.
- **TXT**: Results are saved to `results.txt`.
- **Console**: If no output format is specified, results are printed to the console.

---

## Limitations
- Free API limits will apply.
- Requires valid API keys for AbuseIPDB and VirusTotal, both of which can be obtained by simply creating an account.
- Designed for small-to-medium batch processing. Large datasets may result in rate limits and API limits.

---

## License
This project is licensed under the [MIT License](LICENSE).

---

## Acknowledgments
- [AbuseIPDB](https://www.abuseipdb.com/)
- [VirusTotal](https://www.virustotal.com/)
- [OTX AlienVault](https://otx.alienvault.com/)
- [Spur.us](https://spur.us/)

---

## Disclaimer
LeanScan relies on free resources and is intended for informational purposes only. Use responsibly and ensure compliance with the terms of service of each queried source.
