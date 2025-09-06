# IOC Lookup

Small command line tool that checks IPs, domains, and file hashes against popular threat intel providers and summarizes the results.

## Providers
- VirusTotal (hashes, IPs, domains)
- AbuseIPDB (IPs only)
- AlienVault OTX (hashes, IPs, domains)

Providers are optional. If the API key is not present, that provider is skipped and the tool still runs.

## Setup
1. Create a Python virtualenv (optional) and install requests:
   ```bash
   pip install requests
2. Set API keys as environment variables before running:

```bash
export VT_API_KEY="your_vt_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
export OTX_API_KEY="your_otx_key"
```

Input

A text or CSV file with IOCs separated by newlines, commas, or spaces. Examples:
```bash
8.8.8.8
example.com
44d88612fea8a8f36de82e1278abb02f
d131dd02c5e6eec4693d9a0698aff95c
275a021bbfb6480f2c2cfb45f0e9f9e9b892b4f9f7f0a2b2b176bece1d1a2f3a
```
Usage
# From a file to stdout
python3 ioc_lookup.py --input iocs.txt

# From a file to CSV
python3 ioc_lookup.py --input iocs.txt --out results.csv

# From stdin
cat iocs.txt | python3 ioc_lookup.py

Output

CSV columns:

ioc

type (ip, domain, md5, sha1, sha256)

verdict (malicious, suspicious, clean_or_unknown, unsupported)

vt_link, abuseipdb_link, otx_link

notes (small summary like counts or scores)

Notes

Respect provider rate limits and terms. Set --sleep for a small delay between queries.

Use only on data you are authorized to analyze.

Add more providers later by following the same pattern in the code.

License

MIT


## 3) `iocs.txt` (example input you can include)
```text
8.8.8.8
example.com
44d88612fea8a8f36de82e1278abb02f
