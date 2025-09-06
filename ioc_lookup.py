#!/usr/bin/env python3
"""
IOC Lookup Tool
- Input: list of IOCs (IPs, domains, hashes) from a file or stdin
- Providers: VirusTotal, AbuseIPDB, AlienVault OTX (optional if API keys set)
- Output: CSV to stdout or a file

Env vars for API keys:
  VT_API_KEY        = <virustotal api key>         (https://www.virustotal.com/)
  ABUSEIPDB_API_KEY = <abuseipdb api key>         (https://www.abuseipdb.com/)
  OTX_API_KEY       = <alienvault otx api key>    (https://otx.alienvault.com/)

Usage:
  python3 ioc_lookup.py --input iocs.txt --out results.csv
  cat iocs.txt | python3 ioc_lookup.py
"""
import argparse, csv, os, re, sys, time
from typing import Dict, Any, Tuple, Optional
import requests

IP_RE      = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
DOMAIN_RE  = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")
MD5_RE     = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE    = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE  = re.compile(r"^[a-fA-F0-9]{64}$")

def detect_type(ioc: str) -> Optional[str]:
    if IP_RE.match(ioc): return "ip"
    if DOMAIN_RE.match(ioc): return "domain"
    if SHA256_RE.match(ioc): return "sha256"
    if SHA1_RE.match(ioc): return "sha1"
    if MD5_RE.match(ioc): return "md5"
    return None

def vt_lookup(api_key: str, ioc: str, ioc_type: str) -> Dict[str, Any]:
    base = "https://www.virustotal.com/api/v3"
    headers = {"x-apikey": api_key}
    url = None
    if ioc_type == "ip": url = f"{base}/ip_addresses/{ioc}"
    elif ioc_type == "domain": url = f"{base}/domains/{ioc}"
    else: url = f"{base}/files/{ioc}"

    r = requests.get(url, headers=headers, timeout=20)
    if r.status_code == 404:
        return {"provider":"VirusTotal","status":"not_found"}
    r.raise_for_status()
    data = r.json()
    stats = data.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0)) + int(stats.get("undetected", 0))
    link = data.get("data",{}).get("links",{}).get("self") or f"https://www.virustotal.com/gui/search/{ioc}"
    return {
        "provider": "VirusTotal",
        "status": "ok",
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "link": link
    }

def abuseipdb_lookup(api_key: str, ip: str) -> Dict[str, Any]:
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept":"application/json"}
    params = {"ipAddress": ip, "maxAgeInDays":"90"}
    r = requests.get(url, headers=headers, params=params, timeout=20)
    if r.status_code == 404:
        return {"provider":"AbuseIPDB","status":"not_found"}
    r.raise_for_status()
    data = r.json().get("data", {})
    return {
        "provider": "AbuseIPDB",
        "status": "ok",
        "abuseScore": data.get("abuseConfidenceScore"),
        "totalReports": data.get("totalReports"),
        "isWhitelisted": data.get("isWhitelisted"),
        "countryCode": data.get("countryCode"),
        "usageType": data.get("usageType"),
        "link": f"https://www.abuseipdb.com/check/{ip}"
    }

def otx_lookup(api_key: str, ioc: str, ioc_type: str) -> Dict[str, Any]:
    base = "https://otx.alienvault.com/api/v1/indicators"
    headers = {"X-OTX-API-KEY": api_key}
    kind = {"ip":"IPv4","domain":"domain"}.get(ioc_type, "file")
    url = f"{base}/{kind}/{ioc}/general"
    r = requests.get(url, headers=headers, timeout=20)
    if r.status_code == 404:
        return {"provider":"OTX","status":"not_found"}
    r.raise_for_status()
    data = r.json()
    pulse_cnt = len(data.get("pulse_info",{}).get("pulses",[]))
    reput = data.get("reputation")  # may be null
    return {
        "provider":"OTX",
        "status":"ok",
        "pulses": pulse_cnt,
        "reputation": reput,
        "link": f"https://otx.alienvault.com/indicator/{kind}/{ioc}"
    }

def summarize_row(ioc: str, ioc_type: str,
                  vt: Optional[Dict[str,Any]],
                  abuse: Optional[Dict[str,Any]],
                  otx: Optional[Dict[str,Any]]) -> Dict[str, Any]:
    verdict = "unknown"
    notes = []
    vt_mal = vt.get("malicious") if vt else None
    vt_susp = vt.get("suspicious") if vt else None
    if vt and vt.get("status")=="ok":
        if (vt_mal or 0) > 0: verdict = "malicious"
        elif (vt_susp or 0) > 0: verdict = "suspicious"
        else: verdict = "clean_or_unknown"
        notes.append(f"VT m:{vt_mal} s:{vt_susp}")
    if abuse and abuse.get("status")=="ok":
        score = abuse.get("abuseScore")
        if score is not None:
            notes.append(f"AIP score:{score}")
            if (score or 0) >= 50 and verdict != "malicious":
                verdict = "suspicious"
    if otx and otx.get("status")=="ok":
        pulses = otx.get("pulses",0)
        notes.append(f"OTX pulses:{pulses}")

    return {
        "ioc": ioc,
        "type": ioc_type,
        "verdict": verdict,
        "vt_link": vt.get("link") if vt else "",
        "abuseipdb_link": abuse.get("link") if abuse else "",
        "otx_link": otx.get("link") if otx else "",
        "notes": "; ".join(notes)
    }

def read_iocs(path: Optional[str]) -> list:
    lines = []
    if path:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    else:
        lines = sys.stdin.readlines()
    iocs = []
    for ln in lines:
        for part in re.split(r"[,\s]+", ln.strip()):
            if part: iocs.append(part)
    # de-dupe but keep order
    seen = set(); out=[]
    for x in iocs:
        if x not in seen:
            out.append(x); seen.add(x)
    return out

def main():
    ap = argparse.ArgumentParser(description="IOC Lookup Tool")
    ap.add_argument("--input", help="Path to file containing IOCs (txt or csv). If omitted, reads stdin.")
    ap.add_argument("--out", help="Path to write CSV. If omitted, prints CSV to stdout.")
    ap.add_argument("--sleep", type=float, default=1.0, help="Seconds to sleep between IOCs to be polite.")
    args = ap.parse_args()

    vt_key   = os.getenv("VT_API_KEY")
    ab_key   = os.getenv("ABUSEIPDB_API_KEY")
    otx_key  = os.getenv("OTX_API_KEY")

    if not any([vt_key, ab_key, otx_key]):
        print("No API keys found. Set VT_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY environment variables.", file=sys.stderr)

    iocs = read_iocs(args.input)
    rows = []
    for i, ioc in enumerate(iocs, 1):
        t = detect_type(ioc)
        if not t:
            rows.append({"ioc":ioc,"type":"unknown","verdict":"unsupported","vt_link":"","abuseipdb_link":"","otx_link":"","notes":"format not recognized"})
            continue

        vt = abuse = otx = None
        try:
            if vt_key:
                vt = vt_lookup(vt_key, ioc, t)
        except Exception as e:
            vt = {"provider":"VirusTotal","status":"error","error":str(e)}

        try:
            if ab_key and t == "ip":
                abuse = abuseipdb_lookup(ab_key, ioc)
        except Exception as e:
            abuse = {"provider":"AbuseIPDB","status":"error","error":str(e)}

        try:
            if otx_key:
                otx = otx_lookup(otx_key, ioc, t)
        except Exception as e:
            otx = {"provider":"OTX","status":"error","error":str(e)}

        row = summarize_row(ioc, t, vt, abuse, otx)
        rows.append(row)
        time.sleep(args.sleep)

    # write CSV
    headers = ["ioc","type","verdict","vt_link","abuseipdb_link","otx_link","notes"]
    if args.out:
        with open(args.out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=headers)
            w.writeheader(); w.writerows(rows)
        print(f"Wrote {len(rows)} rows to {args.out}")
    else:
        w = csv.DictWriter(sys.stdout, fieldnames=headers)
        w.writeheader(); w.writerows(rows)

if __name__ == "__main__":
    main()
