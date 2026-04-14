import requests
import re
import time
import logging

log = logging.getLogger(__name__)
VT_BASE = "https://www.virustotal.com/api/v3"


def clean_asset(a: str) -> str:
    return a.replace('[.]', '.').replace('[:]', ':').replace('hxxp', 'http').strip().strip('/')


def extract_domain(a: str) -> str:
    a = clean_asset(a)
    a = re.sub(r'^https?://', '', a)
    return a.split('/')[0].split(':')[0].strip()


def is_ip(s: str) -> bool:
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s))


def get_verdict(stats: dict) -> str:
    if not stats:
        return "Unknown"
    m = stats.get('malicious', 0)
    s = stats.get('suspicious', 0)
    if m >= 5:
        return "Malicious"
    if m >= 1 or s >= 3:
        return "Suspicious"
    if m == 0 and s == 0:
        return "Clean"
    return "Undetected"


def query_domain(domain: str, api_key: str) -> dict:
    try:
        r = requests.get(
            f"{VT_BASE}/domains/{domain}",
            headers={"x-apikey": api_key},
            timeout=10
        )
        if r.status_code == 200:
            d = r.json().get('data', {}).get('attributes', {})
            stats = d.get('last_analysis_stats', {})
            return {
                "queried": domain,
                "found": True,
                "malicious": stats.get('malicious', 0),
                "suspicious": stats.get('suspicious', 0),
                "harmless": stats.get('harmless', 0),
                "undetected": stats.get('undetected', 0),
                "total_engines": sum(stats.values()) if stats else 0,
                "categories": list(set(d.get('categories', {}).values()))[:5],
                "verdict": get_verdict(stats),
                "registrar": d.get('registrar', 'Unknown'),
                "country": d.get('country', 'Unknown'),
                "tags": d.get('tags', [])[:5]
            }
        elif r.status_code == 404:
            return {"queried": domain, "found": False, "verdict": "Not Found in VirusTotal"}
        else:
            return {"queried": domain, "found": False, "verdict": f"API Error {r.status_code}"}
    except Exception as e:
        log.warning(f"VT query failed for {domain}: {e}")
        return {"queried": domain, "found": False, "verdict": "Query Error"}


def enrich_assets(assets: list, api_key: str) -> dict:
    results = {}
    seen = set()
    for asset in assets:
        if not asset or len(asset) < 4:
            continue
        domain = extract_domain(asset)
        if domain and domain not in seen and len(domain) > 3 and '.' in domain:
            seen.add(domain)
            log.info(f"VT querying: {domain}")
            results[domain] = query_domain(domain, api_key)
            time.sleep(0.5)
    return results
