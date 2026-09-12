"""
CHAKRAVYUH - IP Geolocation Module
==================================

Resolves IP addresses to geographic information (country, city, ISP)
using the free ip-api.com service. Results are cached locally to
minimize API calls and respect rate limits.

Design Notes:
    - Private/local IPs are handled without network calls.
    - Cache is stored in JSON format for transparency and easy debugging.
    - Network failures degrade gracefully (returns "Unknown").
"""

import json
import requests
from pathlib import Path

CACHE_FILE = Path("logs/geoip_cache.json")
API_TIMEOUT = 5  # seconds


def _load_cache() -> dict:
    """Load the geolocation cache from disk."""
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}


def _save_cache(cache: dict) -> None:
    """Persist the geolocation cache to disk."""
    CACHE_FILE.parent.mkdir(exist_ok=True)
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)


def _is_private_ip(ip: str) -> bool:
    """Return True if the IP is a private/local address."""
    if not ip:
        return True
    if ip in ("127.0.0.1", "::1", "localhost"):
        return True
    return (
        ip.startswith("192.168.") or
        ip.startswith("10.") or
        ip.startswith("172.16.") or
        ip.startswith("172.17.") or
        ip.startswith("172.18.") or
        ip.startswith("172.19.") or
        ip.startswith("172.2") or
        ip.startswith("172.30.") or
        ip.startswith("172.31.")
    )


def get_geo(ip: str) -> dict:
    """
    Look up geographic information for an IP address.

    Parameters
    ----------
    ip : str
        IPv4 address to look up.

    Returns
    -------
    dict
        Keys: country, city, isp, country_code.
    """
    if _is_private_ip(ip):
        return {
            "country": "Local",
            "city": "Localhost",
            "isp": "Private Network",
            "country_code": "LO"
        }

    cache = _load_cache()
    if ip in cache:
        return cache[ip]

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}"
            f"?fields=status,country,countryCode,city,isp",
            timeout=API_TIMEOUT
        )
        data = response.json()

        if data.get("status") == "success":
            result = {
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "country_code": data.get("countryCode", "??")
            }
            cache[ip] = result
            _save_cache(cache)
            return result
    except requests.RequestException as exc:
        print(f"[GeoIP] Lookup failed for {ip}: {exc}")

    return {
        "country": "Unknown",
        "city": "",
        "isp": "",
        "country_code": "??"
    }