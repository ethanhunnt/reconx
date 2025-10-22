# modules/subdomains.py

import asyncio
import logging
import socket
from typing import List, Dict
from core import save_json, timestamp

CRT_URL = "https://crt.sh/?q=%25.{domain}&output=json"
ALIENVAULT_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
BUFFEROOVER_URL = "https://dns.bufferover.run/dns?q={domain}"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
SECURITYTRAILS_URL = "https://api.securitytrails.com/v1/domain/{domain}/subdomains"
CENSYS_URL = "https://search.censys.io/api/v2/resources/websites/domains/{domain}/children"

async def fetch_crtsh(domain: str, proxy: str = None) -> List[str]:
    import aiohttp
    try:
        async with aiohttp.ClientSession() as session:
            logging.info(f"[CRT.SH] Fetching subdomains for {domain} via proxy {proxy}")
            async with session.get(CRT_URL.format(domain=domain), timeout=15, proxy=proxy, ssl=False) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    return list(set(entry["name_value"] for entry in data))
                else:
                    logging.error(f"[CRT.SH] Status code {r.status} fetching {domain}")
    except Exception as e:
        logging.error(f"crt.sh error: {str(e)}")
    return []

async def fetch_alienvault(domain: str, proxy: str = None) -> List[str]:
    import aiohttp
    try:
        async with aiohttp.ClientSession() as session:
            logging.info(f"[AlienVault] Fetching subdomains for {domain} via proxy {proxy}")
            async with session.get(ALIENVAULT_URL.format(domain=domain), timeout=15, proxy=proxy, ssl=False) as r:
                data = await r.json()
                return list(set(entry["hostname"] for entry in data.get("passive_dns", [])))
    except Exception as e:
        logging.error(f"AlienVault error: {str(e)}")
    return []

async def fetch_bufferover(domain: str, proxy: str = None) -> List[str]:
    import aiohttp
    try:
        async with aiohttp.ClientSession() as session:
            logging.info(f"[Bufferover] Fetching subdomains for {domain} via proxy {proxy}")
            async with session.get(BUFFEROOVER_URL.format(domain=domain), timeout=15, proxy=proxy, ssl=False) as r:
                data = await r.json()
                subdomains = []
                for k in ['FDNS_A', 'RDNS']:
                    subdomains += [item.split(',')[1] for item in data.get(k, []) if ',' in item]
                return list(set(subdomains))
    except Exception as e:
        logging.error(f"Bufferover error: {str(e)}")
    return []

async def fetch_virustotal(domain: str, vt_key: str = "", proxy: str = None) -> List[str]:
    import aiohttp
    headers = {"x-apikey": vt_key}
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            logging.info(f"[VirusTotal] Fetching subdomains for {domain} via proxy {proxy}")
            async with session.get(VIRUSTOTAL_URL.format(domain=domain), timeout=15, headers=headers, proxy=proxy, ssl=False) as r:
                if r.status == 200:
                    data = await r.json()
                    return [item["id"] for item in data.get("data", [])]
                else:
                    logging.error(f"[VirusTotal] Status {r.status} for {domain}")
    except Exception as e:
        logging.error(f"VirusTotal error: {str(e)}")
    return []

async def fetch_securitytrails(domain: str, st_key: str = "", proxy: str = None) -> List[str]:
    import aiohttp
    headers = {"apikey": st_key}
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            logging.info(f"[SecurityTrails] Fetching subdomains for {domain} via proxy {proxy}")
            async with session.get(SECURITYTRAILS_URL.format(domain=domain), timeout=15, headers=headers, proxy=proxy, ssl=False) as r:
                if r.status == 200:
                    data = await r.json()
                    subdomains = [f"{sub}.{domain}" for sub in data.get("subdomains", [])]
                    return subdomains
                else:
                    logging.error(f"[SecurityTrails] Status {r.status} for {domain}")
    except Exception as e:
        logging.error(f"SecurityTrails error: {str(e)}")
    return []

async def fetch_censys(domain: str, censys_auth: str = "", proxy: str = None) -> List[str]:
    import aiohttp, base64
    try:
        api_id, api_secret = censys_auth.split(":", 1)
        auth_string = f"{api_id}:{api_secret}"
        auth_header = base64.b64encode(auth_string.encode()).decode()
        headers = {"Authorization": f"Basic {auth_header}"}
        async with aiohttp.ClientSession(headers=headers) as session:
            logging.info(f"[Censys] Fetching children subdomains for {domain} via proxy {proxy}")
            async with session.get(CENSYS_URL.format(domain=domain), timeout=15, headers=headers, proxy=proxy, ssl=False) as r:
                if r.status == 200:
                    data = await r.json()
                    return data.get("result", {}).get("children", [])
                else:
                    logging.error(f"[Censys] Status {r.status} for {domain}")
    except Exception as e:
        logging.error(f"Censys error: {str(e)}")
    return []

def resolve_host(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

async def run_subdomain_enum(domain: str, config: Dict, proxy: str = None):
    logging.info(f"Starting subdomain enumeration for {domain} with proxy {proxy}")

    vt_key = config.get("api_keys", {}).get("virustotal", "")
    st_key = config.get("api_keys", {}).get("securitytrails", "")
    censys_auth = config.get("api_keys", {}).get("censys", "")

    tasks = [
        fetch_crtsh(domain, proxy=proxy),
        fetch_alienvault(domain, proxy=proxy),
        fetch_bufferover(domain, proxy=proxy)
    ]
    if vt_key:
        tasks.append(fetch_virustotal(domain, vt_key, proxy=proxy))
    if st_key:
        tasks.append(fetch_securitytrails(domain, st_key, proxy=proxy))
    if censys_auth:
        tasks.append(fetch_censys(domain, censys_auth, proxy=proxy))

    results = await asyncio.gather(*tasks)
    subdomains = sorted(set(sum(results, [])))
    logging.info(f"Total unique subdomains found: {len(subdomains)}")

    live_hosts = []
    for sd in subdomains:
        ip = resolve_host(sd)
        if ip:
            live_hosts.append({"subdomain": sd, "ip": ip})
            logging.info(f"Resolved live host: {sd} -> {ip}")

    output_path = f"results/{domain}_subdomains_{timestamp()}.json"
    save_json(live_hosts, output_path)
    logging.info(f"Subdomain enumeration complete for {domain}")