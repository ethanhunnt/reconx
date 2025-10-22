# modules/web_enum.py

import aiohttp
import asyncio
import logging
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import List, Dict
from core import save_json, timestamp

COMMON_PATHS = [
    ".git/", ".env", ".htaccess", "config.php", "wp-config.php",
    "robots.txt", "sitemap.xml", "phpinfo.php", ".DS_Store"
]

SECURITY_HEADERS = [
    "Content-Security-Policy", "Strict-Transport-Security",
    "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"
]

WAPPALYZER_PATTERNS = {
    "wordpress": ["wp-content", "wp-json", "wp-includes"],
    "django": ["csrftoken", "sessionid", "djdebug"],
    "laravel": ["x-csrf-token", "laravel_session"],
    "express": ["x-powered-by: express"],
    "flask": ["set-cookie: session", "flask"],
    "rails": ["_rails_session", "csrf-token"],
    "spring": ["x-powered-by: spring"],
    "react": ["<div id=\"root\">", "reactroot", "_reactroot"],
    "vue": ["data-v-"],
    "angular": ["ng-app", "ng-version", "angular.js"],
    "ember.js": ["ember-view", "emberapplication"],
    "jquery": ["jquery", "jQuery"],
    "backbone.js": ["backbone"],
    "polymer": ["polymer-element"],
    "svelte": ["svelte"],
    "magento": ["mage/cookies", "mage-messages"],
    "drupal": ["drupal.settings", "sites/default"],
    "joomla": ["joomla_session", "j3.9"],
    "shopify": ["cdn.shopify.com"],
    "ghost": ["ghost-head", "ghost-foot"],
    "wix": ["wix.com"],
    "bitrix": ["bitrix"],
    "nginx": ["server: nginx"],
    "apache": ["server: apache"],
    "iis": ["server: microsoft-iis"]
}

async def fetch(session: aiohttp.ClientSession, url: str, proxy: str = None) -> Dict:
    try:
        logging.info(f"Fetching {url} via proxy {proxy}")
        async with session.get(url, timeout=15, proxy=proxy, ssl=False) as response:
            text = await response.text()
            headers = {k.lower(): v for k, v in response.headers.items()}
            logging.info(f"Received status {response.status} for {url}")
            return {"url": str(response.url), "status": response.status, "headers": headers, "body": text}
    except Exception as e:
        logging.error(f"Error fetching {url}: {str(e)}")
        return {"url": url, "status": 0, "headers": {}, "body": ""}

def detect_tech(html: str, headers: Dict) -> List[str]:
    detected = []
    html_lower = html.lower()
    headers_joined = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()

    for tech, indicators in WAPPALYZER_PATTERNS.items():
        for indicator in indicators:
            indicator_lower = indicator.lower()
            if indicator_lower.startswith("server:"):
                if indicator_lower in headers_joined:
                    detected.append(tech)
                    break
            elif indicator_lower in html_lower or indicator_lower in headers_joined:
                detected.append(tech)
                break
    return list(set(detected))

def check_security_headers(headers: Dict) -> Dict:
    results = {}
    for head in SECURITY_HEADERS:
        results[head] = head.lower() in headers
    return results

async def probe_common_paths(base: str, session: aiohttp.ClientSession, proxy: str = None) -> List[str]:
    found = []
    base_url = base if base.endswith("/") else base + "/"
    for p in COMMON_PATHS:
        target = urljoin(base_url, p)
        try:
            logging.info(f"Probing common path {target} with proxy {proxy}")
            async with session.get(target, timeout=10, proxy=proxy, ssl=False) as response:
                if response.status in [200, 403]:
                    found.append(target)
                    logging.info(f"Found interesting path: {target} [{response.status}]")
        except Exception as e:
            logging.debug(f"Skipping {target} due to error: {e}")
            continue
    return found

async def run_web_enum(target: str, config: Dict, proxy: str = None):
    parsed = urlparse(target)
    base_url = target if parsed.scheme else f"http://{target}"
    logging.info(f"Starting web scan for {base_url} with proxy {proxy}...")

    async with aiohttp.ClientSession() as session:
        result = await fetch(session, base_url, proxy=proxy)
        headers, text = result["headers"], result["body"]

        tech = detect_tech(text, headers)
        headers_check = check_security_headers(headers)
        common_files = await probe_common_paths(base_url, session, proxy=proxy)

    soup = BeautifulSoup(text, "html.parser")
    title = soup.title.string.strip() if soup.title else "None"
    links = [urljoin(base_url, a["href"]) for a in soup.find_all("a", href=True)]
    unique_links = sorted(set(links))

    report = {
        "target": base_url,
        "title": title,
        "status": result["status"],
        "technologies": tech,
        "security_headers": headers_check,
        "common_files": common_files,
        "discovered_links": unique_links
    }

    output_path = f"results/{urlparse(base_url).hostname}_web_enum_{timestamp()}.json"
    save_json(report, output_path)
    logging.info(f"Web enumeration completed for {base_url}")