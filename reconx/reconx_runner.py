import asyncio
import logging
import os
import shutil
import json
import requests
import argparse
from core.utils import load_config
from git import Repo
from modules.auth_test import run_auth_test
from modules.subdomains import run_subdomain_enum
from modules.web_enum import run_web_enum
from modules.token_scan import run_token_scan
from modules.ai_login_detector import detect_login_pages

from exploits.injection_tests import run_injection_tests
from exploits.auth_exploit_tests import run_auth_exploit_tests
from exploits.dir_enum import run_dir_enum
from exploits.cve_lookup import run_cve_lookup
from exploits.file_upload_test import run_file_upload_tests
from exploits.misconfig_tests import run_misconfig_tests

GITHUB_API = "https://api.github.com/search/repositories"

def search_github_repos(query, max_repos=3, token=None):
    headers = {"Authorization": f"token {token}"} if token else {}
    params = {"q": query, "per_page": max_repos, "sort": "stars", "order": "desc"}
    try:
        resp = requests.get(GITHUB_API, headers=headers, params=params, timeout=15)
        if resp.status_code == 200:
            return resp.json().get("items", [])
        else:
            logging.error(f"GitHub API error: {resp.status_code} {resp.text}")
            return []
    except Exception as e:
        logging.error(f"GitHub API request failed: {e}")
        return []

def clone_github_repo(clone_url, path):
    if os.path.exists(path):
        shutil.rmtree(path)
    logging.info(f"Cloning {clone_url} into {path}")
    try:
        Repo.clone_from(clone_url, path)
    except Exception as e:
        logging.error(f"Failed to clone repository {clone_url}: {e}")

async def run_auth_tests_on_logins(login_entries, usernames, passwords, config, proxy, concurrent_limit):
    semaphore = asyncio.Semaphore(concurrent_limit)
    async def sem_run_auth_test(entry):
        async with semaphore:
            logging.info(f"Testing login URL {entry['url']} with confidence {entry['confidence']}")
            await run_auth_test(entry['url'], usernames, passwords, config, proxy=proxy)
    await asyncio.gather(*(sem_run_auth_test(entry) for entry in login_entries))

async def main():
    parser = argparse.ArgumentParser(description="ReconX Automated Recon and Exploitation Framework")
    parser.add_argument('--concurrency', type=int, default=20,
                        help='Number of concurrent tasks (default: 20)')
    args = parser.parse_args()
    concurrent_limit = args.concurrency

    config = load_config()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    target_domain = input("Enter target domain for full ReconX scan: ").strip()
    if not target_domain:
        logging.error("No target domain provided. Exiting.")
        return

    proxy = input("Enter proxy URL (e.g., http://127.0.0.1:8080) or leave blank for none: ").strip() or None

    repo_base_dir = f"C:/Security/tools/OSINT Recon tool/reconx/cloned_repos/{target_domain}"
    os.makedirs(repo_base_dir, exist_ok=True)

    # Phase 1: Subdomain enumeration
    logging.info(f"Starting Phase 1: Subdomain Enumeration for {target_domain}")
    await run_subdomain_enum(target_domain, config, proxy=proxy)

    results_dir = "results"
    subdomain_file = next((f for f in os.listdir(results_dir)
                           if f.startswith(target_domain) and "_subdomains_" in f), None)

    if not subdomain_file:
        logging.error("No subdomain results found. Exiting.")
        return

    subdomain_path = os.path.join(results_dir, subdomain_file)
    with open(subdomain_path, "r", encoding="utf-8") as f:
        subdomain_data = json.load(f)
    live_subdomains = [entry["subdomain"] for entry in subdomain_data]

    logging.info(f"Subdomains found: {len(live_subdomains)}")

    # Phase 2: Web enum + AI login detection
    logging.info("Starting Phase 2: Web Enumeration and AI Login Detection")
    all_login_entries = []
    all_discovered_links = []

    async def web_enum_and_ai(subdomain):
        base_url = f"https://{subdomain}"
        logging.info(f"Running web enum for subdomain: {base_url}")
        await run_web_enum(base_url, config, proxy=proxy)
        reports = [f for f in os.listdir(results_dir) if subdomain in f and "_web_enum_" in f]
        if not reports:
            logging.warning(f"No web enum result for {subdomain}, skipping AI detection.")
            return [], []
        latest_report = max(reports, key=lambda x: os.path.getctime(os.path.join(results_dir, x)))
        with open(os.path.join(results_dir, latest_report), "r", encoding="utf-8") as f:
            web_data = json.load(f)
        discovered_links = web_data.get("discovered_links", [])
        if not discovered_links:
            logging.warning(f"No links discovered on {subdomain}")
            return [], []
        detected_pages = await detect_login_pages(base_url, discovered_links, proxy=proxy)
        login_entries = []
        for page_type, urls in detected_pages.items():
            for url in urls:
                login_entries.append({
                    "type": page_type,
                    "url": url,
                    "subdomain": subdomain,
                    "confidence": 1.0 if page_type == "login" else 0.7
                })
        return discovered_links, login_entries

    # Run web enum/AI login detection concurrently
    result = await asyncio.gather(*[
        web_enum_and_ai(subdomain) for subdomain in live_subdomains
    ])
    for discovered_links, login_entries in result:
        all_discovered_links.extend(discovered_links)
        all_login_entries.extend(login_entries)

    logging.info(f"Total login candidates found: {len(all_login_entries)}")

    # Phase 3: GitHub search & clone
    logging.info("Starting Phase 3: GitHub repo search and clone")
    github_token = os.environ.get("GITHUB_TOKEN") or config.get("api_keys", {}).get("github", None)
    query = f"{target_domain} in:name,description"
    repos = search_github_repos(query, max_repos=3, token=github_token)

    cloned_paths = []
    for repo in repos:
        clone_url = repo.get("clone_url")
        repo_name = repo.get("name")
        clone_path = os.path.join(repo_base_dir, repo_name)
        clone_github_repo(clone_url, clone_path)
        cloned_paths.append(clone_path)

    # Phase 4: Token scan
    for path in cloned_paths:
        logging.info(f"Starting Phase 4: Token Scan on {path}")
        run_token_scan(path, config)

    # Phase 5: Injection Tests (async)
    logging.info("Starting Phase 5: Injection Tests")
    inject_results = await run_injection_tests(target_domain, all_discovered_links, proxy=proxy)
    with open(os.path.join(results_dir, f"{target_domain}_injection_results.json"), "w") as f:
        json.dump(inject_results, f, indent=2)

    # Phase 6: Auth Exploit Tests (async)
    logging.info("Starting Phase 6: Authorization Exploit Tests")
    auth_exploit_results = await run_auth_exploit_tests(target_domain, all_discovered_links, proxy=proxy)
    with open(os.path.join(results_dir, f"{target_domain}_auth_exploit_results.json"), "w") as f:
        json.dump(auth_exploit_results, f, indent=2)

    # Phase 7: Directory Enumeration (async)
    logging.info("Starting Phase 7: Directory Enumeration")
    found_dirs = await run_dir_enum(f"https://{target_domain}", proxy=proxy)
    with open(os.path.join(results_dir, f"{target_domain}_dir_enum_results.json"), "w") as f:
        json.dump(found_dirs, f, indent=2)

    # Phase 8: CVE Lookup (async)
    logging.info("Starting Phase 8: CVE Lookup")
    banners = [entry.get("server_banner", "") for entry in subdomain_data if entry.get("server_banner")]
    cve_results = await run_cve_lookup(banners)
    with open(os.path.join(results_dir, f"{target_domain}_cve_lookup_results.json"), "w") as f:
        json.dump(cve_results, f, indent=2)

    # Phase 9: File Upload Tests (async concurrently)
    logging.info("Starting Phase 9: File Upload Tests")
    async def upload_file_enum(subdomain):
        base_url = f"https://{subdomain}"
        findings = await run_file_upload_tests(base_url, proxy=proxy)
        return findings
    file_upload_results = await asyncio.gather(*[
        upload_file_enum(subdomain) for subdomain in live_subdomains
    ])
    file_upload_findings = []
    for findings in file_upload_results:
        file_upload_findings.extend(findings)
    with open(os.path.join(results_dir, f"{target_domain}_file_upload_results.json"), "w") as f:
        json.dump(file_upload_findings, f, indent=2)

    # Phase 10: Misconfiguration Tests (async concurrently)
    logging.info("Starting Phase 10: Misconfiguration Tests")
    async def misconfig_enum(subdomain):
        base_url = f"https://{subdomain}"
        results = await run_misconfig_tests(base_url, proxy=proxy)
        return {base_url: results}
    misconfig_results = await asyncio.gather(*[
        misconfig_enum(subdomain) for subdomain in live_subdomains
    ])
    with open(os.path.join(results_dir, f"{target_domain}_misconfig_results.json"), "w") as f:
        json.dump(misconfig_results, f, indent=2)

    # Phase 11: Auth Testing on detected login pages (high concurrency)
    usernames_input = input("Enter usernames to test (comma separated, default: testuser): ").strip()
    usernames = [u.strip() for u in usernames_input.split(",") if u.strip()] or ["testuser"]
    try:
        with open("passwords.txt", "r", encoding="utf-8") as f:
            password_list = [line.strip() for line in f if line.strip()]
        logging.info(f"Loaded {len(password_list)} passwords.")
    except Exception:
        logging.warning("Passwords file missing, falling back to default list.")
        password_list = ["password123", "admin", "test", "letmein", "123456"]
    if all_login_entries:
        all_login_entries.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        logging.info(f"Starting Phase 11: Concurrent Auth Testing on {len(all_login_entries)} login URLs (limit: {concurrent_limit})")
        await run_auth_tests_on_logins(all_login_entries, usernames, password_list, config, proxy, concurrent_limit)
    else:
        logging.warning("No login URLs detected, skipping auth tests.")

    logging.info("ReconX AI-enhanced workflow complete.")

if __name__ == "__main__":
    asyncio.run(main())
