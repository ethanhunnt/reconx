import asyncio
import logging
import os
import shutil
import json
import requests
from core.utils import load_config
from git import Repo
from modules.auth_test import run_auth_test
from modules.subdomains import run_subdomain_enum
from modules.web_enum import run_web_enum
from modules.token_scan import run_token_scan
from modules.ai_login_detector import detect_login_pages

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

async def run_auth_tests_on_logins(login_entries, usernames, passwords, config, proxy):
    tasks = []
    for entry in login_entries:
        url = entry["url"]
        conf = entry.get("confidence", 0)
        subdomain = entry.get("subdomain", "unknown")
        logging.info(f"Scheduling auth test for '{url}' (confidence={conf:.2f} on {subdomain})")
        tasks.append(run_auth_test(url, usernames, passwords, config, proxy=proxy))
    await asyncio.gather(*tasks)

async def main():
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

    for subdomain in live_subdomains:
        base_url = f"https://{subdomain}"
        logging.info(f"Running web enum for subdomain: {base_url}")
        await run_web_enum(base_url, config, proxy=proxy)

        reports = [f for f in os.listdir(results_dir) if subdomain in f and "_web_enum_" in f]
        if not reports:
            logging.warning(f"No web enum result for {subdomain}, skipping AI detection.")
            continue

        latest_report = max(reports, key=lambda x: os.path.getctime(os.path.join(results_dir, x)))
        with open(os.path.join(results_dir, latest_report), "r", encoding="utf-8") as f:
            web_data = json.load(f)

        discovered_links = web_data.get("discovered_links", [])
        if not discovered_links:
            logging.warning(f"No links discovered on {subdomain}")
            continue

        detected_pages = await detect_login_pages(base_url, discovered_links, proxy=proxy)
        for page_type, urls in detected_pages.items():
            for url in urls:
                all_login_entries.append({
                    "type": page_type,
                    "url": url,
                    "subdomain": subdomain,
                    "confidence": 1.0 if page_type == "login" else 0.7
                })

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

    # Phase 5: Auth testing with concurrency and priority
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
        # Sort login entries by confidence descending
        all_login_entries.sort(key=lambda x: x.get("confidence", 0), reverse=True)

        logging.info(f"Starting Phase 5: Concurrent Auth Testing on {len(all_login_entries)} login URLs")
        # Run concurrent auth tests with bounded semaphore for limited concurrency
        semaphore = asyncio.Semaphore(5)  # limit parallelism to 5

        async def sem_run_auth_test(entry):
            async with semaphore:
                logging.info(f"Testing login URL {entry['url']} from subdomain {entry['subdomain']} with confidence {entry['confidence']}")
                await run_auth_test(entry['url'], usernames, password_list, config, proxy=proxy)

        await asyncio.gather(*(sem_run_auth_test(entry) for entry in all_login_entries))
    else:
        logging.warning("No login URLs detected, skipping auth tests.")

    logging.info("ReconX AI-enhanced workflow complete.")

if __name__ == "__main__":
    asyncio.run(main())
