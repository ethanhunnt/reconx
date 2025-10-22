# modules/token_scan.py

import os
import re
import logging
from typing import List, Dict, Any
from core import save_json, timestamp

# More comprehensive regexes for common leaked tokens/keys
PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?(?:secret|access)?(.{0,20})?['\"]([0-9a-zA-Z/+=]{40})['\"]",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Private RSA Key": r"-----BEGIN(?: RSA)? PRIVATE KEY-----",
    "Heroku API Key": r"heroku[a-f0-9]{32}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    # Add additional patterns as required
}

def scan_file_for_tokens(filepath: str) -> List[Dict[str, Any]]:
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            for name, pattern in PATTERNS.items():
                for match in re.finditer(pattern, content):
                    snippet_start = max(0, match.start() - 30)
                    snippet_end = match.end() + 30
                    snippet = content[snippet_start:snippet_end]
                    findings.append({
                        "file": filepath,
                        "type": name,
                        "line": content.count("\n", 0, match.start()) + 1,
                        "match": match.group(0),
                        "snippet": snippet.strip().replace("\n", " ")
                    })
                    logging.debug(f"Found {name} in {filepath} on line {content.count(chr(10), 0, match.start()) + 1}")
    except Exception as e:
        logging.error(f"Failed to scan {filepath}: {str(e)}")
    return findings

def scan_directory(path: str) -> List[Dict[str, Any]]:
    all_findings = []
    for root, _, files in os.walk(path):
        for file in files:
            full_path = os.path.join(root, file)
            findings = scan_file_for_tokens(full_path)
            if findings:
                all_findings.extend(findings)
    return all_findings

def run_token_scan(target_path: str, config: Dict):
    logging.info(f"Starting token scan in directory: {target_path}")
    results = scan_directory(target_path)
    if results:
        output_path = f"results/token_scan_{timestamp()}.json"
        save_json(results, output_path)
        logging.info(f"Token scan found {len(results)} potential tokens/secrets")
    else:
        logging.info("Token scan found no tokens or secrets")
