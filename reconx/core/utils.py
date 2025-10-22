# core/utils.py

import aiohttp
import asyncio
import json
import logging
import os
from typing import List, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Fetch page content asynchronously
async def fetch(session: aiohttp.ClientSession, url: str) -> str:
    try:
        async with session.get(url, timeout=10) as response:
            return await response.text()
    except Exception as e:
        logging.error(f"Error fetching {url}: {str(e)}")
        return ""

# Handle batch asynchronous fetches
async def gather_requests(urls: List[str]) -> List[str]:
    async with aiohttp.ClientSession() as session:
        tasks = [fetch(session, u) for u in urls]
        return await asyncio.gather(*tasks)

# Save data as JSON
def save_json(data: Any, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    logging.info(f"Saved output to {path}")

# Load configuration
def load_config(path: str = "config/settings.json") -> Dict[str, Any]:
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}
