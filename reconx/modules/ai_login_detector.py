# modules/ai_login_detector.py

import aiohttp
import logging
import asyncio
import re
from bs4 import BeautifulSoup
from typing import List, Dict
from urllib.parse import urljoin
from transformers import pipeline

# Initialize zero-shot classification for login page detection
classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

# Basic fallback keywords and text indicators
LOGIN_HINTS = ["login", "sign in", "user", "account", "portal", "auth", "access"]
REGISTER_HINTS = ["register", "sign up", "create account"]
FORGOT_HINTS = ["forgot", "password reset", "recover", "reset password"]

HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/100.0.4896.127 Safari/537.36")
}

async def fetch_html(session: aiohttp.ClientSession, url: str, proxy: str = None) -> str:
    try:
        async with session.get(url, headers=HEADERS, proxy=proxy, timeout=15, ssl=False) as resp:
            text = await resp.text(errors="ignore")
            logging.debug(f"[AI-DETECTOR] Fetched {url} [{resp.status}] (len={len(text)})")
            return text
    except Exception as e:
        logging.debug(f"[AI-DETECTOR] Error fetching {url}: {e}")
        return ""

def heuristic_check(url: str, text: str) -> Dict[str, bool]:
    url_lower = url.lower()
    text_lower = text.lower()
    return {
        "login": any(k in url_lower or k in text_lower for k in LOGIN_HINTS),
        "register": any(k in url_lower or k in text_lower for k in REGISTER_HINTS),
        "forgot": any(k in url_lower or k in text_lower for k in FORGOT_HINTS)
    }

async def analyze_page(session: aiohttp.ClientSession, base_url: str, path: str, proxy: str = None) -> Dict[str, str]:
    target = urljoin(base_url, path)
    html = await fetch_html(session, target, proxy=proxy)
    if not html:
        return {}

    soup = BeautifulSoup(html, "html.parser")
    title = (soup.title.string.strip() if soup.title else "").lower()
    text_sample = " ".join(soup.stripped_strings)[:700]
    heuristic_flags = heuristic_check(target, title + text_sample)

    candidate_labels = ["login page", "registration page", "forgot password page", "homepage", "admin panel"]
    prediction = classifier(text_sample or title, candidate_labels)
    label = prediction["labels"][0]
    score = float(prediction["scores"][0])

    if label in ["login page", "registration page", "forgot password page"] and score > 0.7:
        logging.info(f"[AI-DETECTOR] AI predicted {label} ({score:.2f}) for {target}")

    if label == "login page" or heuristic_flags["login"]:
        return {"type": "login", "url": target, "confidence": score}
    elif label == "registration page" or heuristic_flags["register"]:
        return {"type": "register", "url": target, "confidence": score}
    elif label == "forgot password page" or heuristic_flags["forgot"]:
        return {"type": "forgot", "url": target, "confidence": score}

    return {}

async def detect_login_pages(base_url: str, discovered_links: List[str], proxy: str = None) -> Dict[str, List[str]]:
    logging.info(f"[AI-DETECTOR] Detecting login/register/forgot pages on {base_url} with proxy {proxy}")
    login_pages, register_pages, forgot_pages = [], [], []

    async with aiohttp.ClientSession() as session:
        tasks = [analyze_page(session, base_url, link, proxy=proxy) for link in discovered_links]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for res in results:
        if not res or isinstance(res, Exception):
            continue
        if res["type"] == "login":
            login_pages.append(res["url"])
        elif res["type"] == "register":
            register_pages.append(res["url"])
        elif res["type"] == "forgot":
            forgot_pages.append(res["url"])

    logging.info(f"[AI-DETECTOR] Found {len(login_pages)} login, {len(register_pages)} register, {len(forgot_pages)} forgot URLs.")
    return {
        "login": sorted(set(login_pages)),
        "register": sorted(set(register_pages)),
        "forgot": sorted(set(forgot_pages))
    }
