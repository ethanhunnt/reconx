import asyncio
import aiohttp
import logging
import time
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from typing import Dict, List
from core import save_json, timestamp
from transformers import pipeline

# Initialize NLP pipeline globally
nlp_classifier = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english")

DEFAULT_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/100.0.4896.127 Safari/537.36")
}

async def fetch(session: aiohttp.ClientSession, url: str) -> Dict:
    try:
        async with session.get(url, headers=DEFAULT_HEADERS, timeout=15, ssl=False) as resp:
            text = await resp.text()
            return {"url": str(resp.url), "status": resp.status, "body": text}
    except Exception as e:
        logging.error(f"Failed to fetch page {url}: {e}")
        return {"url": url, "status": 0, "body": ""}

def classify_response_with_nlp(text: str) -> str:
    try:
        text_sample = text[:512]  # Limit length for performance
        result = nlp_classifier(text_sample)
        label = result[0]["label"].lower()
        if label == "negative":
            return "failure"
        elif label == "positive":
            return "success"
        else:
            return "unknown"
    except Exception as e:
        logging.error(f"NLP classification error: {e}")
        return "unknown"

def classify_page_content(html: str, url: str) -> str:
    url_lower = url.lower()
    # Basic URL heuristic
    if any(k in url_lower for k in ["login", "signin", "log-in"]):
        return "login"
    if any(k in url_lower for k in ["register", "signup", "sign-up"]):
        return "register"
    if any(k in url_lower for k in ["forgot", "reset-password", "lost-password"]):
        return "forgot_password"
    # Use NLP on HTML content for a better guess (simple sentiment analogy)
    return classify_response_with_nlp(html)

async def discover_related_pages(session: aiohttp.ClientSession, base_url: str) -> Dict[str, List[str]]:
    html_resp = await fetch(session, base_url)
    soup = BeautifulSoup(html_resp["body"], "html.parser")
    links = soup.find_all("a", href=True)
    found_pages = {"login": [], "register": [], "forgot_password": []}
    for a in links:
        href = urljoin(base_url, a["href"])
        page_type = classify_page_content("", href)  # URL-based classification
        if page_type in found_pages:
            found_pages[page_type].append(href)
    return found_pages

def parse_login_form(html: str, base_url: str) -> Dict:
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    for form in forms:
        if form.find('input', {'type': 'password'}):
            action = form.get("action") or base_url
            method = form.get("method", "post").lower()
            inputs = {}
            username_field = None
            password_field = None
            for inp in form.find_all("input"):
                name = inp.get("name")
                if not name:
                    continue
                value = inp.get("value", "")
                inputs[name] = value
                if inp.get("type") == "password":
                    password_field = name
                elif username_field is None and re.search(r"user|email|login", name, re.I):
                    username_field = name
            if not password_field:
                raise ValueError("Password field not found")
            if not username_field:
                for inp in form.find_all("input"):
                    name = inp.get("name")
                    if inp.get("type") == "text" and name:
                        username_field = name
                        break
            return {
                "action": urljoin(base_url, action),
                "method": method,
                "inputs": inputs,
                "username_field": username_field,
                "password_field": password_field
            }
    raise ValueError("Login form with password input not found")

def prepare_payload(inputs: Dict[str, str], username_field: str, username: str, password_field: str, password: str) -> Dict[str, str]:
    data = inputs.copy()
    data[username_field] = username
    data[password_field] = password
    return data

async def attempt_login(session: aiohttp.ClientSession, url: str, method: str, data: Dict):
    try:
        start = time.time()
        if method == "post":
            async with session.post(url, data=data, headers=DEFAULT_HEADERS, ssl=False) as resp:
                text = await resp.text()
        else:
            async with session.get(url, params=data, headers=DEFAULT_HEADERS, ssl=False) as resp:
                text = await resp.text()
        elapsed = time.time() - start
        response_class = classify_response_with_nlp(text)
        if "captcha" in text.lower():
            response_class = "captcha"
        elif "lockout" in text.lower() or "too many attempts" in text.lower():
            response_class = "lockout"
        return {"status": resp.status, "response_class": response_class, "time": elapsed, "body": text}
    except Exception as e:
        logging.error(f"Login attempt error: {e}")
        return {"status": 0, "response_class": "error", "time": 0, "body": ""}

async def load_passwords(file_path="passwords.txt") -> List[str]:
    try:
        with open(file_path, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        logging.warning(f"Failed to load passwords.txt: {e}, using default small list.")
        return ["password123", "admin", "test", "letmein", "123456"]

async def run_auth_test(login_url: str, usernames: List[str], password_list: List[str], config: Dict):
    logging.info(f"Starting advanced auth test on {login_url}")

    async with aiohttp.ClientSession() as session:
        page_resp = await fetch(session, login_url)
        if page_resp["status"] == 0:
            logging.error(f"Failed to fetch login page {login_url}, aborting auth test.")
            return

        try:
            form_info = parse_login_form(page_resp["body"], login_url)
        except ValueError as e:
            logging.error(f"{e}, aborting auth test.")
            return

        related_pages = await discover_related_pages(session, login_url)
        logging.info(f"Discovered related pages: {related_pages}")

        results = []
        for username in usernames:
            for i, password in enumerate(password_list):
                payload = prepare_payload(form_info["inputs"], form_info["username_field"], username, form_info["password_field"], password)
                res = await attempt_login(session, form_info["action"], form_info["method"], payload)
                results.append({"username": username, "attempt": i + 1, "password": password, **res})
                logging.info(f"User '{username}' attempt {i+1} password '{password}' resulted in {res['response_class']}")

                if res["response_class"] in ["success", "captcha", "lockout"]:
                    logging.info(f"Stopping brute force for user '{username}' due to {res['response_class']}")
                    break
                await asyncio.sleep(1)

        output_path = f"results/auth_test_{timestamp()}.json"
        save_json(results, output_path)
        logging.info(f"Auth test completed. Results saved to {output_path}")