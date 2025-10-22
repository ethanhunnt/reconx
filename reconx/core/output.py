# core/output.py

import json
import csv
import logging
from datetime import datetime
from typing import List, Dict

def print_table(data: List[Dict]):
    if not data:
        logging.info("No data to display.")
        return
    headers = list(data[0].keys())
    widths = [max(len(str(row[h])) for row in data) for h in headers]
    print(" | ".join([f"{h:<{widths[i]}}" for i, h in enumerate(headers)]))
    print("-" * (sum(widths) + len(headers) * 3))
    for row in data:
        print(" | ".join([f"{str(row[h]):<{widths[i]}}" for i, h in enumerate(headers)]))

def export_csv(data: List[Dict], path: str):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
    logging.info(f"CSV exported to {path}")

def export_json(data: List[Dict], path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    logging.info(f"JSON exported to {path}")

def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")
