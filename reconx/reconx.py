# reconx.py

import argparse
import asyncio
import logging
from core.utils import load_config, gather_requests
from core.output import timestamp

def main():
    parser = argparse.ArgumentParser(description="ReconX - Modular Reconnaissance Framework")
    parser.add_argument("--mode", choices=["subdomains", "web", "tokens", "auth"], help="Select scan mode.")
    parser.add_argument("--target", required=True, help="Target domain or URL")
    args = parser.parse_args()

    config = load_config()
    logging.info(f"Running ReconX in {args.mode} mode against {args.target}")
    
# inside reconx.py main()

    if args.mode == "auth":
        from modules.auth_test import run_auth_test
        # Example fixed username and password list for demonstration (replace with input or file)
        passwords = ["password123", "admin", "test", "letmein", "123456"]
        asyncio.run(run_auth_test(args.target, "testuser", passwords, config))

    elif args.mode == "tokens":
        from modules.token_scan import run_token_scan
        run_token_scan(args.target, config)

    elif args.mode == "web":
        from modules.web_enum import run_web_enum
        asyncio.run(run_web_enum(args.target, config))

    elif args.mode == "subdomains":
        from modules.subdomains import run_subdomain_enum
        asyncio.run(run_subdomain_enum(args.target, config))
    else:
        logging.warning("Selected mode not implemented yet. Available: subdomains")

if __name__ == "__main__":
    main()
# inside reconx.py main()


