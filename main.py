import argparse
import sys
from utils.logger import setup_logger

# Import the passive modules we created
from modules.whois_lookup import run_whois
from modules.dns_enum import run_dns_enum
from modules.subdomain_enum import run_subdomain_enum

def main():
    parser = argparse.ArgumentParser(
        description="Custom Reconnaissance Tool - Automated Security Information Gathering"
    )
    parser.add_argument("-t", "--target", help="Target domain name or IP address", required=True)
    parser.add_argument("-v", "--verbose", help="Enable verbose (DEBUG) logging output", action="store_true")
    
    # Module activation flags
    parser.add_argument("--whois", help="Run WHOIS lookups", action="store_true")
    parser.add_argument("--dns", help="Run DNS enumeration", action="store_true")
    parser.add_argument("--subdomains", help="Run passive subdomain enumeration", action="store_true")

    args = parser.parse_args()
    logger = setup_logger(verbose=args.verbose)

    logger.info(f"Starting reconnaissance engine against target: {args.target}")

    # Ensure at least one scanning module flag is specified by user
    if not (args.whois or args.dns or args.subdomains):
        logger.error("No assessment flags provided. Please specify --whois, --dns, or --subdomains.")
        sys.exit(1)

    # Dictionary container to aggregate runtime results
    scan_results = {}

    if args.whois:
        scan_results["whois"] = run_whois(args.target)
        print(f"\n[+] WHOIS Results Summary:\n{scan_results['whois']}")

    if args.dns:
        scan_results["dns"] = run_dns_enum(args.target)
        print(f"\n[+] DNS Results Summary:\n{scan_results['dns']}")

    if args.subdomains:
        scan_results["subdomains"] = run_subdomain_enum(args.target)
        print(f"\n[+] Extracted Subdomains Summary:\n{scan_results['subdomains']}")

if __name__ == "__main__":
    main()
