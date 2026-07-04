import argparse
import sys
from utils.logger import setup_logger

# Import Passive Modules
from modules.whois_lookup import run_whois
from modules.dns_enum import run_dns_enum
from modules.subdomain_enum import run_subdomain_enum

# Import Active Modules
from modules.port_scanner import run_port_scan
from modules.banner_grabber import grab_banner
from modules.tech_detector import run_tech_detection

def main():
    parser = argparse.ArgumentParser(description="Custom Reconnaissance Tool")
    parser.add_argument("-t", "--target", help="Target domain name or IP", required=True)
    parser.add_argument("-v", "--verbose", help="Enable verbose logging", action="store_true")
    
    # Configuration flags
    parser.add_argument("--whois", action="store_true")
    parser.add_argument("--dns", action="store_true")
    parser.add_argument("--subdomains", action="store_true")
    parser.add_argument("--scan", help="Run active port scan and banner grab", action="store_true")
    parser.add_argument("--tech", help="Detect web technology stack", action="store_true")

    args = parser.parse_args()
    logger = setup_logger(verbose=args.verbose)

    if not (args.whois or args.dns or args.subdomains or args.scan or args.tech):
        logger.error("No modules selected. Please choose a tool option flag.")
        sys.exit(1)

    scan_results = {}

    # --- Passive Modules Execution Loop ---
    if args.whois:
        scan_results["whois"] = run_whois(args.target)
    if args.dns:
        scan_results["dns"] = run_dns_enum(args.target)
    if args.subdomains:
        scan_results["subdomains"] = run_subdomain_enum(args.target)

    # --- Active Modules Execution Loop ---
    if args.scan:
        open_ports = run_port_scan(args.target)
        scan_results["ports"] = {}
        for port in open_ports:
            banner = grab_banner(args.target, port)
            scan_results["ports"][port] = banner
        print(f"\n[+] Active Port Scanning Findings:\n{scan_results['ports']}")

    if args.tech:
        scan_results["tech"] = run_tech_detection(args.target)
        print(f"\n[+] Tech Stack Fingerprint Findings:\n{scan_results['tech']}")

if __name__ == "__main__":
    main()
