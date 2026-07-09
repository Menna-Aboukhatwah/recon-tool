import argparse
import sys
import socket

# Import Loggers & Reporting Engine
from utils.logger import setup_logger
from modules.reporter import save_report

# Import Functional Processing Engines
from modules.whois_lookup import run_whois
from modules.dns_enum import run_dns_enum
from modules.subdomain_enum import run_subdomain_enum
from modules.port_scanner import run_port_scan
from modules.banner_grabber import grab_banner
from modules.tech_detector import run_tech_detection

def main():
    parser = argparse.ArgumentParser(description="Custom Reconnaissance Tool Menu Setup")
    parser.add_argument("-t", "--target", help="Target domain name or IP", required=True)
    parser.add_argument("-v", "--verbose", help="Enable verbose logging", action="store_true")
    
    # Execution Modules (Matching image_bd8eac.png usage definitions)
    parser.add_argument("--whois", action="store_true")
    parser.add_argument("--dns", action="store_true")
    parser.add_argument("--subdomains", action="store_true")
    parser.add_argument("--portscan", action="store_true")
    parser.add_argument("--techdetect", action="store_true")
    parser.add_argument("--all", action="store_true")

    # Output Options Setup
    parser.add_argument("--format", choices=["txt", "html"], default="txt", help="Output layout layout format")
    parser.add_argument("-o", "--output", help="Provide a custom filename template")

    args = parser.parse_args()
    logger = setup_logger(verbose=args.verbose)

    # Handle the broad "--all" override trigger flag
    if args.all:
        args.whois = args.dns = args.subdomains = args.portscan = args.techdetect = True

    if not (args.whois or args.dns or args.subdomains or args.portscan or args.techdetect):
        logger.error("No analysis action modules flagged. Add --all or separate specific option markers.")
        sys.exit(1)

    # Prepare master storage data container structure
    aggregated_results = {}
    
    # Try fetching the target IP resolution constraint early for logging and reports
    try:
        aggregated_results["target_ip"] = socket.gethostbyname(args.target)
    except Exception:
        aggregated_results["target_ip"] = "Failed to resolve IP string"

    # --- Engine Execution Sequence Pipeline ---
    if args.whois:
        aggregated_results["whois"] = run_whois(args.target)
    if args.dns:
        aggregated_results["dns"] = run_dns_enum(args.target)
    if args.subdomains:
        aggregated_results["subdomains"] = run_subdomain_enum(args.target)

    if args.portscan:
        open_ports = run_port_scan(args.target)
        aggregated_results["ports"] = {}
        for port in open_ports:
            banner = grab_banner(args.target, port)
            aggregated_results["ports"][port] = banner

    if args.techdetect:
        aggregated_results["tech"] = run_tech_detection(args.target)

    # --- Triggering the Reporting Engine ---
    save_report(
        target=args.target, 
        scan_data=aggregated_results, 
        file_format=args.format, 
        custom_filename=args.output
    )

if __name__ == "__main__":
    main()
