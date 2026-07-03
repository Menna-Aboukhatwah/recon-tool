import argparse
from utils.logger import setup_logger

def main():
    # 1. Initialize the Command-Line Argument Parser
    parser = argparse.ArgumentParser(
        description="Custom Reconnaissance Tool - Automated Security Information Gathering"
    )
    
    # Core target configuration
    parser.add_argument("-t", "--target", help="Target domain name or IP address", required=True)
    
    # Verbosity configuration
    parser.add_argument("-v", "--verbose", help="Enable verbose (DEBUG) logging output", action="store_true")

    # Flag placeholders for individual feature modules (to be built in later steps)
    parser.add_argument("--whois", help="Run WHOIS lookups", action="store_true")
    parser.add_argument("--dns", help="Run DNS enumeration", action="store_true")
    parser.add_argument("--port-scan", help="Run active port scanning", action="store_true")

    # Parse arguments provided by user execution
    args = parser.parse_args()

    # 2. Initialize our custom logger using the verbose user flag
    logger = setup_logger(verbose=args.verbose)

    logger.info(f"Starting reconnaissance engine against target: {args.target}")
    logger.debug("Verbose logging is enabled. Diagnostic details will be shown.")

    # Contextual routing triggers (Logic will expand as modules are built)
    if args.whois:
        logger.info("WHOIS module triggered (Awaiting module implementation...)")
    if args.dns:
        logger.info("DNS module triggered (Awaiting module implementation...)")
    if args.port_scan:
        logger.info("Port scanning module triggered (Awaiting module implementation...)")

if __name__ == "__main__":
    main()
