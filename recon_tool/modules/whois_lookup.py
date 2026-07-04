import logging
import sys

# Attempt to safely import the external python-whois package
try:
    import whois
except ImportError:
    print("[!] Error: 'python-whois' package is not installed.")
    print("[*] Please add 'python-whois>=0.8.0' to requirements.txt and run pip install.")
    sys.exit(1)

logger = logging.getLogger("recon_tool")

def run_whois(target: str) -> dict:
    """
    Performs a WHOIS registry query against the target domain.
    Returns a dictionary of key registration data.
    """
    logger.info(f"Initiating WHOIS lookup query for: {target}")
    
    try:
        # Perform query using the third-party client
        query_result = whois.whois(target)
        
        # Parse and sanitize output into a standardized dictionary
        parsed_data = {
            "domain_name": query_result.domain_name,
            "registrar": query_result.registrar,
            "creation_date": str(query_result.creation_date) if query_result.creation_date else None,
            "expiration_date": str(query_result.expiration_date) if query_result.expiration_date else None,
            "name_servers": query_result.name_servers if isinstance(query_result.name_servers, list) else [query_result.name_servers]
        }
        
        logger.debug(f"WHOIS data retrieved successfully: {parsed_data['registrar']}")
        return parsed_data

    except Exception as e:
        logger.error(f"Failed to perform WHOIS lookup on {target}: {str(e)}")
        return {"error": f"WHOIS query failed: {str(e)}"}
