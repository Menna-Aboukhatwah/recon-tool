import logging
import requests

logger = logging.getLogger("recon_tool")

def run_subdomain_enum(target: str) -> list:
    """
    Passively queries crt.sh Certificate Transparency logs to find subdomains.
    Returns a sorted list of unique subdomains.
    """
    logger.info(f"Initiating passive subdomain extraction via crt.sh for: {target}")
    
    # Target URL endpoint for JSON queries on crt.sh
    url = f"https://crt.sh/?q=%.{target}&output=json"
    subdomains = set()
    
    try:
        # Use a short timeout to prevent the CLI from hanging indefinitely
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            
            for entry in data:
                # Extract the common name or name value matching the target pattern
                name_value = entry.get("name_value", "")
                
                # Clean up wildcard fields or newline entries sometimes found in logs
                names = name_value.split("\n")
                for name in names:
                    name = name.replace("*.", "").strip().lower()
                    if name and name.endswith(target):
                        subdomains.add(name)
                        
            logger.debug(f"Successfully extracted {len(subdomains)} unique subdomains from logs.")
            return sorted(list(subdomains))
        else:
            logger.error(f"Received non-200 status code from crt.sh API: {response.status_code}")
            return []
            
    except Exception as e:
        logger.error(f"Failed to pull subdomain telemetry data: {str(e)}")
        return []
