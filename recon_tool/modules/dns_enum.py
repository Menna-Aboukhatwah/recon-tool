import logging
import dns.resolver

logger = logging.getLogger("recon_tool")

def run_dns_enum(target: str) -> dict:
    """
    Queries standard DNS records (A, MX, TXT, NS) for the target domain.
    Returns a dictionary grouped by record types.
    """
    logger.info(f"Initiating DNS query lookup for: {target}")
    
    record_types = ["A", "MX", "TXT", "NS"]
    dns_results = {}
    
    for record in record_types:
        dns_results[record] = []
        try:
            logger.debug(f"Querying DNS record type: {record}")
            answers = dns.resolver.resolve(target, record)
            
            for rdata in answers:
                # Standardize records to string representations
                dns_results[record].append(str(rdata))
                
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            logger.debug(f"No active response found for DNS record type: {record}")
        except Exception as e:
            logger.error(f"Error encountered while querying {record} records: {str(e)}")
            
    return dns_results
