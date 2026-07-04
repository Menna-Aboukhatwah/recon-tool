import logging
import socket
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger("recon_tool")

# Standard web and infrastructure ports to scan
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 8080, 8443]

def scan_single_port(target_ip: str, port: int, timeout: float = 1.5) -> int or None:
    """
    Attempts a standard TCP handshake with a single port.
    Returns the port number if open, otherwise None.
    """
    # Create a standard TCP streaming socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        # connect_ex returns 0 if the connection was successful
        result = s.connect_ex((target_ip, port))
        if result == 0:
            logger.debug(f"Port {port} discovered OPEN on {target_ip}")
            return port
    return None

def run_port_scan(target: str, ports: list = None) -> list:
    """
    Main entry point for port scanning. Resolves hostnames and runs multi-threaded scanning.
    """
    if ports is None:
        ports = COMMON_PORTS

    logger.info(f"Initiating active port scan against: {target}")
    
    # Resolve hostname to an IP address if a domain name is passed
    try:
        target_ip = socket.gethostbyname(target)
        logger.debug(f"Resolved target host {target} to IP {target_ip}")
    except socket.gaierror:
        logger.error(f"Failed to resolve target hostname: {target}")
        return []

    open_ports = []
    
    # Use ThreadPoolExecutor for high-speed multi-threading
    with ThreadPoolExecutor(max_workers=20) as executor:
        # Submit scan tasks to the pool
        futures = [executor.submit(scan_single_port, target_ip, port) for port in ports]
        
        for future in futures:
            port_result = future.result()
            if port_result is not None:
                open_ports.append(port_result)

    logger.info(f"Port scan complete. Found {len(open_ports)} open ports.")
    return sorted(open_ports)
