import logging
import socket

logger = logging.getLogger("recon_tool")

def grab_banner(target: str, port: int) -> str:
    """
    Connects to an open port and attempts to extract service banner text.
    """
    logger.debug(f"Attempting banner grab on {target}:{port}")
    try:
        target_ip = socket.gethostbyname(target)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect((target_ip, port))
            
            # For some standard protocols (like HTTP), we need to send a probe string to get a response
            if port in [80, 8080, 443]:
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            
            # Read up to 1024 bytes of the banner response
            banner = s.recv(1024).decode(errors='ignore').strip()
            
            if banner:
                # Truncate clean log previews for presentation purposes
                preview = banner.replace('\r', '').replace('\n', ' ')[:50]
                logger.debug(f"Successfully grabbed banner on port {port}: {preview}...")
                return banner
                
    except Exception as e:
        logger.debug(f"Could not retrieve service banner on port {port}: {str(e)}")
        
    return "No banner exposed or dynamic timeout encountered."
