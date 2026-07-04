import logging
import requests

logger = logging.getLogger("recon_tool")

def run_tech_detection(target: str) -> dict:
    """
    Fingers standard web technologies by looking at HTTP response headers.
    """
    logger.info(f"Initiating web infrastructure technology detection on: {target}")
    
    # Normalize URL format to default to standard HTTP/HTTPS protocols
    if not target.startswith(("http://", "https://")):
        url = f"http://{target}"
    else:
        url = target

    detected_stack = {
        "server": "Unknown",
        "powered_by": "Unknown",
        "security_headers": [],
        "extra_hints": []
    }

    try:
        # Request headers without grabbing the entire body payload
        response = requests.head(url, timeout=5, allow_redirects=True)
        headers = response.headers

        # 1. Parse common server stack headers
        if "Server" in headers:
            detected_stack["server"] = headers["Server"]
        if "X-Powered-By" in headers:
            detected_stack["powered_by"] = headers["X-Powered-By"]

        # 2. Check for the existence of secure headers
        security_indicators = ["X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy"]
        for sec_header in security_indicators:
            if sec_header in headers:
                detected_stack["security_headers"].append(sec_header)

        # 3. Check cookies for specific frameworks
        if "Set-Cookie" in headers:
            cookie_data = headers["Set-Cookie"].lower()
            if "phpsessid" in cookie_data:
                detected_stack["extra_hints"].append("PHP Session Framework")
            if "jsessionid" in cookie_data:
                detected_stack["extra_hints"].append("Java/Tomcat Ecosystem")

        logger.debug(f"Web signatures analyzed. Server detected: {detected_stack['server']}")
        return detected_stack

    except Exception as e:
        logger.error(f"Web application detection failed on {url}: {str(e)}")
        return {"error": f"Technology fingerprinting failed: {str(e)}"}
