import os
import logging
from datetime import datetime

logger = logging.getLogger("recon_tool")

def generate_text_report(target: str, data: dict, output_path: str):
    """Generates a clean, human-readable plain text summary report."""
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("=" * 60 + "\n")
            f.write(f"RECONNAISSANCE SUMMARY REPORT FOR: {target}\n")
            f.write(f"Generated On: {data.get('timestamp', 'N/A')}\n")
            f.write(f"Target IP Resolution: {data.get('target_ip', 'N/A')}\n")
            f.write("=" * 60 + "\n\n")

            # 1. WHOIS Data Section
            f.write("[+] WHOIS REGISTRY INFORMATION\n")
            f.write("-" * 30 + "\n")
            whois = data.get("whois", {})
            if "error" in whois:
                f.write(f"Error: {whois['error']}\n")
            else:
                for k, v in whois.items():
                    f.write(f"{k.replace('_', ' ').title()}: {v}\n")
            f.write("\n")

            # 2. DNS Section
            f.write("[+] DNS RESOURCE RECORDS\n")
            f.write("-" * 30 + "\n")
            dns_records = data.get("dns", {})
            for rtype, records in dns_records.items():
                if records:
                    f.write(f"{rtype} Records:\n")
                    for r in records:
                        f.write(f"  - {r}\n")
                else:
                    f.write(f"{rtype} Records: None discovered.\n")
            f.write("\n")

            # 3. Subdomains Section
            f.write("[+] DISCOVERED SUBDOMAINS\n")
            f.write("-" * 30 + "\n")
            subdomains = data.get("subdomains", [])
            if subdomains:
                for sub in subdomains:
                    f.write(f"  - {sub}\n")
            else:
                f.write("No active subdomains found via passive extraction.\n")
            f.write("\n")

            # 4. Port Scanning & Banner Section
            f.write("[+] ACTIVE NETWORK PORT INFRASTRUCTURE\n")
            f.write("-" * 30 + "\n")
            ports = data.get("ports", {})
            if ports:
                for port, banner in ports.items():
                    f.write(f"Port {port}: OPEN\n")
                    f.write(f"  Banner: {banner}\n")
            else:
                f.write("No open ports found or module was not executed.\n")
            f.write("\n")

            # 5. Technology Fingerprint Section
            f.write("[+] WEB TECHNOLOGY FINGERPRINT\n")
            f.write("-" * 30 + "\n")
            tech = data.get("tech", {})
            if "error" in tech:
                f.write(f"Error: {tech['error']}\n")
            else:
                f.write(f"Web Server Stack: {tech.get('server', 'Unknown')}\n")
                f.write(f"Powered By: {tech.get('powered_by', 'Unknown')}\n")
                f.write(f"Security Headers Present: {', '.join(tech.get('security_headers', [])) or 'None'}\n")
                f.write(f"Additional Signatures: {', '.join(tech.get('extra_hints', [])) or 'None'}\n")

        logger.info(f"Text report successfully saved to {output_path}")
    except Exception as e:
        logger.error(f"Failed to write text report to disk: {str(e)}")


def generate_html_report(target: str, data: dict, output_path: str):
    """Generates a professional web-based dashboard summary report."""
    try:
        # Simple rendering logic without massive external templating tools
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Recon Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 30px; background-color: #f4f6f9; color: #333; }}
        h1, h2 {{ color: #1e293b; border-bottom: 2px solid #cbd5e1; padding-bottom: 8px; }}
        .meta-box {{ background-color: #e2e8f0; padding: 15px; border-radius: 6px; margin-bottom: 25px; }}
        .card {{ background: #fff; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }}
        ul {{ line-height: 1.6; }}
        pre {{ background: #0f172a; color: #38bdf8; padding: 15px; border-radius: 6px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>Security Assessment Report: {target}</h1>
    <div class="meta-box">
        <p><strong>Scan Timestamp:</strong> {data.get('timestamp', 'N/A')}</p>
        <p><strong>Target IP Resolution:</strong> {data.get('target_ip', 'N/A')}</p>
    </div>

    <div class="card">
        <h2>Web Technology Fingerprint</h2>
        <p><strong>Server:</strong> {data.get('tech', {}).get('server', 'Unknown')}</p>
        <p><strong>Powered By:</strong> {data.get('tech', {}).get('powered_by', 'Unknown')}</p>
        <p><strong>Security Headers:</strong> {', '.join(data.get('tech', {}).get('security_headers', [])) or 'None Detected'}</p>
    </div>

    <div class="card">
        <h2>Open Ports & Banner Records</h2>
        <ul>
        """
        ports = data.get("ports", {})
        if ports:
            for port, banner in ports.items():
                html_content += f"<li><strong>Port {port}:</strong> <pre>{banner}</pre></li>"
        else:
            html_content += "<li>No active open ports mapped.</li>"
        
        html_content += f"""
        </ul>
    </div>

    <div class="card">
        <h2>Discovered Subdomains ({len(data.get('subdomains', []))})</h2>
        <ul>
        """
        for sub in data.get('subdomains', []):
            html_content += f"<li>{sub}</li>"
            
        html_content += """
        </ul>
    </div>
</body>
</html>
        """
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        logger.info(f"HTML report successfully saved to {output_path}")
    except Exception as e:
        logger.error(f"Failed to write HTML report to disk: {str(e)}")


def save_report(target: str, scan_data: dict, file_format: str = "txt", custom_filename: str = None):
    """Manager function to handle file generation into the reports/ folder."""
    # Ensure the output directory exists
    os.makedirs("reports", exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Pick custom name or generate a standardized one
    if custom_filename:
        filename = custom_filename
    else:
        filename = f"{target}_{timestamp}.{file_format}"

    output_path = os.path.join("reports", filename)

    if file_format.lower() == "html":
        generate_html_report(target, scan_data, output_path)
    else:
        generate_text_report(target, scan_data, output_path)
    
    print(f"\n[✓] Recon complete. Report saved to: {output_path}")
