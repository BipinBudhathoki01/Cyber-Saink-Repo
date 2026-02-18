import socket
from concurrent.futures import ThreadPoolExecutor

# Top 20 common ports for quick audit
TOP_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    27017: "MongoDB"
}

def check_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            result = s.connect_ex((host, port))
            if result == 0:
                return port
    except:
        pass
    return None

def scan_network(target_host):
    findings = []
    
    # Resolve domain to IP (if needed) or use as is
    try:
        # Strip protocol if present
        hostname = target_host.replace("https://", "").replace("http://", "").split("/")[0]
        ip = socket.gethostbyname(hostname)
    except Exception as e:
        print(f"[-] Could not resolve host {target_host}: {e}")
        return findings

    print(f"    Scanning ports on {hostname} ({ip})...")

    open_ports = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_port, ip, port) for port in TOP_PORTS.keys()]
        for future in futures:
            port = future.result()
            if port:
                open_ports.append(port)

    for port in open_ports:
        service = TOP_PORTS.get(port, "Unknown")
        severity = "High" if port in [21, 23, 445, 3389, 6379, 27017] else "Medium"
        
        findings.append({
            "title": f"Open Port: {port} ({service})",
            "severity": severity,
            "confidence": "High",
            "evidence": f"Port {port} is open on {ip}",
            "affected_url": target_host,
            "category": "Network & Infrastructure",
            "recommendation": f"Restrict access to port {port}. Use a firewall or VPN.",
        })

    return findings
