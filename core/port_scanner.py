"""
Fast Concurrent TCP Port Scanner for PyStalker.
Scans critical web, administrative, and database ports on active target IPs.
"""
import socket
import concurrent.futures
from core.config import TOP_PORTS
from core.banner import console, log_info, log_success

PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS",
    3000: "Node.js / React Dev",
    3306: "MySQL",
    5000: "Flask / Python Web",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "Django / Web Alt",
    8080: "HTTP-Proxy / Tomcat",
    8081: "HTTP-Alt / Admin",
    8443: "HTTPS-Alt",
    8888: "Jupyter / Alt Web",
    9000: "PHP-FPM / SonarQube",
    27017: "MongoDB"
}

def scan_single_port(ip: str, port: int, timeout: float = 1.2) -> int | None:
    """Checks if a TCP port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return port
    except Exception:
        pass
    return None

def scan_host_ports(ip: str, ports: list = TOP_PORTS, max_workers: int = 20) -> list:
    """Scans a list of ports on a specific IP."""
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_single_port, ip, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            p = fut.result()
            if p:
                service = PORT_SERVICES.get(p, "Unknown")
                open_ports.append({"port": p, "service": service})
    return sorted(open_ports, key=lambda x: x["port"])

def run_port_scan(active_hosts: list, ports: list = TOP_PORTS, max_threads: int = 25) -> dict:
    """
    Scans distinct IP addresses of active web hosts.
    Returns: { "ip": [ {"port": 80, "service": "HTTP"}, ... ], ... }
    """
    ip_to_hosts = {}
    for host in active_hosts:
        ip = host.get("ip")
        if ip and ip != "N/A":
            ip_to_hosts.setdefault(ip, []).append(host.get("url", ""))

    unique_ips = list(ip_to_hosts.keys())
    if not unique_ips:
        return {}

    results = {}
    log_info(f"Escaneando portas críticas em {len(unique_ips)} IPs distintos...")

    with console.status(f"[bold cyan]Escaneando {len(ports)} portas em {len(unique_ips)} hosts...[/]", spinner="dots"):
        for ip in unique_ips:
            opened = scan_host_ports(ip, ports)
            if opened:
                results[ip] = {
                    "open_ports": opened,
                    "associated_hosts": ip_to_hosts[ip]
                }
                port_list = ", ".join([f"{item['port']}/{item['service']}" for item in opened])
                log_success(f"[PORT SCAN] IP {ip} -> Portas Abertas: [bold green]{port_list}[/]")

    return results
