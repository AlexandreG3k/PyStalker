"""
Multi-source Subdomain Discovery Engine.
Integrates Subfinder, Assetfinder, Findomain, Amass, crt.sh, Waybackurls, and APIs.
"""
import subprocess
import concurrent.futures
import requests
import json
from core.config import (
    API_KEYS, COMMON_SUBDOMAINS, DEFAULT_TIMEOUT, DEFAULT_THREADS, CUSTOM_HEADERS
)
from core.utils import resolve_tool_path, get_random_agent
from core.banner import log_info, log_success, log_warning, console
from core.dns_engine import resolve_ip

def query_crtsh(domain: str) -> set:
    """Queries crt.sh certificate transparency logs for subdomains."""
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        headers = CUSTOM_HEADERS.copy()
        headers["User-Agent"] = get_random_agent()
        res = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
        if res.status_code == 200:
            data = res.json()
            for item in data:
                name = item.get("name_value", "")
                for entry in name.split("\n"):
                    entry = entry.strip().lower()
                    if entry.startswith("*."):
                        entry = entry[2:]
                    if entry.endswith(f".{domain}") or entry == domain:
                        subdomains.add(entry)
    except Exception:
        pass
    return subdomains

def query_wayback_subdomains(domain: str) -> set:
    """Extracts subdomains from historical Wayback Machine URLs."""
    subdomains = set()
    wayback_bin = resolve_tool_path("waybackurls")
    if not wayback_bin:
        return subdomains

    try:
        cmd = [wayback_bin, domain]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
        for line in res.stdout.splitlines():
            line = line.strip().lower()
            if "://" in line:
                host = line.split("://")[1].split("/")[0].split(":")[0]
                if host.endswith(f".{domain}") or host == domain:
                    subdomains.add(host)
    except Exception:
        pass
    return subdomains

def query_securitytrails(domain: str) -> set:
    """Queries SecurityTrails API for subdomains if API key is provided."""
    subdomains = set()
    api_key = API_KEYS.get("SECURITYTRAILS")
    if not api_key:
        return subdomains
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {"Accept": "application/json", "APIKEY": api_key}
        res = requests.get(url, headers=headers, params={"children_only": "true"}, timeout=10)
        if res.status_code == 200:
            data = res.json()
            for sub in data.get("subdomains", []):
                subdomains.add(f"{sub}.{domain}".lower())
    except Exception:
        pass
    return subdomains

def query_shodan_subdomains(domain: str) -> set:
    """Queries Shodan DNS API if API key is provided."""
    subdomains = set()
    api_key = API_KEYS.get("SHODAN")
    if not api_key:
        return subdomains
    try:
        url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            data = res.json()
            for sub in data.get("subdomains", []):
                subdomains.add(f"{sub}.{domain}".lower())
    except Exception:
        pass
    return subdomains

def run_cli_subdomain_tool(tool_name: str, cmd_args: list, timeout: int, domain: str) -> set:
    """Executes a CLI reconnaissance tool safely with timeout."""
    subdomains = set()
    bin_path = resolve_tool_path(tool_name)
    if not bin_path:
        return subdomains

    cmd_args[0] = bin_path
    try:
        res = subprocess.run(cmd_args, capture_output=True, text=True, timeout=timeout)
        for line in res.stdout.splitlines():
            s = line.strip().lower()
            if s and (s.endswith(f".{domain}") or s == domain):
                subdomains.add(s)
    except subprocess.TimeoutExpired:
        log_warning(f"{tool_name} excedeu o tempo limite ({timeout}s) e foi interrompido.")
    except Exception as e:
        log_warning(f"Erro ao executar {tool_name}: {e}")
    return subdomains

def collect_subdomains(domain: str, fast_mode: bool = False, threads: int = DEFAULT_THREADS) -> list:
    """
    Main aggregator for subdomain discovery.
    Runs multiple OSINT tools in parallel and returns a deduplicated list of subdomains.
    """
    all_subs = set([domain])
    domain = domain.lower()

    # Tool definitions: (name, command, timeout)
    tools = [
        ("subfinder", ["subfinder", "-d", domain, "-silent"], 45),
        ("assetfinder", ["assetfinder", "--subs-only", domain], 25),
        ("findomain", ["findomain", "-t", domain, "--quiet"], 25),
    ]

    if not fast_mode:
        # Amass is thorough but slower, run only in full mode with strict timeout
        tools.append(("amass", ["amass", "enum", "-passive", "-d", domain, "-timeout", "2", "-noalts", "-norecursive"], 90))

    with console.status(f"[bold cyan]Coletando subdomínios para [white]{domain}[/]...[/]", spinner="dots"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            future_to_source = {}

            # Launch CLI tools
            for name, cmd, timeout in tools:
                if resolve_tool_path(name):
                    future = executor.submit(run_cli_subdomain_tool, name, cmd, timeout, domain)
                    future_to_source[future] = name

            # Launch passive web sources
            future_to_source[executor.submit(query_crtsh, domain)] = "crt.sh"
            future_to_source[executor.submit(query_wayback_subdomains, domain)] = "waybackurls"

            if API_KEYS.get("SECURITYTRAILS"):
                future_to_source[executor.submit(query_securitytrails, domain)] = "SecurityTrails API"
            if API_KEYS.get("SHODAN"):
                future_to_source[executor.submit(query_shodan_subdomains, domain)] = "Shodan API"

            for future in concurrent.futures.as_completed(future_to_source):
                src_name = future_to_source[future]
                try:
                    results = future.result()
                    if results:
                        all_subs.update(results)
                        log_success(f"{src_name}: +{len(results)} subdomínios")
                    else:
                        log_info(f"{src_name}: 0 novos resultados")
                except Exception as e:
                    log_warning(f"{src_name}: falhou ({e})")

    # If results are very low (< 5), run fast DNS brute-force
    if len(all_subs) <= 3:
        log_info("Poucos subdomínios encontrados. Executando DNS Brute-Force rápido...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(resolve_ip, f"{sub}.{domain}"): f"{sub}.{domain}" for sub in COMMON_SUBDOMAINS}
            for fut in concurrent.futures.as_completed(futures):
                fqdn = futures[fut]
                ip = fut.result()
                if ip:
                    all_subs.add(fqdn)

    # Clean and validate
    final_list = sorted(list({s for s in all_subs if s.endswith(domain) or s == domain}))
    log_success(f"Total de subdomínios descobertos: [bold cyan]{len(final_list)}[/]")
    return final_list
