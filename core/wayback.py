"""
Historical Endpoints and Wayback URLs Mining Module.
"""
import subprocess
from urllib.parse import urlparse, parse_qs
from core.utils import resolve_tool_path
from core.config import INTERESTING_PARAMS
from core.banner import console, log_info, log_success

def mine_wayback_endpoints(domain: str, max_urls: int = 250) -> dict:
    """
    Collects historical URLs using waybackurls and categorizes them.
    Returns:
      {
        "total_urls": int,
        "parameter_urls": list,
        "sensitive_files": list,
        "api_endpoints": list
      }
    """
    wayback_bin = resolve_tool_path("waybackurls")
    if not wayback_bin:
        return {"total_urls": 0, "parameter_urls": [], "sensitive_files": [], "api_endpoints": []}

    discovered = set()
    try:
        with console.status(f"[bold cyan]Minerando endpoints históricos via Wayback Machine para {domain}...[/]", spinner="dots"):
            cmd = [wayback_bin, domain]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=35)
            for line in res.stdout.splitlines():
                u = line.strip()
                if u and domain in u:
                    discovered.add(u)
    except Exception:
        pass

    param_urls = []
    sensitive_files = []
    api_endpoints = []

    sens_extensions = (".pdf", ".xls", ".xlsx", ".sql", ".zip", ".tar.gz", ".bak", ".log", ".env", ".json", ".xml", ".txt")

    for url in list(discovered)[:max_urls]:
        parsed = urlparse(url)
        path = parsed.path.lower()
        query = parsed.query

        # Check sensitive file extensions
        if any(path.endswith(ext) for ext in sens_extensions):
            sensitive_files.append(url)

        # Check API endpoints
        if "/api/" in path or "/v1/" in path or "/v2/" in path or "/graphql" in path:
            api_endpoints.append(url)

        # Check interesting parameters
        if query:
            qs = parse_qs(query)
            if any(p.lower() in INTERESTING_PARAMS for p in qs.keys()):
                param_urls.append(url)

    log_success(f"Wayback mining concluído: {len(discovered)} URLs encontradas ({len(param_urls)} com parâmetros de teste)")

    return {
        "total_urls": len(discovered),
        "parameter_urls": param_urls[:50],
        "sensitive_files": sensitive_files[:30],
        "api_endpoints": api_endpoints[:30]
    }
