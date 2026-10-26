"""
JavaScript Endpoint and Secret Extractor for PyStalker.
Scrapes JS files from live targets and detects exposed tokens and hidden API routes.
"""
import re
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from core.config import CUSTOM_HEADERS, DEFAULT_TIMEOUT
from core.utils import get_random_agent
from core.banner import console, log_vuln

SECRET_PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "Bearer / JWT Token": r"Bearer\s+ey[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_=]*",
    "Generic Secret / API Key": r"(?:api_key|apikey|secret_key|app_secret|client_secret)\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,64}['\"]"
}

API_ROUTE_PATTERN = r"['\"](/api/v[0-9]/[a-zA-Z0-9_\-\/]+|/v[0-9]/[a-zA-Z0-9_\-\/]+|/graphql)[\"']"

def analyze_js_files(active_hosts: list, max_hosts: int = 5, max_scripts_per_host: int = 4) -> list:
    """
    Downloads and scans JavaScript files from top active hosts.
    Returns a list of findings (secrets and endpoints).
    """
    findings = []
    analyzed_urls = set()

    with console.status("[bold cyan]Analisando arquivos JavaScript para detecção de segredos e endpoints...[/]", spinner="dots"):
        for host in active_hosts[:max_hosts]:
            url = host.get("url", "")
            if not url:
                continue

            try:
                headers = CUSTOM_HEADERS.copy()
                headers["User-Agent"] = get_random_agent()
                res = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
                soup = BeautifulSoup(res.text, "html.parser")
                scripts = soup.find_all("script", src=True)

                for tag in scripts[:max_scripts_per_host]:
                    script_src = tag["src"]
                    full_js_url = urljoin(url, script_src)
                    if full_js_url in analyzed_urls or not full_js_url.endswith(".js"):
                        continue
                    analyzed_urls.add(full_js_url)

                    try:
                        js_res = requests.get(full_js_url, headers=headers, timeout=5, verify=False)
                        js_text = js_res.text

                        # Check for secrets
                        for sec_name, pattern in SECRET_PATTERNS.items():
                            matches = re.findall(pattern, js_text)
                            if matches:
                                matched_val = str(matches[0])[:40] + "..."
                                log_vuln("HIGH", f"JavaScript Secret Exposed ({sec_name})", full_js_url, matched_val)
                                findings.append({
                                    "type": "SECRET",
                                    "title": f"Exposed {sec_name}",
                                    "source": full_js_url,
                                    "match": matched_val,
                                    "severity": "HIGH"
                                })

                        # Check for hidden API routes
                        routes = re.findall(API_ROUTE_PATTERN, js_text)
                        if routes:
                            unique_routes = list(set(routes))[:5]
                            findings.append({
                                "type": "ENDPOINT",
                                "title": "Discovered API Routes in JS",
                                "source": full_js_url,
                                "match": ", ".join(unique_routes),
                                "severity": "INFO"
                            })

                    except Exception:
                        continue

            except Exception:
                continue

    return findings
