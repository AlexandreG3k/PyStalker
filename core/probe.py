"""
HTTP Probing Engine for PyStalker.
Classifies subdomains into web_active, dns_only, timeout, and filtered.
Detects technologies, titles, login pages, SSL certificates, and WAFs.
"""
import ssl
import socket
import re
import concurrent.futures
import requests
import urllib3
from core.config import (
    DEFAULT_TIMEOUT, DEFAULT_THREADS, CUSTOM_HEADERS, LOGIN_INDICATORS
)
from core.utils import get_random_agent, resolve_tool_path
from core.dns_engine import resolve_ip
from core.waf import detect_waf
from core.banner import console, log_info, log_success

# Suppress insecure SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TECH_PATTERNS = {
    "WordPress": r"wp-content|wp-includes|wordpress",
    "Drupal": r"drupal|sites/all",
    "Joomla": r"joomla|/components/com_",
    "Laravel": r"laravel|XSRF-TOKEN|laravel_session",
    "Django": r"csrftoken|django",
    "Flask": r"flask|werkzeug",
    "React": r"react\.production|__react|_next/static",
    "Next.js": r"_next/static|__NEXT_DATA__",
    "Vue.js": r"vue\.js|vue\.min\.js|data-v-",
    "Angular": r"ng-version|angular\.js",
    "Spring Boot": r"whitelabel error page|org\.springframework",
    "ASP.NET": r"viewstate|asp\.net",
    "Ruby on Rails": r"rails|actionpack",
    "Express": r"x-powered-by: express",
    "PHP": r"x-powered-by: php|\.php",
    "Bootstrap": r"bootstrap\.min\.css|bootstrap\.min\.js",
    "TailwindCSS": r"tailwind",
    "jQuery": r"jquery\.min\.js|jquery-[0-9]"
}

def extract_title(html: str) -> str:
    """Extracts HTML page title cleanly."""
    if not html:
        return "No Title"
    match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    if match:
        t = match.group(1).strip().replace("\n", " ").replace("\r", " ")
        return re.sub(r'\s+', ' ', t)[:80]
    return "No Title"

def detect_technologies(headers: dict, html: str, cookies) -> str:
    """Identifies tech stack from headers, HTML content, and cookies."""
    tech = set()

    # Headers
    server = headers.get("server", "")
    if server:
        tech.add(server.split()[0])
    powered_by = headers.get("x-powered-by", "")
    if powered_by:
        tech.add(powered_by)
    if "x-aspnet-version" in headers or "x-aspnetmvc-version" in headers:
        tech.add("ASP.NET")

    # Body matching
    content = html.lower() if html else ""
    for name, pattern in TECH_PATTERNS.items():
        if re.search(pattern, content, re.IGNORECASE):
            tech.add(name)

    # Cookies
    for c in cookies:
        name_lower = c.name.lower()
        if "wp" in name_lower or "wordpress" in name_lower:
            tech.add("WordPress")
        elif "laravel" in name_lower:
            tech.add("Laravel")
        elif "django" in name_lower or "csrftoken" in name_lower:
            tech.add("Django")
        elif "phpsessid" in name_lower:
            tech.add("PHP")
        elif "jsessionid" in name_lower:
            tech.add("Java")
        elif "asp.net" in name_lower or "aspnet" in name_lower:
            tech.add("ASP.NET")

    return ", ".join(sorted(list(tech))) if tech else "Unknown"

def detect_login_page(html: str) -> bool:
    """Detects if page is a login/authentication portal."""
    if not html:
        return False
    lower = html.lower()

    # Form with password input is strong indicator
    if "<input" in lower and ('type="password"' in lower or "type='password'" in lower):
        return True

    # Indicators
    found_count = sum(1 for kw in LOGIN_INDICATORS if kw in lower)
    if found_count >= 3:
        return True

    return False

def get_ssl_issuer(hostname: str, timeout: int = 4) -> str:
    """Extracts SSL Certificate Issuer."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if cert and 'issuer' in cert:
                    for item in cert['issuer']:
                        for k, v in item:
                            if k == 'organizationName' or k == 'commonName':
                                return v
    except Exception:
        pass
    return "N/A"

def check_host(subdomain: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Probes a single subdomain via HTTP/HTTPS and classifies it."""
    ip = resolve_ip(subdomain)
    if not ip:
        return {
            "subdomain": subdomain,
            "category": "dns_only",
            "url": f"http://{subdomain}",
            "status": "DNS Resolution Failed",
            "tech": "N/A",
            "title": "N/A",
            "ip": "N/A",
            "ssl": "N/A",
            "waf": "N/A",
            "login_detected": False,
            "content_length": 0
        }

    has_timeout = False
    has_conn_error = False

    for proto in ["https://", "http://"]:
        url = f"{proto}{subdomain}"
        try:
            headers = CUSTOM_HEADERS.copy()
            headers["User-Agent"] = get_random_agent()

            resp = requests.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
                verify=False
            )

            if resp.status_code < 500:
                tech = detect_technologies(resp.headers, resp.text, resp.cookies)
                title = extract_title(resp.text)
                is_login = detect_login_page(resp.text)
                ssl_issuer = get_ssl_issuer(subdomain) if proto == "https://" else "N/A"
                waf = detect_waf(dict(resp.headers), resp.text[:2000])

                return {
                    "subdomain": subdomain,
                    "category": "web_active",
                    "url": url,
                    "status": resp.status_code,
                    "tech": tech,
                    "title": title,
                    "ip": ip,
                    "ssl": ssl_issuer,
                    "waf": waf,
                    "login_detected": is_login,
                    "content_length": len(resp.content)
                }

        except requests.exceptions.Timeout:
            has_timeout = True
        except requests.exceptions.SSLError:
            pass
        except requests.exceptions.ConnectionError:
            has_conn_error = True
        except Exception:
            pass

    category = "dns_only"
    status_msg = "DNS Only"
    if has_timeout:
        category = "timeout"
        status_msg = "Timeout"
    elif has_conn_error:
        category = "filtered"
        status_msg = "Connection Reset / Filtered"

    return {
        "subdomain": subdomain,
        "category": category,
        "url": f"http://{subdomain}",
        "status": status_msg,
        "tech": "N/A",
        "title": "N/A",
        "ip": ip,
        "ssl": "N/A",
        "waf": "N/A",
        "login_detected": False,
        "content_length": 0
    }

def probe_subdomains(subdomains: list, threads: int = DEFAULT_THREADS, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    Probes all discovered subdomains concurrently.
    Categorizes them into web_active, dns_only, timeout, and filtered.
    """
    classification = {
        "web_active": [],
        "dns_only": [],
        "timeout": [],
        "filtered": []
    }

    total = len(subdomains)
    with console.status(f"[bold cyan]Verificando hosts ativos ({total} alvos, {threads} threads)...[/]", spinner="arc"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_host, sub, timeout): sub for sub in subdomains}
            for fut in concurrent.futures.as_completed(futures):
                try:
                    res = fut.result()
                    cat = res.get("category", "dns_only")
                    if cat in classification:
                        classification[cat].append(res)
                        if cat == "web_active":
                            login_tag = " [bold red][LOGIN][/]" if res["login_detected"] else ""
                            log_success(f"[WEB ACTIVE] {res['url']} ({res['status']}) - {res['title']}{login_tag}")
                except Exception:
                    pass

    return classification
