"""
Vulnerability Scanner and Tech-Aware Fuzzing Module.
Checks for Sensitive File Exposure, Admin Panels, Reflected XSS, SQLi, and Nuclei integration.
"""
import re
import json
import subprocess
import concurrent.futures
import requests
from core.config import (
    ADMIN_PATHS, SENSITIVE_PATHS, BACKUP_EXTENSIONS, PAYLOADS,
    VULN_SIGNATURES, DEFAULT_TIMEOUT, DEFAULT_THREADS, CUSTOM_HEADERS
)
from core.utils import get_random_agent, resolve_tool_path
from core.probe import detect_login_page, detect_technologies
from core.banner import console, log_vuln, log_info, log_success

def is_false_positive_page(response) -> bool:
    """Filters out generic soft-404s, empty pages, and error handlers."""
    if len(response.content) < 60:
        return True

    if response.status_code in [400, 401, 402, 403, 404, 405, 500, 502, 503]:
        return True

    text_lower = response.text.lower()
    error_phrases = [
        "page not found", "404 not found", "error 404", "not found",
        "access denied", "403 forbidden", "unauthorized access",
        "doesn't exist", "does not exist", "pagina nao encontrada"
    ]
    for phrase in error_phrases:
        if phrase in text_lower:
            return True

    return False

def check_sensitive_url(url: str, tech_type: str = "generic") -> dict | None:
    """Probes a single sensitive URL path."""
    try:
        headers = CUSTOM_HEADERS.copy()
        headers["User-Agent"] = get_random_agent()
        resp = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False, allow_redirects=False)

        # 200 OK or 301/302 Redirect to an internal page
        if resp.status_code == 200 and not is_false_positive_page(resp):
            url_lower = url.lower()
            vuln_type = "Sensitive File Exposure"
            severity = "MEDIUM"

            if ".env" in url_lower or "config" in url_lower:
                vuln_type = "Configuration Leak (.env / config)"
                severity = "CRITICAL"
            elif ".git" in url_lower:
                vuln_type = "Source Code Exposure (.git)"
                severity = "CRITICAL"
            elif ".sql" in url_lower or "backup" in url_lower:
                vuln_type = "Database Backup Exposure"
                severity = "CRITICAL"
            elif "phpinfo" in url_lower:
                vuln_type = "PHPInfo Exposure"
                severity = "HIGH"
            elif any(p in url_lower for p in ["/admin", "/login", "/dashboard", "/controlpanel"]):
                vuln_type = "Admin / Login Portal"
                severity = "MEDIUM"

            log_vuln(severity, vuln_type, url, f"HTTP {resp.status_code} ({len(resp.content)} bytes)")

            return {
                "url": url,
                "status": resp.status_code,
                "type": vuln_type,
                "severity": severity,
                "length": len(resp.content),
                "payload": "N/A"
            }
    except Exception:
        pass
    return None

def test_xss_reflection(base_url: str, tech_type: str = "generic") -> dict | None:
    """Injects and verifies reflected XSS payloads in query parameters."""
    payloads = PAYLOADS["XSS"].get(tech_type, []) + PAYLOADS["XSS"]["generic"]
    for payload in payloads[:3]:
        test_url = f"{base_url.rstrip('/')}/?search={payload}"
        try:
            headers = CUSTOM_HEADERS.copy()
            headers["User-Agent"] = get_random_agent()
            resp = requests.get(test_url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
            if payload in resp.text:
                log_vuln("HIGH", "Reflected XSS Detected", test_url, f"Payload reflected: {payload}")
                return {
                    "url": test_url,
                    "status": resp.status_code,
                    "type": "Reflected XSS",
                    "severity": "HIGH",
                    "length": len(resp.content),
                    "payload": payload
                }
        except Exception:
            continue
    return None

def test_sqli_error(base_url: str) -> dict | None:
    """Injects error-based SQLi probes into query parameters."""
    sqli_probe = "' OR '1'='1"
    test_url = f"{base_url.rstrip('/')}/?id={sqli_probe}"
    try:
        headers = CUSTOM_HEADERS.copy()
        headers["User-Agent"] = get_random_agent()
        resp = requests.get(test_url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
        for pattern in [VULN_SIGNATURES["SQL_INJECTION"]]:
            if re.search(pattern, resp.text, re.IGNORECASE):
                log_vuln("CRITICAL", "SQL Injection (Error-based)", test_url, "Database error pattern matched")
                return {
                    "url": test_url,
                    "status": resp.status_code,
                    "type": "SQL Injection (Error-based)",
                    "severity": "CRITICAL",
                    "length": len(resp.content),
                    "payload": sqli_probe
                }
    except Exception:
        pass
    return None

def run_fuzzing(active_hosts: list, tech_type: str = "generic", threads: int = DEFAULT_THREADS) -> list:
    """
    Fuzzes active web hosts with tech-aware paths and vulnerability probes.
    """
    all_findings = []
    urls_to_fuzz = []

    # Build fuzzing target URLs
    for host in active_hosts:
        base_url = host.get("url", "")
        if not base_url:
            continue

        # Add admin & sensitive paths
        for p in ADMIN_PATHS + SENSITIVE_PATHS:
            urls_to_fuzz.append((f"{base_url.rstrip('/')}{p}", tech_type))

        # Add backup extension checks
        for ext in BACKUP_EXTENSIONS:
            for file_name in ["index.php", "config.php", "database.php", "settings.php"]:
                urls_to_fuzz.append((f"{base_url.rstrip('/')}/{file_name}{ext}", tech_type))

    log_info(f"Iniciando fuzzing de {len(urls_to_fuzz)} requisições com {threads} threads...")

    with console.status(f"[bold cyan]Executando fuzzing inteligente ({len(urls_to_fuzz)} testes)...[/]", spinner="dots"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(check_sensitive_url, u, t) for u, t in urls_to_fuzz]
            for fut in concurrent.futures.as_completed(futures):
                try:
                    res = fut.result()
                    if res:
                        all_findings.append(res)
                except Exception:
                    pass

        # Run XSS & SQLi checks on top 10 hosts
        for host in active_hosts[:10]:
            base_url = host.get("url", "")
            xss_res = test_xss_reflection(base_url, tech_type)
            if xss_res:
                all_findings.append(xss_res)
            sqli_res = test_sqli_error(base_url)
            if sqli_res:
                all_findings.append(sqli_res)

    log_success(f"Fuzzing concluído: {len(all_findings)} vulnerabilidades / arquivos sensíveis encontrados!")
    return all_findings

def run_nuclei_scanner(active_hosts: list, target_domain: str, severity: str = "low,medium,high,critical") -> list:
    """
    Runs Nuclei scanner against active targets using fast exposure and misconfiguration templates.
    """
    nuclei_bin = resolve_tool_path("nuclei")
    if not nuclei_bin:
        log_info("Nuclei não encontrado no sistema. Pulando scan de Nuclei.")
        return []

    target_urls = [h.get("url") for h in active_hosts if h.get("url")]
    if not target_urls:
        return []

    findings = []
    log_info(f"Iniciando scan de vulnerabilidades com Nuclei em {len(target_urls)} alvos...")

    # Write target URLs to a temp file
    temp_target_file = f"/tmp/pystalker_nuclei_{target_domain}.txt"
    try:
        with open(temp_target_file, "w") as f:
            for u in target_urls:
                f.write(f"{u}\n")

        cmd = [
            nuclei_bin,
            "-list", temp_target_file,
            "-severity", severity,
            "-silent",
            "-jsonl",
            "-timeout", "5",
            "-rate-limit", "50"
        ]

        with console.status("[bold cyan]Executando Nuclei Engine...[/]", spinner="dots"):
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            for line in proc.stdout.splitlines():
                if line.strip():
                    try:
                        item = json.loads(line.strip())
                        info = item.get("info", {})
                        sev = info.get("severity", "MEDIUM").upper()
                        name = info.get("name", item.get("template-id", "Nuclei Finding"))
                        matched_at = item.get("matched-at", item.get("host", ""))
                        
                        log_vuln(sev, f"[Nuclei] {name}", matched_at)
                        findings.append({
                            "url": matched_at,
                            "status": 200,
                            "type": f"[Nuclei] {name}",
                            "severity": sev,
                            "length": 0,
                            "payload": item.get("template-id", "")
                        })
                    except Exception:
                        continue
    except Exception as e:
        log_warning(f"Erro ao executar Nuclei: {e}")

    return findings
