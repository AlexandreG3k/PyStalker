#!/usr/bin/env python3
"""
PyStalker v2.0 - Advanced Reconnaissance & Vulnerability Suite
Developed for Bug Bounty Hunters and Pentesters | BRUMASEC
"""
import sys
import os
import argparse
import time

# Ensure core package is resolvable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.banner import (
    print_banner, log_step, log_info, log_success, log_warning,
    log_error, print_final_summary_rich, console
)
from core.utils import clean_domain, open_report, copy_to_clipboard
from core.config import DEFAULT_THREADS, DEFAULT_TIMEOUT, TOP_PORTS
from core.recon import collect_subdomains
from core.probe import probe_subdomains
from core.dns_engine import check_email_security, check_takeover, check_zone_transfer
from core.port_scanner import run_port_scan
from core.wayback import mine_wayback_endpoints
from core.js_analyzer import analyze_js_files
from core.vuln_scanner import run_fuzzing, run_nuclei_scanner
from core.dorks import get_dork_list, execute_google_api_dorks
from core.reporter import generate_reports

def run_mock_simulation(target: str = "example.com"):
    """
    Executes a rich UI mock demonstration.
    Generates sample data and creates a realistic HTML dashboard.
    """
    print_banner(target=target, mode="MOCK / UI-TEST", threads=25)
    log_info("Modo de simulação visual (UI Mock) ativado.")
    time.sleep(0.4)

    log_step("Descoberta de Subdomínios", 1, 7)
    mock_subs = [
        target, f"www.{target}", f"api.{target}", f"admin.{target}",
        f"dev.{target}", f"staging.{target}", f"portal.{target}",
        f"mail.{target}", f"vpn.{target}", f"internal.{target}",
        f"auth.{target}", f"beta.{target}", f"cdn.{target}",
        f"assets.{target}", f"status.{target}"
    ]
    log_success(f"15 subdomínios descobertos via Subfinder, Assetfinder, Findomain e crt.sh")

    log_step("Probing HTTP & Detecção de Tecnologias", 2, 7)
    mock_classification = {
        "web_active": [
            {"subdomain": f"admin.{target}", "url": f"https://admin.{target}", "status": 200, "tech": "Laravel, Vue.js, Nginx", "title": "Painel Administrativo", "ip": "104.21.55.10", "waf": "Cloudflare", "login_detected": True, "content_length": 8420},
            {"subdomain": f"api.{target}", "url": f"https://api.{target}", "status": 403, "tech": "Node.js, Express", "title": "API Gateway", "ip": "104.21.55.10", "waf": "Cloudflare", "login_detected": False, "content_length": 240},
            {"subdomain": f"portal.{target}", "url": f"https://portal.{target}", "status": 200, "tech": "React, Next.js", "title": "Portal do Cliente", "ip": "151.101.1.140", "waf": "Fastly", "login_detected": True, "content_length": 15400},
            {"subdomain": f"dev.{target}", "url": f"http://dev.{target}", "status": 302, "tech": "Apache, PHP 8.2", "title": "Redirect", "ip": "192.0.2.45", "waf": "None / Direct", "login_detected": False, "content_length": 450},
            {"subdomain": f"www.{target}", "url": f"https://www.{target}", "status": 200, "tech": "WordPress 6.4, TailwindCSS", "title": "Home - Empresa", "ip": "104.21.55.10", "waf": "Cloudflare", "login_detected": False, "content_length": 32100}
        ],
        "dns_only": [{"subdomain": f"vpn.{target}", "ip": "192.0.2.100"}, {"subdomain": f"mail.{target}", "ip": "192.0.2.101"}],
        "timeout": [{"subdomain": f"staging.{target}", "ip": "192.0.2.102"}],
        "filtered": [{"subdomain": f"internal.{target}", "ip": "10.0.0.1"}]
    }
    log_success(f"5 hosts Web Ativos identificados e categorizados.")

    log_step("Auditoria DNS & Email Security", 3, 7)
    mock_email = {
        "spf_found": True,
        "spf_record": "v=spf1 include:_spf.google.com ~all",
        "spf_status": "SoftFail (~all)",
        "dmarc_found": True,
        "dmarc_record": "v=DMARC1; p=none; sp=none;",
        "dmarc_policy": "p=none (Monitor Only)",
        "spoofable": True
    }
    log_warning("DMARC configurado com 'p=none' - Domínio vulnerável a spoofing de e-mail!")

    log_step("Subdomain Takeover & CNAME Dangling", 4, 7)
    mock_takeovers = [
        {"subdomain": f"status.{target}", "url": f"http://status.{target}", "cname": "status-page.github.io", "provider": "GitHub Pages", "status": "CONFIRMED"}
    ]
    log_success("1 Subdomain Takeover potencial detectado em status." + target)

    log_step("Port Scanning Concorrente", 5, 7)
    mock_ports = {
        "104.21.55.10": {"open_ports": [{"port": 80, "service": "HTTP"}, {"port": 443, "service": "HTTPS"}, {"port": 8443, "service": "HTTPS-Alt"}], "associated_hosts": [f"admin.{target}", f"api.{target}"]},
        "192.0.2.45": {"open_ports": [{"port": 80, "service": "HTTP"}, {"port": 8080, "service": "HTTP-Proxy / Tomcat"}, {"port": 3306, "service": "MySQL"}], "associated_hosts": [f"dev.{target}"]}
    }
    log_success("Portas 8080 e 3306 (MySQL) expostas em 192.0.2.45!")

    log_step("Fuzzing Inteligente & Vulnerabilidades", 6, 7)
    mock_findings = [
        {"url": f"https://admin.{target}/.env", "status": 200, "type": "Configuration Leak (.env)", "severity": "CRITICAL", "length": 1420},
        {"url": f"https://admin.{target}/.git/config", "status": 200, "type": "Source Code Exposure (.git)", "severity": "CRITICAL", "length": 340},
        {"url": f"http://dev.{target}/phpinfo.php", "status": 200, "type": "PHPInfo Exposure", "severity": "HIGH", "length": 45020},
        {"url": f"https://www.{target}/?search=%22%3E%3Cscript%3Ealert(1)%3C/script%3E", "status": 200, "type": "Reflected XSS", "severity": "HIGH", "length": 12400}
    ]
    log_success("4 arquivos críticos / vulnerabilidades confirmadas!")

    log_step("Google Dorks & Exportação do Relatório", 7, 7)
    mock_dorks = get_dork_list(target)
    mock_wayback = {
        "total_urls": 420,
        "parameter_urls": [f"https://www.{target}/view?id=45", f"https://api.{target}/user?token=xyz"],
        "sensitive_files": [f"https://www.{target}/backup.zip"],
        "api_endpoints": [f"https://api.{target}/v1/users"]
    }
    mock_js = [
        {"type": "SECRET", "title": "Exposed Google API Key", "source": f"https://www.{target}/app.js", "match": "AIzaSyD-mockGoogleApiKey12345", "severity": "HIGH"}
    ]

    reports = generate_reports(
        target, mock_subs, mock_classification, mock_findings,
        mock_takeovers, mock_email, mock_ports, mock_wayback, mock_js, mock_dorks
    )

    print_final_summary_rich(
        target, len(mock_subs), mock_classification, mock_findings,
        mock_takeovers, mock_ports, len(mock_dorks), reports["html"]
    )

    try:
        choice = console.input("\n  [bold cyan][ENTER][/] Abrir Dashboard no Navegador  |  [dim][n] Sair  |  [c] Copiar Caminho[/]\n  > ").strip().lower()
        if choice == 'c':
            copy_to_clipboard(os.path.abspath(reports["html"]))
            log_success("Caminho absoluto copiado para o clipboard!")
        elif choice != 'n':
            open_report(reports["html"])
    except (KeyboardInterrupt, EOFError):
        pass
    sys.exit(0)

def scan_target(target: str, args):
    """Executes a full recon & vulnerability scan against a single target."""
    domain = clean_domain(target)
    if not domain:
        log_error(f"Alvo inválido: {target}")
        return

    mode = "FULL AUDIT" if args.full else ("FAST RECON" if args.fast else "STANDARD")
    print_banner(target=domain, mode=mode, threads=args.threads)

    total_steps = 7 if (args.full or args.ports or args.nuclei) else 5

    # 1. Subdomain Discovery
    log_step("Descoberta de Subdomínios Multi-Source", 1, total_steps)
    subdomains = collect_subdomains(domain, fast_mode=args.fast, threads=args.threads)

    # 2. HTTP Probing & Technology Detection
    log_step("Probing HTTP & Classificação de Hosts", 2, total_steps)
    classification = probe_subdomains(subdomains, threads=args.threads, timeout=args.timeout)
    active_hosts = classification.get("web_active", [])

    # Fallback to apex domain if no active subdomains found
    if not active_hosts:
        log_warning("Nenhum subdomínio web ativo encontrado. Testando domínio raiz...")
        apex_probe = probe_subdomains([domain], threads=2, timeout=args.timeout)
        if apex_probe.get("web_active"):
            classification["web_active"].extend(apex_probe["web_active"])
            active_hosts = classification["web_active"]

    # 3. DNS Security & Subdomain Takeover
    log_step("Auditoria de DNS, Spoofing de E-mail & Takeover", 3, total_steps)
    email_sec = check_email_security(domain)
    if email_sec.get("spoofable"):
        log_warning(f"Domínio {domain} potencialmente vulnerável a Email Spoofing (Falta DMARC rígido).")
    else:
        log_success("Políticas SPF e DMARC configuradas adequadamente.")

    takeovers = []
    if not args.fast:
        for sub in subdomains:
            tk = check_takeover(sub)
            if tk:
                takeovers.append(tk)

    # 4. Port Scanning (if full or requested)
    open_ports = {}
    if args.full or args.ports:
        log_step("Port Scanning Concorrente em IPs Ativos", 4, total_steps)
        open_ports = run_port_scan(active_hosts, max_threads=args.threads)

    # 5. Wayback Machine Mining & JS Secrets
    wayback_data = {"total_urls": 0, "parameter_urls": [], "sensitive_files": [], "api_endpoints": []}
    js_secrets = []
    if args.full or args.wayback:
        log_step("Mineração de URLs Históricas & Parâmetros (Wayback)", 5, total_steps)
        wayback_data = mine_wayback_endpoints(domain)

    if args.full or args.js:
        js_secrets = analyze_js_files(active_hosts)

    # 6. Fuzzing & Vulnerability Scanning
    log_step("Fuzzing de Arquivos Sensíveis & Vulnerabilidades", 6 if total_steps == 7 else 4, total_steps)
    findings = []
    if active_hosts:
        findings = run_fuzzing(active_hosts, tech_type=args.tech, threads=args.threads)

    # Nuclei scanner (if requested)
    if args.nuclei and active_hosts:
        nuclei_findings = run_nuclei_scanner(active_hosts, domain)
        findings.extend(nuclei_findings)

    # 7. Google Dorks & Report Generation
    log_step("Google Dorks & Geração de Relatórios", total_steps, total_steps)
    dorks = get_dork_list(domain)
    if args.dorks:
        dorks = execute_google_api_dorks(dorks)

    reports = generate_reports(
        domain, subdomains, classification, findings,
        takeovers, email_sec, open_ports, wayback_data, js_secrets, dorks
    )

    print_final_summary_rich(
        domain, len(subdomains), classification, findings,
        takeovers, open_ports, len(dorks), reports["html"]
    )

    if not args.no_browser:
        try:
            choice = console.input("\n  [bold cyan][ENTER][/] Abrir Dashboard no Navegador  |  [dim][n] Sair  |  [c] Copiar Caminho[/]\n  > ").strip().lower()
            if choice == 'c':
                copy_to_clipboard(os.path.abspath(reports["html"]))
                log_success("Caminho copiado com sucesso!")
            elif choice != 'n':
                open_report(reports["html"])
        except (KeyboardInterrupt, EOFError):
            pass

def main():
    parser = argparse.ArgumentParser(
        description="PyStalker v2.0 - Ultimate Recon & Bug Bounty Framework by BRUMASEC",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("target", nargs="?", default="", help="Domínio ou URL alvo (ex: exemplo.com)")
    parser.add_argument("-l", "--list", help="Arquivo contendo lista de alvos (.txt)")
    parser.add_argument("--fast", action="store_true", help="Modo rápido: pula ferramentas demoradas e foca em velocidade")
    parser.add_argument("--full", action="store_true", help="Modo completo: subdomínios, portas, takeover, wayback, js e fuzzing")
    parser.add_argument("--ports", action="store_true", help="Ativa varredura de portas TCP nos IPs dos subdomínios")
    parser.add_argument("--nuclei", action="store_true", help="Executa templates do Nuclei nos alvos web ativos")
    parser.add_argument("--wayback", action="store_true", help="Minera URLs históricas e parâmetros com Waybackurls")
    parser.add_argument("--js", action="store_true", help="Analisa arquivos JavaScript em busca de tokens e API keys")
    parser.add_argument("--dorks", action="store_true", help="Executa Google Dorks via API (se chaves configuradas)")
    parser.add_argument("--tech", default="generic", choices=["generic", "php", "nodejs", "nextjs", "angular", "django", "flask", "laravel"], help="Tecnologia alvo para payloads específicos")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS, help=f"Número de threads simultâneas (padrão: {DEFAULT_THREADS})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Timeout em segundos para requisições HTTP (padrão: {DEFAULT_TIMEOUT})")
    parser.add_argument("--no-browser", action="store_true", help="Não abre automaticamente o dashboard no navegador")
    parser.add_argument("--mock", "--ui-test", action="store_true", dest="mock", help="Simula uma execução completa de demonstração da UI")

    args = parser.parse_args()

    # UI Mock mode
    if args.mock:
        target = args.target or "alvo-exemplo.com.br"
        run_mock_simulation(target)
        return

    # Check targets
    if not args.target and not args.list:
        parser.print_help()
        print("\n[!] Erro: Você deve fornecer um domínio alvo ou um arquivo com -l/--list.")
        sys.exit(1)

    targets = []
    if args.list:
        if not os.path.isfile(args.list):
            log_error(f"Arquivo de lista não encontrado: {args.list}")
            sys.exit(1)
        with open(args.list, "r") as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    else:
        targets = [args.target]

    try:
        for t in targets:
            scan_target(t, args)
    except KeyboardInterrupt:
        console.print("\n\n[bold yellow][!] Varredura interrompida pelo usuário (Ctrl+C). Saindo com segurança...[/]")
        sys.exit(0)

if __name__ == "__main__":
    main()
