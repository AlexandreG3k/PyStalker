"""
Report Generation Engine for PyStalker.
Generates an interactive standalone HTML dashboard, structured JSON, and subdomains TXT file.
"""
import os
import json
from datetime import datetime
from core.config import OUTPUT_DIR

def load_logo_base64() -> str:
    """Loads pre-generated lightweight base64 thumbnail of BRUMASEC logo."""
    b64_path = os.path.join(os.path.dirname(__file__), "..", "assets", "logo", "logo_thumb.b64")
    if os.path.exists(b64_path):
        try:
            with open(b64_path, "r") as f:
                return f.read().strip()
        except Exception:
            pass
    return ""

def generate_reports(
    domain: str,
    total_subs: list,
    classification: dict,
    findings: list,
    takeovers: list,
    email_security: dict,
    open_ports: dict,
    wayback_data: dict,
    js_secrets: list,
    dorks: list
) -> dict:
    """
    Assembles and writes the HTML, JSON, and TXT reports.
    Returns: {"html": path, "json": path, "txt": path}
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # 1. Generate Subdomains TXT
    txt_path = os.path.join(OUTPUT_DIR, f"subdomains_{domain}.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        for s in total_subs:
            f.write(f"{s}\n")

    # 2. Generate JSON Report
    json_path = os.path.join(OUTPUT_DIR, f"pystalker_{domain}_{file_timestamp}.json")
    json_data = {
        "target": domain,
        "scan_date": timestamp_str,
        "author": "BRUMASEC",
        "total_subdomains": len(total_subs),
        "classification": classification,
        "findings": findings,
        "takeovers": takeovers,
        "email_security": email_security,
        "open_ports": open_ports,
        "wayback": wayback_data,
        "js_secrets": js_secrets,
        "dorks": dorks
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)

    # 3. Generate HTML Dashboard
    html_path = os.path.join(OUTPUT_DIR, f"pystalker_report_{domain}.html")
    template_path = os.path.join(os.path.dirname(__file__), "..", "templates", "dashboard_template.html")

    html_template = ""
    if os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as f:
            html_template = f.read()

    web_active = classification.get("web_active", [])
    dns_only = classification.get("dns_only", [])
    timeouts = classification.get("timeout", [])
    filtered = classification.get("filtered", [])

    # Count vulns by severity
    crit_count = sum(1 for f in findings if f.get("severity") == "CRITICAL") + len(takeovers)
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH") + len([j for j in js_secrets if j.get("severity") == "HIGH"])
    med_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low_count = sum(1 for f in findings if f.get("severity") in ["LOW", "INFO"])

    # Subdomains Table Rows
    subs_rows = ""
    for host in web_active:
        st = host.get("status", 200)
        st_class = "status-2xx" if 200 <= st < 300 else ("status-3xx" if 300 <= st < 400 else ("status-4xx" if 400 <= st < 500 else "status-5xx"))
        login_badge = ' <span class="sev-badge sev-HIGH" style="font-size: 0.65rem;">LOGIN</span>' if host.get("login_detected") else ""
        url = host.get("url", "")
        ip = host.get("ip", "N/A")

        subs_rows += f"""
        <tr>
            <td><a href="{url}" target="_blank" class="table-link">{url}</a>{login_badge}</td>
            <td><span class="status-badge {st_class}">{st}</span></td>
            <td><span style="font-family: var(--font-mono); color: var(--text-secondary);">{ip}</span></td>
            <td><span style="color: var(--neon-purple); font-weight: 600;">{host.get('waf', 'None')}</span></td>
            <td>{host.get('tech', 'Unknown')}</td>
            <td><span style="color: var(--text-muted);">{host.get('title', '—')}</span></td>
            <td><button class="copy-btn" onclick="copyText('{url}', this)" title="Copiar URL">📋</button></td>
        </tr>
        """

    # Vulnerabilities Table Rows
    vulns_rows = ""
    # Add takeovers to vulns table
    for tk in takeovers:
        vulns_rows += f"""
        <tr>
            <td><span class="sev-badge sev-CRITICAL">CRITICAL</span></td>
            <td><strong>Subdomain Takeover ({tk.get('provider')})</strong></td>
            <td><a href="{tk.get('url')}" target="_blank" class="table-link">{tk.get('url')}</a></td>
            <td><span class="status-badge status-4xx">404</span></td>
            <td>CNAME: {tk.get('cname')}</td>
            <td><button class="copy-btn" onclick="copyText('{tk.get('url')}', this)">📋</button></td>
        </tr>
        """
    for f in findings:
        sev = f.get("severity", "MEDIUM")
        vulns_rows += f"""
        <tr>
            <td><span class="sev-badge sev-{sev}">{sev}</span></td>
            <td><strong>{f.get('type', 'Vulnerability')}</strong></td>
            <td><a href="{f.get('url')}" target="_blank" class="table-link">{f.get('url')}</a></td>
            <td><span class="status-badge status-2xx">{f.get('status', '200')}</span></td>
            <td>{f.get('length', 0)} bytes</td>
            <td><button class="copy-btn" onclick="copyText('{f.get('url')}', this)">📋</button></td>
        </tr>
        """

    # Subdomain Takeover Alert Card (if any)
    takeover_alert_html = ""
    if takeovers:
        takeover_alert_html = f"""
        <div class="alert-card">
            <div class="alert-icon">🚨</div>
            <div class="alert-content">
                <h4>ALERTA CRÍTICO: {len(takeovers)} SUBDOMAIN TAKEOVER DETECTADO!</h4>
                <p>Foram encontrados subdomínios apontando para serviços externos abandonados (CNAME dangling) que podem ser reivindicados por invasores para controlar o subdomínio completamente.</p>
            </div>
        </div>
        """

    # DNS & Email Security Section
    email_sec_html = f"""
    <div class="cards-grid">
        <div class="info-card">
            <div class="dork-header">
                <span class="dork-cat">SPF (Sender Policy Framework)</span>
                <span class="status-badge {'status-2xx' if email_security.get('spf_found') else 'status-5xx'}">
                    {'ATIVO' if email_security.get('spf_found') else 'FALTANDO'}
                </span>
            </div>
            <div class="dork-code">{email_security.get('spf_record') or 'Nenhum registro SPF configurado!'}</div>
            <p style="font-size: 0.8rem; color: var(--text-secondary);">{email_security.get('spf_status')}</p>
        </div>

        <div class="info-card">
            <div class="dork-header">
                <span class="dork-cat">DMARC (Email Authentication)</span>
                <span class="status-badge {'status-2xx' if 'Reject' in email_security.get('dmarc_policy', '') else ('status-4xx' if 'none' in email_security.get('dmarc_policy', '') else 'status-5xx')}">
                    {email_security.get('dmarc_policy', 'FALTANDO')}
                </span>
            </div>
            <div class="dork-code">{email_security.get('dmarc_record') or 'Nenhum registro _dmarc configurado!'}</div>
            <p style="font-size: 0.8rem; color: var(--text-secondary);">
                {'VULNERÁVEL A SPOOFING DE E-MAIL!' if email_security.get('spoofable') else 'Protegido contra spoofing.'}
            </p>
        </div>
    </div>
    """

    # Ports Section
    ports_html = '<div class="cards-grid">'
    total_ports_count = 0
    if open_ports:
        for ip, p_data in open_ports.items():
            ports_list = p_data.get("open_ports", [])
            total_ports_count += len(ports_list)
            ports_badges = "".join([f'<span class="status-badge status-2xx" style="margin: 2px;">{p["port"]}/{p["service"]}</span>' for p in ports_list])
            hosts_list = "<br>".join([f'<span style="font-size: 0.75rem; color: var(--text-muted);">{h}</span>' for h in p_data.get("associated_hosts", [])[:3]])

            ports_html += f"""
            <div class="info-card">
                <div class="dork-header">
                    <span class="dork-cat">IP: {ip}</span>
                    <span class="badge-ver">{len(ports_list)} Abertas</span>
                </div>
                <div style="margin-bottom: 0.75rem;">{ports_badges}</div>
                <div>{hosts_list}</div>
            </div>
            """
    else:
        ports_html += '<div style="color: var(--text-muted); padding: 1.5rem;">Nenhuma porta crítica não-padrão detectada ou scan de portas não executado.</div>'
    ports_html += '</div>'

    # Wayback & Parameters Section
    wayback_html = '<div class="cards-grid">'
    if wayback_data.get("parameter_urls"):
        for u in wayback_data["parameter_urls"][:15]:
            wayback_html += f"""
            <div class="info-card">
                <div class="dork-header">
                    <span class="dork-cat" style="color: var(--neon-yellow);">Parâmetro Fuzzing</span>
                    <button class="copy-btn" onclick="copyText('{u}', this)">📋</button>
                </div>
                <div class="dork-code"><a href="{u}" target="_blank" style="color: var(--neon-cyan); text-decoration: none;">{u}</a></div>
            </div>
            """
    else:
        wayback_html += '<div style="color: var(--text-muted); padding: 1.5rem;">Nenhum endpoint histórico minerado no momento.</div>'
    wayback_html += '</div>'

    # JS Secrets Section
    js_html = '<div class="cards-grid">'
    if js_secrets:
        for item in js_secrets:
            js_html += f"""
            <div class="info-card">
                <div class="dork-header">
                    <span class="dork-cat" style="color: var(--neon-red);">{item.get('title')}</span>
                    <span class="sev-badge sev-{item.get('severity', 'HIGH')}">{item.get('severity', 'HIGH')}</span>
                </div>
                <div class="dork-code">{item.get('match')}</div>
                <div style="font-size: 0.75rem; color: var(--text-muted); word-break: break-all;">Fonte: {item.get('source')}</div>
            </div>
            """
    else:
        js_html += '<div style="color: var(--text-muted); padding: 1.5rem;">Nenhum token ou segredo sensível exposto em scripts JavaScript analisados.</div>'
    js_html += '</div>'

    # Google Dorks Section
    dorks_html = ""
    for d in dorks:
        dorks_html += f"""
        <div class="info-card">
            <div class="dork-header">
                <span class="dork-cat">{d.get('category')}</span>
                <a href="{d.get('search_url')}" target="_blank" class="btn" style="padding: 2px 8px; font-size: 0.7rem;">Abrir no Google ↗</a>
            </div>
            <div class="dork-code">{d.get('query')}</div>
        </div>
        """

    # Replace placeholders
    replacements = {
        "{{TARGET}}": domain,
        "{{DATE}}": timestamp_str,
        "{{LOGO_BASE64}}": load_logo_base64(),
        "{{TOTAL_SUBDOMAINS}}": str(len(total_subs)),
        "{{WEB_ACTIVE_COUNT}}": str(len(web_active)),
        "{{DNS_ONLY_COUNT}}": str(len(dns_only)),
        "{{TIMEOUTS_COUNT}}": str(len(timeouts)),
        "{{FILTERED_COUNT}}": str(len(filtered)),
        "{{VULNS_COUNT}}": str(len(findings) + len(takeovers)),
        "{{CRITICAL_VULNS_COUNT}}": str(crit_count),
        "{{HIGH_VULNS_COUNT}}": str(high_count),
        "{{MEDIUM_VULNS_COUNT}}": str(med_count),
        "{{LOW_VULNS_COUNT}}": str(low_count),
        "{{PORTS_COUNT}}": str(total_ports_count),
        "{{DORKS_COUNT}}": str(len(dorks)),
        "<!-- {{TAKEOVER_ALERT}} -->": takeover_alert_html,
        "<!-- {{SUBDOMAINS_ROWS}} -->": subs_rows,
        "<!-- {{VULNS_ROWS}} -->": vulns_rows,
        "<!-- {{EMAIL_SECURITY_CONTENT}} -->": email_sec_html,
        "<!-- {{PORTS_CONTENT}} -->": ports_html,
        "<!-- {{WAYBACK_CONTENT}} -->": wayback_html,
        "<!-- {{JS_SECRETS_CONTENT}} -->": js_html,
        "<!-- {{DORKS_CONTENT}} -->": dorks_html,
        "{{REPORT_JSON_DATA}}": json.dumps(json_data, ensure_ascii=False)
    }

    final_html = html_template
    for k, v in replacements.items():
        final_html = final_html.replace(k, v)

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(final_html)

    return {
        "html": html_path,
        "json": json_path,
        "txt": txt_path
    }
