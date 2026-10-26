"""
Banner and UI styling using Rich.
"""
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

BANNER_ART = r"""
 ██████╗ ██╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗  ██╗███████╗██████╗ 
 ██╔══██╗╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔══██╗██║     ██║ ██╔╝██╔════╝██╔══██╗
 ██████╔╝ ╚████╔╝ ███████╗   ██║   ███████║██║     █████╔╝ █████╗  ██████╔╝
 ██╔═══╝   ╚██╔╝  ╚════██║   ██║   ██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
 ██║        ██║   ███████║   ██║   ██║  ██║███████╗██║  ██╗███████╗██║  ██║
 ╚═╝        ╚═╝   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
"""

def print_banner(target: str = "", mode: str = "standard", threads: int = 25):
    """Renders the top cyberpunk banner and target metadata."""
    console.print()
    banner_text = Text(BANNER_ART, style="bold cyan")
    console.print(banner_text, justify="center")

    tagline = Text()
    tagline.append("⚡ ULTIMATE RECONNAISSANCE & BUG BOUNTY FRAMEWORK ⚡\n", style="bold bright_cyan")
    tagline.append("🛡️  Developed by ", style="dim")
    tagline.append("BRUMASEC", style="bold magenta")
    tagline.append("  •  Version: ", style="dim")
    tagline.append("2.0.0 Pro", style="bold green")
    tagline.append("  •  Date: ", style="dim")
    tagline.append(datetime.now().strftime("%Y-%m-%d %H:%M"), style="cyan")

    console.print(Panel(tagline, border_style="cyan", box=box.ROUNDED, padding=(0, 2)))

    if target:
        meta_table = Table.grid(padding=(0, 3))
        meta_table.add_column(style="bold bright_blue")
        meta_table.add_column(style="white")
        meta_table.add_column(style="bold bright_blue")
        meta_table.add_column(style="white")

        meta_table.add_row(
            "🎯 TARGET:", f"[bold bright_green]{target}[/]",
            "⚙️ MODE:", f"[bold bright_yellow]{mode.upper()}[/]"
        )
        meta_table.add_row(
            "🧵 THREADS:", f"[cyan]{threads}[/]",
            "⏱️ TIMESTAMP:", f"[dim]{datetime.now().strftime('%H:%M:%S')}[/]"
        )
        console.print(Panel(meta_table, title="[bold cyan]SESSION CONFIGURATION[/]", border_style="bright_blue", box=box.ROUNDED))
    console.print()

def log_step(step_name: str, step_num: int = 0, total_steps: int = 0):
    """Prints a styled step divider."""
    prefix = f"[{step_num}/{total_steps}] " if step_num and total_steps else ""
    console.print(f"\n[bold bright_cyan]─── {prefix}▶ {step_name.upper()} ───[/]")

def log_info(msg: str):
    console.print(f"  [cyan]ℹ[/] {msg}")

def log_success(msg: str):
    console.print(f"  [bold green]✔[/] {msg}")

def log_warning(msg: str):
    console.print(f"  [bold yellow]⚠[/] {msg}")

def log_error(msg: str):
    console.print(f"  [bold red]✖[/] {msg}")

def log_vuln(severity: str, title: str, url: str, extra: str = ""):
    colors = {
        "CRITICAL": "bold red on black",
        "HIGH": "bold red",
        "MEDIUM": "bold yellow",
        "LOW": "bold cyan",
        "INFO": "dim blue"
    }
    style = colors.get(severity.upper(), "bold magenta")
    details = f" - {extra}" if extra else ""
    console.print(f"  [{style}][{severity.upper()}][/{style}] [bold white]{title}[/]: [underline cyan]{url}[/]{details}")

def print_final_summary_rich(
    domain: str,
    total_subdomains: int,
    classification: dict,
    findings: list,
    takeovers: list,
    open_ports: dict,
    dorks_count: int,
    report_path: str
):
    """Renders a comprehensive Rich summary table and dashboard launch prompt."""
    web_active = len(classification.get("web_active", []))
    dns_only = len(classification.get("dns_only", []))
    timeouts = len(classification.get("timeout", []))
    filtered = len(classification.get("filtered", []))
    total_vulns = len(findings)
    total_takeovers = len(takeovers)
    total_ports = sum(len(ports) for ports in open_ports.values())

    console.print()
    summary_table = Table(title="📊 SCAN RESULTS SUMMARY", box=box.ROUNDED, border_style="cyan")
    summary_table.add_column("Category", style="bold white", width=30)
    summary_table.add_column("Count", justify="right", style="bold", width=12)
    summary_table.add_column("Status / Severity", style="dim", width=25)

    summary_table.add_row("Total Discovered Subdomains", str(total_subdomains), "[cyan]DNS Records[/]")
    summary_table.add_row("Web Active Hosts (HTTP/S)", str(web_active), "[bold green]Online & Responsive[/]")
    summary_table.add_row("DNS-Only Subdomains", str(dns_only), "[yellow]No HTTP Service[/]")
    summary_table.add_row("Timeouts / Unreachable", str(timeouts), "[dim red]Connection Dropped[/]")
    summary_table.add_row("Filtered / Blocked", str(filtered), "[dim]Firewall / WAF Drop[/]")
    summary_table.add_section()

    if total_takeovers > 0:
        summary_table.add_row("🚨 Subdomain Takeovers", f"[bold red]{total_takeovers}[/]", "[blink bold red]CRITICAL RISK[/]")
    else:
        summary_table.add_row("Subdomain Takeovers", "0", "[green]Clean (No dangling CNAME)[/]")

    vuln_color = "bold red" if total_vulns > 0 else "green"
    summary_table.add_row("Vulnerabilities & Sensitive Paths", f"[{vuln_color}]{total_vulns}[/]", "[bold yellow]Exposures & Bugs[/]" if total_vulns > 0 else "[green]None Detected[/]")
    summary_table.add_row("Open Ports & Services", str(total_ports), "[bold cyan]Active TCP Ports[/]")
    summary_table.add_row("Google Dorks Results", str(dorks_count), "[magenta]Indexed Data[/]")

    console.print(summary_table)

    # Report path card
    report_panel = Panel(
        f"[bold bright_green]Relatório HTML Profissional Gerado:[/]\n[underline cyan]{report_path}[/]\n\n"
        f"[dim]Totalmente interativo com gráficos Chart.js, busca em tempo real, filtros de status e exportação JSON.[/]",
        title="[bold green]📁 DASHBOARD PRONTO[/]",
        border_style="green",
        box=box.ROUNDED
    )
    console.print(report_panel)
