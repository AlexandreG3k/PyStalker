"""
DNS Engine, Email Security Audit (SPF/DMARC), AXFR, and Subdomain Takeover detection.
"""
import dns.resolver
import dns.zone
import dns.query
import requests
from core.config import TAKEOVER_FINGERPRINTS, DEFAULT_TIMEOUT, CUSTOM_HEADERS
from core.utils import get_random_agent
from core.banner import log_vuln

def resolve_ip(hostname: str) -> str | None:
    """Resolves an IPv4 address for a hostname with short timeout."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.5
        resolver.lifetime = 2.5
        answers = resolver.resolve(hostname, 'A')
        for rdata in answers:
            return str(rdata)
    except Exception:
        return None

def get_dns_records(domain: str) -> dict:
    """Collects A, AAAA, CNAME, MX, TXT, and NS records for a domain."""
    records = {
        "A": [],
        "AAAA": [],
        "CNAME": [],
        "MX": [],
        "TXT": [],
        "NS": []
    }
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    for r_type in records.keys():
        try:
            answers = resolver.resolve(domain, r_type)
            for rdata in answers:
                records[r_type].append(str(rdata).strip('"'))
        except Exception:
            pass

    return records

def check_email_security(domain: str) -> dict:
    """
    Audits SPF, DMARC, and MX records to check if domain is vulnerable to email spoofing.
    """
    audit = {
        "domain": domain,
        "spf_found": False,
        "spf_record": None,
        "spf_status": "Missing",
        "dmarc_found": False,
        "dmarc_record": None,
        "dmarc_policy": "Missing",
        "mx_found": False,
        "spoofable": False,
        "issues": []
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    # Check MX
    try:
        mx_answers = resolver.resolve(domain, 'MX')
        if mx_answers:
            audit["mx_found"] = True
    except Exception:
        audit["mx_found"] = False

    # Check SPF
    try:
        txt_answers = resolver.resolve(domain, 'TXT')
        for rdata in txt_answers:
            txt_str = str(rdata).strip('"')
            if "v=spf1" in txt_str:
                audit["spf_found"] = True
                audit["spf_record"] = txt_str
                if "~all" in txt_str:
                    audit["spf_status"] = "SoftFail (~all)"
                elif "-all" in txt_str:
                    audit["spf_status"] = "Strict (-all)"
                elif "+all" in txt_str or "?all" in txt_str:
                    audit["spf_status"] = "Permissive (+/?all)"
                    audit["issues"].append("SPF policy is permissive (+all/?all), allowing unauthorized sender IPs.")
                break
    except Exception:
        pass

    if not audit["spf_found"]:
        audit["issues"].append("Missing SPF record. Anyone can send spoofed emails using this domain.")

    # Check DMARC
    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in dmarc_answers:
            txt_str = str(rdata).strip('"')
            if "v=DMARC1" in txt_str:
                audit["dmarc_found"] = True
                audit["dmarc_record"] = txt_str
                if "p=none" in txt_str:
                    audit["dmarc_policy"] = "p=none (Monitor Only)"
                    audit["issues"].append("DMARC policy is set to 'p=none', which fails to enforce spoofing rejection.")
                elif "p=quarantine" in txt_str:
                    audit["dmarc_policy"] = "p=quarantine"
                elif "p=reject" in txt_str:
                    audit["dmarc_policy"] = "p=reject (Strong)"
                break
    except Exception:
        pass

    if not audit["dmarc_found"]:
        audit["issues"].append("Missing DMARC record. Email servers will not reject spoofed emails.")

    # If domain has MX (or receives email) and lacks DMARC or has p=none + weak SPF, it's spoofable
    if not audit["dmarc_found"] or audit["dmarc_policy"] == "p=none (Monitor Only)":
        audit["spoofable"] = True

    return audit

def check_zone_transfer(domain: str) -> list:
    """Attempts DNS Zone Transfer (AXFR) on authoritative nameservers."""
    vulnerable_servers = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    try:
        ns_records = resolver.resolve(domain, 'NS')
        for ns in ns_records:
            ns_host = str(ns).rstrip('.')
            try:
                ns_ip = resolver.resolve(ns_host, 'A')[0].to_text()
                z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=4))
                if z and len(z.nodes) > 1:
                    vulnerable_servers.append({
                        "nameserver": ns_host,
                        "ip": ns_ip,
                        "records_count": len(z.nodes)
                    })
            except Exception:
                continue
    except Exception:
        pass

    return vulnerable_servers

def check_takeover(subdomain: str) -> dict | None:
    """
    Checks if a subdomain has a dangling CNAME pointing to a known cloud provider
    and verifies if the service can be claimed (Subdomain Takeover).
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.5
        resolver.lifetime = 2.5
        cname_answers = resolver.resolve(subdomain, 'CNAME')
        cname = str(cname_answers[0].target).rstrip('.')
    except Exception:
        return None

    for provider, data in TAKEOVER_FINGERPRINTS.items():
        if any(cname_pattern in cname.lower() for cname_pattern in data["cname"]):
            # CNAME matches a takeover candidate - verify HTTP response
            for proto in ["https://", "http://"]:
                url = f"{proto}{subdomain}"
                try:
                    headers = CUSTOM_HEADERS.copy()
                    headers["User-Agent"] = get_random_agent()
                    res = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False, allow_redirects=True)
                    for fingerprint in data["response"]:
                        if fingerprint in res.text:
                            log_vuln("CRITICAL", f"Subdomain Takeover Detected ({provider})", url, f"CNAME: {cname}")
                            return {
                                "subdomain": subdomain,
                                "url": url,
                                "cname": cname,
                                "provider": provider,
                                "fingerprint": fingerprint,
                                "status": "CONFIRMED"
                            }
                except Exception:
                    continue

    return None
