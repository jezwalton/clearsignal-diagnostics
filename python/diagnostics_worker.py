#!/usr/bin/env python3
"""ClearSignal Diagnostics Worker — comprehensive DNS, network and mail-security checks."""
from __future__ import annotations

import argparse
import ipaddress
import json
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import email.utils
import re
import smtplib
from datetime import datetime, timezone
from email.parser import HeaderParser

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.resolver
import dns.reversename
import dns.rdatatype
import requests

IS_WINDOWS = platform.system().lower() == "windows"

ROOT_SERVERS = [
    "198.41.0.4",     # a.root-servers.net
    "199.9.14.201",   # b.root-servers.net
    "192.33.4.12",    # c.root-servers.net
    "199.7.91.13",    # d.root-servers.net
]

PUBLIC_RESOLVERS = {
    "Cloudflare":    "1.1.1.1",
    "Google":        "8.8.8.8",
    "Quad9":         "9.9.9.9",
    "OpenDNS":       "208.67.222.222",
    "SFIT DNS1":     "46.30.136.19",
    "SFIT DNS2":     "46.30.136.18",
}

# All common record types to scan
RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "SRV", "CAA", "PTR"]

CLOUDFLARE_NETS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32",
    "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32",
]
CLOUDFLARE_RANGES = [ipaddress.ip_network(c) for c in CLOUDFLARE_NETS]

CLOUDFLARE_NS_SUFFIXES = [".ns.cloudflare.com"]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _infer_status(summary: str, cause: str) -> str:
    lower = summary.lower()

    # Explicit OK patterns — override everything
    ok_terms = ("optional", "not enabled", "not configured", "not using",
                "clean", "all ok", "valid", "active", "supported", "consistent",
                "resolved", "reachable", "found", "record found", "present")
    if any(t in lower for t in ok_terms) and not cause:
        return "ok"

    fail_terms = ("fail", "error", "stopped", "not installed",
                  "could not", "missing", "expired ", "connection refused",
                  "verification failed", "timed out", "unreachable",
                  "permerror", "mismatch detected")
    warn_terms = ("warning", "disagree", "possible", "mismatch", "multiple",
                  "proxied", "inconsistent", "lame", "expir", "softfail",
                  "no spf", "no dkim", "no dmarc", "no mx")
    if any(t in lower for t in fail_terms):
        return "fail"
    if any(t in lower for t in warn_terms):
        return "warn"
    if cause:
        return "warn"
    return "ok"


def ok_check(name: str, summary: str, details: Any, cause: str = "", fix: str = "") -> Dict[str, Any]:
    return {
        "name": name,
        "status": _infer_status(summary, cause),
        "summary": summary,
        "details": details,
        "likely_root_cause": cause,
        "recommended_fix": fix,
    }


def safe_run(command: List[str], timeout: int = 10) -> Dict[str, Any]:
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        return {"ok": proc.returncode == 0, "returncode": proc.returncode,
                "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip(), "command": command}
    except Exception as exc:
        return {"ok": False, "returncode": 1, "stdout": "", "stderr": str(exc), "command": command}


def first_ip_for_name(name: str) -> Optional[str]:
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(2.0)
        infos = socket.getaddrinfo(name, 53, proto=socket.IPPROTO_UDP)
        for info in infos:
            if info[4]:
                return info[4][0]
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)
    return None


def is_cloudflare_ip(ip_text: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_text)
        return any(ip_obj in net for net in CLOUDFLARE_RANGES)
    except Exception:
        return False


def is_cloudflare_ns(ns_name: str) -> bool:
    lower = ns_name.lower().rstrip(".")
    return any(lower.endswith(s.rstrip(".")) for s in CLOUDFLARE_NS_SUFFIXES)


def resolve_records(name: str, rdtype: str, server: Optional[str] = None,
                    timeout: float = 2.0) -> Dict[str, Any]:
    """Resolve a record type and return answers with TTL."""
    try:
        resolver = dns.resolver.Resolver(configure=not bool(server))
        resolver.timeout = timeout
        resolver.lifetime = timeout
        if server:
            resolver.nameservers = [server]
        start = time.perf_counter()
        answer = resolver.resolve(name, rdtype)
        elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
        records = []
        for rr in answer:
            records.append(rr.to_text())
        return {
            "rcode": "NOERROR",
            "records": records,
            "ttl": answer.rrset.ttl if answer.rrset else None,
            "response_time_ms": elapsed_ms,
        }
    except dns.resolver.NXDOMAIN:
        return {"rcode": "NXDOMAIN", "records": [], "ttl": None}
    except dns.resolver.NoAnswer:
        return {"rcode": "NOANSWER", "records": [], "ttl": None}
    except dns.resolver.NoNameservers as exc:
        return {"rcode": "SERVFAIL", "records": [], "ttl": None, "error": str(exc)}
    except dns.exception.Timeout:
        return {"rcode": "TIMEOUT", "records": [], "ttl": None}
    except Exception as exc:
        return {"rcode": "ERROR", "records": [], "ttl": None, "error": str(exc)}


def get_txt_records(name: str) -> List[str]:
    out: List[str] = []
    try:
        response = dns.resolver.resolve(name, "TXT")
        for r in response:
            if hasattr(r, "strings"):
                out.append("".join(part.decode() if isinstance(part, bytes) else str(part) for part in r.strings))
            else:
                out.append(r.to_text().strip('"'))
    except Exception:
        pass
    return out


def query_ns_from_server(zone: str, server: str, timeout: float = 2.0) -> Tuple[List[str], str]:
    try:
        q = dns.message.make_query(zone, dns.rdatatype.NS, want_dnssec=True)
        r = dns.query.udp(q, server, timeout=timeout)
        if r.rcode() != dns.rcode.NOERROR:
            return [], dns.rcode.to_text(r.rcode())
        ns_records: List[str] = []
        for section in list(r.answer) + list(r.authority):
            if section.rdtype == dns.rdatatype.NS:
                for rr in section:
                    target = getattr(rr, "target", None)
                    if target:
                        ns_records.append(str(target).rstrip("."))
        return sorted(set(ns_records)), ""
    except Exception as exc:
        return [], str(exc)


def resolve_with_server(qname: str, rdtype: str, server: str, timeout: float = 2.0) -> Tuple[str, List[str], str]:
    try:
        q = dns.message.make_query(qname, rdtype, want_dnssec=True)
        r = dns.query.udp(q, server, timeout=timeout)
        answers: List[str] = []
        for rrset in r.answer:
            if rrset.rdtype == dns.rdatatype.from_text(rdtype):
                answers.extend([item.to_text() for item in rrset])
        return dns.rcode.to_text(r.rcode()), answers, ""
    except Exception as exc:
        return "ERROR", [], str(exc)


def zone_chain_for_fqdn(fqdn: str) -> List[str]:
    labels = fqdn.rstrip(".").split(".")
    zones: List[str] = []
    for i in range(len(labels) - 1):
        zones.append(".".join(labels[i:]))
    zones.append(labels[-1])
    return list(reversed(zones))


def extract_domain(host: str) -> str:
    """Extract registrable domain from a hostname (e.g. 'www.example.co.uk' -> 'example.co.uk')."""
    parts = host.rstrip(".").split(".")
    # Handle known SLDs like co.uk, org.uk, com.au etc.
    known_slds = {"co.uk", "org.uk", "me.uk", "net.uk", "ac.uk", "gov.uk",
                  "com.au", "net.au", "org.au", "co.nz", "net.nz", "org.nz",
                  "co.za", "com.br", "co.in", "co.jp", "uk.com", "eu.com"}
    if len(parts) >= 3:
        sld = ".".join(parts[-2:])
        if sld.lower() in known_slds:
            return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


# ---------------------------------------------------------------------------
# Network checks
# ---------------------------------------------------------------------------

def check_ping(target: str) -> Dict[str, Any]:
    count_flag = "-n" if IS_WINDOWS else "-c"
    result = safe_run(["ping", count_flag, "2", target], timeout=6)
    return ok_check(
        "Ping", "Reachable" if result["ok"] else "Ping failed", result,
        "" if result["ok"] else "Target did not answer ICMP echo or ICMP is filtered.",
        "" if result["ok"] else "Check host availability, firewall rules, and whether ICMP is intentionally blocked.",
    )


def check_traceroute(target: str) -> Dict[str, Any]:
    cmd = None
    if IS_WINDOWS:
        if shutil.which("tracert"):
            cmd = ["tracert", "-h", "12", "-w", "1000", target]
    else:
        if shutil.which("traceroute"):
            cmd = ["traceroute", "-m", "12", target]
        elif shutil.which("tracepath"):
            cmd = ["tracepath", target]
    if cmd is None:
        tool_name = "tracert" if IS_WINDOWS else "traceroute/tracepath"
        return ok_check("Traceroute", "Traceroute utility not installed",
                        {"ok": False, "stderr": f"{tool_name} is not available."},
                        f"The GLPI host is missing {tool_name}.",
                        f"Install {tool_name} on the GLPI host.")
    result = safe_run(cmd, timeout=15)
    return ok_check(
        "Traceroute", "Traceroute completed" if result["ok"] else "Traceroute failed or timed out", result,
        "" if result["ok"] else "Path visibility is limited, blocked, or the utility timed out.",
        "" if result["ok"] else "Check outbound network permissions and confirm the target is reachable.",
    )


# ---------------------------------------------------------------------------
# DNS record checks
# ---------------------------------------------------------------------------

def check_forward_lookup(host: str) -> Dict[str, Any]:
    a = resolve_records(host, "A")
    aaaa = resolve_records(host, "AAAA")
    details = {"A": a, "AAAA": aaaa}
    found = a["records"] + aaaa["records"]
    return ok_check(
        "Forward Lookup", ", ".join(found) if found else "No A or AAAA records found", details,
        "" if found else "The hostname does not publish A or AAAA records.",
        "" if found else "Create or correct the record in the authoritative DNS provider.",
    )


def check_reverse_lookup(ip: str) -> Dict[str, Any]:
    try:
        rev = dns.reversename.from_address(ip)
        ptrs = [r.to_text() for r in dns.resolver.resolve(rev, "PTR")]
        return ok_check("Reverse Lookup", ", ".join(ptrs), {"ip": ip, "PTR": ptrs})
    except Exception as exc:
        return ok_check("Reverse Lookup", "PTR lookup failed", {"ip": ip, "error": str(exc)},
                        "No reverse DNS is configured for this IP.",
                        "Configure the PTR record with the IP owner or upstream provider.")


def check_full_record_scan(host: str) -> Dict[str, Any]:
    """Scan all common record types and return results with TTLs."""
    results: Dict[str, Any] = {}
    types_to_scan = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "CAA"]
    for rdtype in types_to_scan:
        results[rdtype] = resolve_records(host, rdtype)

    # Count how many types returned records
    found_count = sum(1 for v in results.values() if v.get("records"))
    return ok_check(
        "Full Record Scan",
        f"{found_count} record type(s) found for {host}",
        {"host": host, "records": results},
    )


def check_soa(host: str) -> Dict[str, Any]:
    """Get SOA record with parsed fields."""
    try:
        answer = dns.resolver.resolve(host, "SOA")
        soa = answer[0]
        details = {
            "primary_ns": str(soa.mname).rstrip("."),
            "admin_email": str(soa.rname).rstrip(".").replace(".", "@", 1),
            "serial": soa.serial,
            "refresh": soa.refresh,
            "retry": soa.retry,
            "expire": soa.expire,
            "minimum_ttl": soa.minimum,
            "ttl": answer.rrset.ttl,
        }
        return ok_check("SOA Record", f"Serial {soa.serial} — Primary NS: {details['primary_ns']}", details)
    except dns.resolver.NoAnswer:
        # Try the parent domain
        domain = extract_domain(host)
        if domain != host:
            try:
                answer = dns.resolver.resolve(domain, "SOA")
                soa = answer[0]
                details = {
                    "queried": domain,
                    "note": f"SOA not found for {host}, showing SOA for parent {domain}",
                    "primary_ns": str(soa.mname).rstrip("."),
                    "admin_email": str(soa.rname).rstrip(".").replace(".", "@", 1),
                    "serial": soa.serial,
                    "refresh": soa.refresh,
                    "retry": soa.retry,
                    "expire": soa.expire,
                    "minimum_ttl": soa.minimum,
                    "ttl": answer.rrset.ttl,
                }
                return ok_check("SOA Record", f"Serial {soa.serial} (from {domain})", details)
            except Exception:
                pass
        return ok_check("SOA Record", "No SOA record found", {"host": host},
                        "The domain does not return an SOA record.",
                        "Verify the zone exists and the nameservers are correctly delegated.")
    except Exception as exc:
        return ok_check("SOA Record", "SOA lookup failed", {"error": str(exc)},
                        "Could not retrieve the SOA record.",
                        "Check DNS configuration and nameserver health.")


def check_ns_detail(host: str) -> Dict[str, Any]:
    """Get NS records with their IP addresses and response test."""
    domain = host
    # Try to get NS for the exact name first, fall back to parent domain
    ns_result = resolve_records(domain, "NS")
    if not ns_result["records"]:
        domain = extract_domain(host)
        ns_result = resolve_records(domain, "NS")

    if not ns_result["records"]:
        return ok_check("Nameservers", "No NS records found", {"host": host},
                        "No nameservers are published for this domain.",
                        "Check delegation at the parent zone / registrar.")

    ns_details = []
    for ns_name_raw in ns_result["records"]:
        ns_name = ns_name_raw.rstrip(".")
        ns_ip = first_ip_for_name(ns_name)
        is_cf = is_cloudflare_ns(ns_name)

        # Test if the NS actually responds
        responds = False
        response_time_ms = None
        if ns_ip:
            rcode, _, _ = resolve_with_server(domain, "SOA", ns_ip, timeout=2.0)
            responds = rcode == "NOERROR"

        ns_details.append({
            "nameserver": ns_name,
            "ip": ns_ip,
            "responds": responds,
            "is_cloudflare": is_cf,
        })

    all_respond = all(n["responds"] for n in ns_details if n["ip"])
    cf_count = sum(1 for n in ns_details if n["is_cloudflare"])
    non_respond = [n["nameserver"] for n in ns_details if n["ip"] and not n["responds"]]

    summary = f"{len(ns_details)} nameserver(s) for {domain}"
    if cf_count:
        summary += f" ({cf_count} Cloudflare)"
    if non_respond:
        summary += f" — {len(non_respond)} not responding"

    cause = ""
    fix = ""
    if non_respond:
        cause = f"Nameserver(s) not responding: {', '.join(non_respond)}"
        fix = "Check nameserver health or update delegation to remove stale entries."

    return ok_check("Nameservers", summary, {
        "domain": domain,
        "nameservers": ns_details,
        "ttl": ns_result.get("ttl"),
    }, cause, fix)


# ---------------------------------------------------------------------------
# Delegation and DNSSEC
# ---------------------------------------------------------------------------

def check_delegation_trace(fqdn: str) -> Dict[str, Any]:
    hops: List[Dict[str, Any]] = []
    current_servers = ROOT_SERVERS[:]
    failure = None

    for zone in zone_chain_for_fqdn(fqdn):
        found_ns: List[str] = []
        last_error = ""
        for server in current_servers[:2]:
            ns, err = query_ns_from_server(zone, server)
            if ns:
                found_ns = ns
                hops.append({"zone": zone, "queried_server": server, "ns_records": ns})
                break
            last_error = err

        if not found_ns:
            failure = {"zone": zone, "error": last_error or "No NS returned"}
            hops.append({"zone": zone, "queried_servers": current_servers[:2], "error": failure["error"]})
            break

        next_servers = []
        for ns in found_ns:
            ip = first_ip_for_name(ns)
            if ip:
                next_servers.append(ip)
        if not next_servers:
            failure = {"zone": zone, "error": "No glue/resolvable nameserver addresses"}
            break
        current_servers = next_servers

    if failure:
        return ok_check(
            "Delegation Trace", f"Delegation stopped at {failure['zone']}",
            {"hops": hops, "failure": failure},
            f"Delegation appears broken at {failure['zone']}.",
            "Ensure the parent publishes the correct nameservers and the child zone is active.",
        )
    return ok_check("Delegation Trace", "Full delegation path resolved", {"hops": hops})


def check_dnssec_validation(fqdn: str, rdtype: str = "A") -> Dict[str, Any]:
    server = PUBLIC_RESOLVERS["Cloudflare"]
    try:
        q1 = dns.message.make_query(fqdn, rdtype, want_dnssec=True)
        r1 = dns.query.udp(q1, server, timeout=3)
        normal_rcode = dns.rcode.to_text(r1.rcode())
        normal_answers = []
        for rrset in r1.answer:
            if rrset.rdtype == dns.rdatatype.from_text(rdtype):
                normal_answers.extend([r.to_text() for r in rrset])

        q2 = dns.message.make_query(fqdn, rdtype, want_dnssec=True)
        q2.flags |= dns.flags.CD
        r2 = dns.query.udp(q2, server, timeout=3)
        cd_rcode = dns.rcode.to_text(r2.rcode())
        cd_answers = []
        for rrset in r2.answer:
            if rrset.rdtype == dns.rdatatype.from_text(rdtype):
                cd_answers.extend([r.to_text() for r in rrset])

        # Check for DS record at parent
        domain = extract_domain(fqdn)
        ds_result = resolve_records(domain, "DS")
        has_ds = bool(ds_result.get("records"))

        details = {
            "standard_rcode": normal_rcode, "cd_rcode": cd_rcode,
            "standard_answers": normal_answers, "cd_answers": cd_answers,
            "ds_record_exists": has_ds, "ds_records": ds_result.get("records", []),
        }

        if normal_rcode == "SERVFAIL" and cd_answers:
            return ok_check("DNSSEC", "DNSSEC mismatch detected", details,
                            "Standard validation failed but CD flag returned data — DS/DNSKEY mismatch.",
                            "Remove stale DS record at registrar, or regenerate and publish the correct DS from the DNS provider.")

        if normal_rcode == "NOERROR" and cd_rcode == "NOERROR":
            if has_ds:
                return ok_check("DNSSEC", "DNSSEC active and validating", details)
            else:
                return ok_check("DNSSEC", "DNSSEC not enabled — optional", details)

        return ok_check("DNSSEC", f"Standard={normal_rcode}; CD={cd_rcode}", details)
    except Exception as exc:
        return ok_check("DNSSEC", "DNSSEC check failed", {"error": str(exc)},
                        "The DNSSEC check could not be completed.",
                        "Retry the test and review DNSSEC status at the DNS provider.")


def check_parent_child_ns(fqdn: str) -> Dict[str, Any]:
    domain = extract_domain(fqdn)
    try:
        parent_ns = [str(r.target).rstrip(".") for r in dns.resolver.resolve(domain, "NS")]
    except Exception as exc:
        return ok_check("Parent vs Child NS", "NS lookup failed", {"error": str(exc)},
                        "Could not retrieve NS records for the domain.",
                        "Check delegation at the parent zone.")

    direct_results = []
    mismatches = []
    for ns in parent_ns:
        ip = first_ip_for_name(ns)
        if not ip:
            mismatches.append({"nameserver": ns, "error": "Could not resolve NS IP"})
            continue
        rcode, answers, error = resolve_with_server(domain, "NS", ip)
        record = {"nameserver": ns, "ip": ip, "rcode": rcode,
                  "answers": [a.rstrip(".") for a in answers], "error": error}
        direct_results.append(record)
        if error or rcode != "NOERROR":
            mismatches.append(record)

    if mismatches:
        return ok_check("Parent vs Child NS", "Inconsistent delegation detected",
                        {"parent_ns": parent_ns, "direct_results": direct_results, "mismatches": mismatches},
                        "Not all nameservers respond consistently.",
                        "Ensure delegation matches the live nameservers and remove stale entries.")
    return ok_check("Parent vs Child NS", "Delegation is consistent",
                    {"parent_ns": parent_ns, "direct_results": direct_results})


# ---------------------------------------------------------------------------
# Cloudflare detection
# ---------------------------------------------------------------------------

def check_cloudflare(host: str) -> Dict[str, Any]:
    """Comprehensive Cloudflare detection: IP ranges, NS names, HTTP headers."""
    ips: List[str] = []
    for t in ("A", "AAAA"):
        r = resolve_records(host, t)
        ips.extend(r.get("records", []))

    cf_ips = [ip for ip in ips if is_cloudflare_ip(ip)]
    ip_proxied = bool(cf_ips)

    # Check NS
    domain = extract_domain(host)
    ns_result = resolve_records(domain, "NS")
    ns_names = [r.rstrip(".") for r in ns_result.get("records", [])]
    cf_ns = [n for n in ns_names if is_cloudflare_ns(n)]
    uses_cf_ns = bool(cf_ns)

    details = {
        "ips": ips,
        "cloudflare_ips": cf_ips,
        "ip_proxied": ip_proxied,
        "nameservers": ns_names,
        "cloudflare_nameservers": cf_ns,
        "uses_cloudflare_ns": uses_cf_ns,
    }

    if ip_proxied and uses_cf_ns:
        summary = "Cloudflare proxied (orange-cloud) with CF nameservers"
    elif ip_proxied:
        summary = "IPs are in Cloudflare range but NS are not Cloudflare"
    elif uses_cf_ns:
        summary = "Cloudflare nameservers but DNS-only (grey-cloud)"
    else:
        summary = "Not using Cloudflare"

    return ok_check("Cloudflare", summary, details)


# ---------------------------------------------------------------------------
# Resolver comparison
# ---------------------------------------------------------------------------

def check_resolver_comparison(host: str) -> Dict[str, Any]:
    """Compare A record results across public resolvers + authoritative NS."""
    results: List[Dict[str, Any]] = []

    # Public resolvers
    for name, ip in PUBLIC_RESOLVERS.items():
        r = resolve_records(host, "A", server=ip)
        results.append({
            "resolver": name, "ip": ip, "type": "public",
            "rcode": r["rcode"], "records": r.get("records", []),
            "ttl": r.get("ttl"), "response_time_ms": r.get("response_time_ms"),
        })

    # Authoritative NS
    domain = extract_domain(host)
    try:
        ns_recs = dns.resolver.resolve(domain, "NS")
        for ns_rr in list(ns_recs)[:2]:  # first 2 authoritative
            ns_name = str(ns_rr.target).rstrip(".")
            ns_ip = first_ip_for_name(ns_name)
            if ns_ip:
                r = resolve_records(host, "A", server=ns_ip)
                results.append({
                    "resolver": f"Auth: {ns_name}", "ip": ns_ip, "type": "authoritative",
                    "rcode": r["rcode"], "records": r.get("records", []),
                    "ttl": r.get("ttl"), "response_time_ms": r.get("response_time_ms"),
                })
    except Exception:
        pass

    # Determine consistency
    answer_sets = set()
    for r in results:
        recs = tuple(sorted(r.get("records", [])))
        answer_sets.add(recs)

    rcodes = {r["rcode"] for r in results}
    consistent = len(answer_sets) <= 1 and len(rcodes) <= 1

    if consistent:
        return ok_check("Resolver Comparison", "All resolvers agree", {"resolvers": results})
    return ok_check("Resolver Comparison", "Resolvers disagree", {"resolvers": results},
                    "Resolver disagreement may indicate propagation delay, DNSSEC issues, or stale delegation.",
                    "Verify zone activation, nameserver delegation, and DNSSEC DS values.")


# ---------------------------------------------------------------------------
# Mail security
# ---------------------------------------------------------------------------

def check_mx(domain: str) -> Dict[str, Any]:
    r = resolve_records(domain, "MX")
    if not r["records"]:
        return ok_check("MX Records", "No MX records found", r,
                        "The domain has no MX records.", "Publish MX records if this domain should receive email.")
    # Parse and sort
    mx_list = []
    for rec in r["records"]:
        parts = rec.split(None, 1)
        if len(parts) == 2:
            mx_list.append({"priority": int(parts[0]), "exchange": parts[1].rstrip(".")})
    mx_list.sort(key=lambda x: x["priority"])
    return ok_check("MX Records", f"{len(mx_list)} MX record(s)", {"mx": mx_list, "ttl": r.get("ttl")})


def check_spf(domain: str) -> Dict[str, Any]:
    txt = get_txt_records(domain)
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    if not spf:
        return ok_check("SPF", "No SPF record found", {"txt": txt},
                        "The domain has no SPF policy.",
                        "Create a single SPF TXT record beginning with v=spf1.")
    if len(spf) > 1:
        return ok_check("SPF", "Multiple SPF records — permerror", {"spf": spf},
                        "Multiple SPF records cause SPF permerror.",
                        "Merge into one record.")
    record = spf[0]
    mechanisms = record.split()
    terminal = any(record.strip().endswith(x) for x in ["-all", "~all", "?all", "+all"])
    # Count DNS lookups (include, a, mx, ptr, exists, redirect)
    lookup_keywords = {"include:", "a:", "a", "mx:", "mx", "ptr:", "ptr", "exists:", "redirect="}
    lookup_count = sum(1 for m in mechanisms if any(m.lower().startswith(k) for k in lookup_keywords))

    details = {"spf": record, "mechanisms": mechanisms, "terminal": terminal,
               "dns_lookup_count": lookup_count, "over_10_lookups": lookup_count > 10}

    issues = []
    if not terminal:
        issues.append("no terminal all mechanism")
    if lookup_count > 10:
        issues.append(f"{lookup_count} DNS lookups (max 10)")

    if issues:
        return ok_check("SPF", f"SPF found — issues: {'; '.join(issues)}", details,
                        "; ".join(issues), "Review and optimise the SPF policy.")
    return ok_check("SPF", "SPF record valid", details)


def check_dkim(domain: str, selector: str) -> Dict[str, Any]:
    if not selector:
        return ok_check("DKIM", "No selector supplied", {},
                        "DKIM cannot be validated without a selector.",
                        "Enter the active DKIM selector before running the check.")
    fqdn = f"{selector}._domainkey.{domain}"
    txt = get_txt_records(fqdn)
    dkim = [t for t in txt if "v=DKIM1" in t.upper() or "p=" in t]
    details = {"selector": selector, "fqdn": fqdn, "records": txt}
    if dkim:
        # Check for empty public key (revoked)
        for rec in dkim:
            if "p=" in rec:
                p_val = rec.split("p=")[1].split(";")[0].strip()
                if not p_val:
                    return ok_check("DKIM", "DKIM key is revoked (empty p= tag)", details,
                                    "The DKIM key has been revoked.", "Publish a new DKIM key.")
    return ok_check("DKIM", "DKIM record found" if dkim else "No DKIM record found", details,
                    "" if dkim else "DKIM record not found for this selector.",
                    "" if dkim else "Publish the DKIM TXT record for the correct selector.")


def check_dmarc(domain: str) -> Dict[str, Any]:
    txt = get_txt_records(f"_dmarc.{domain}")
    dmarc = [t for t in txt if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        return ok_check("DMARC", "No DMARC record found", {"txt": txt},
                        "The domain has no DMARC policy.",
                        "Create a _dmarc TXT record starting with v=DMARC1.")
    record = dmarc[0]
    tags: Dict[str, str] = {}
    for part in record.split(";"):
        p = part.strip()
        if "=" in p:
            k, v = p.split("=", 1)
            tags[k.strip().lower()] = v.strip()

    policy = tags.get("p", "")
    sp = tags.get("sp", "")
    rua = tags.get("rua", "")
    ruf = tags.get("ruf", "")
    pct = tags.get("pct", "100")

    details = {"record": record, "policy": policy, "subdomain_policy": sp,
               "rua": rua, "ruf": ruf, "pct": pct, "tags": tags}

    issues = []
    if policy == "none":
        issues.append("policy is 'none' (monitoring only)")
    if not rua:
        issues.append("no rua (aggregate report) address")

    summary = f"DMARC p={policy or 'unknown'}"
    if sp:
        summary += f" sp={sp}"
    if issues:
        summary += f" — {'; '.join(issues)}"

    return ok_check("DMARC", summary, details,
                    "; ".join(issues) if issues else "",
                    "Consider strengthening to p=quarantine or p=reject once monitoring confirms legitimate sources." if policy == "none" else "")


# ---------------------------------------------------------------------------
# Website / TLS
# ---------------------------------------------------------------------------

def check_website(url_or_host: str) -> Dict[str, Any]:
    url = url_or_host if url_or_host.startswith(("http://", "https://")) else f"https://{url_or_host}"
    details: Dict[str, Any] = {"url_tested": url}
    try:
        start = time.perf_counter()
        response = requests.get(url, timeout=10, allow_redirects=True)
        elapsed = round((time.perf_counter() - start) * 1000, 1)
        details.update({
            "final_url": response.url,
            "status_code": response.status_code,
            "server": response.headers.get("Server"),
            "response_time_ms": elapsed,
            "redirect_chain": [r.url for r in response.history] if response.history else [],
        })

        parsed = urllib.parse.urlparse(response.url)
        hostname = parsed.hostname
        cert_summary: Dict[str, Any] = {}
        if hostname:
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        not_after = cert.get("notAfter", "")
                        # Parse expiry
                        expiry_str = ""
                        days_remaining = None
                        if not_after:
                            try:
                                expiry = time.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                expiry_ts = time.mktime(expiry)
                                days_remaining = int((expiry_ts - time.time()) / 86400)
                                expiry_str = time.strftime("%Y-%m-%d", expiry)
                            except Exception:
                                expiry_str = not_after

                        # Extract readable subject/issuer
                        subject_cn = ""
                        issuer_org = ""
                        for field in cert.get("subject", ()):
                            for k, v in field:
                                if k == "commonName":
                                    subject_cn = v
                        for field in cert.get("issuer", ()):
                            for k, v in field:
                                if k == "organizationName":
                                    issuer_org = v

                        san_list = []
                        for san_type, san_val in cert.get("subjectAltName", ()):
                            if san_type == "DNS":
                                san_list.append(san_val)

                        cert_summary = {
                            "subject_cn": subject_cn,
                            "issuer": issuer_org,
                            "expires": expiry_str,
                            "days_remaining": days_remaining,
                            "san": san_list[:10],  # first 10 SANs
                        }
            except Exception as exc:
                cert_summary = {"error": str(exc)}
        details["tls_certificate"] = cert_summary

        return ok_check("Website Check", f"HTTP {response.status_code} — {elapsed}ms", details,
                        "" if response.ok else "Non-success status code.",
                        "" if response.ok else "Review origin, proxy settings, SSL/TLS mode, and firewall rules.")
    except Exception as exc:
        details["error"] = str(exc)
        return ok_check("Website Check", "Website check failed", details,
                        "The site was unreachable or failed TLS/HTTP negotiation.",
                        "Check DNS, proxy mode, SSL/TLS config, and origin server health.")


# ---------------------------------------------------------------------------
# Website / SSL diagnostic (standalone tool checks)
# ---------------------------------------------------------------------------

def check_tls_certificate(host: str) -> Dict[str, Any]:
    """Full TLS certificate analysis including chain, protocol, cipher."""
    details: Dict[str, Any] = {"host": host}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                details["tls_version"] = ssock.version()
                details["cipher"] = ssock.cipher()

                # Subject
                subject_cn = ""
                subject_org = ""
                for field in cert.get("subject", ()):
                    for k, v in field:
                        if k == "commonName":
                            subject_cn = v
                        elif k == "organizationName":
                            subject_org = v

                # Issuer
                issuer_cn = ""
                issuer_org = ""
                for field in cert.get("issuer", ()):
                    for k, v in field:
                        if k == "commonName":
                            issuer_cn = v
                        elif k == "organizationName":
                            issuer_org = v

                # SANs
                san_list = []
                for san_type, san_val in cert.get("subjectAltName", ()):
                    if san_type == "DNS":
                        san_list.append(san_val)

                # Dates
                not_before = cert.get("notBefore", "")
                not_after = cert.get("notAfter", "")
                issued_str = ""
                expiry_str = ""
                days_remaining = None
                try:
                    if not_before:
                        issued = time.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                        issued_str = time.strftime("%Y-%m-%d", issued)
                    if not_after:
                        expiry = time.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        expiry_ts = time.mktime(expiry)
                        days_remaining = int((expiry_ts - time.time()) / 86400)
                        expiry_str = time.strftime("%Y-%m-%d", expiry)
                except Exception:
                    pass

                # Serial number
                serial = cert.get("serialNumber", "")

                details.update({
                    "subject_cn": subject_cn,
                    "subject_org": subject_org,
                    "issuer_cn": issuer_cn,
                    "issuer_org": issuer_org,
                    "serial": serial,
                    "issued": issued_str,
                    "expires": expiry_str,
                    "days_remaining": days_remaining,
                    "san": san_list,
                    "san_count": len(san_list),
                })

                # Determine certificate type
                cert_type = "DV"
                if subject_org:
                    cert_type = "OV/EV"
                if issuer_org and "let's encrypt" in issuer_org.lower():
                    cert_type = "DV (Let's Encrypt)"
                elif issuer_org and "cloudflare" in issuer_org.lower():
                    cert_type = "DV (Cloudflare)"
                details["cert_type"] = cert_type

                # Check hostname match
                hostname_match = subject_cn == host or host in san_list or \
                    any(san.startswith("*.") and host.endswith(san[1:]) for san in san_list)
                details["hostname_match"] = hostname_match

                # Summary
                cause = ""
                fix = ""
                if days_remaining is not None and days_remaining < 0:
                    summary = f"EXPIRED {abs(days_remaining)} days ago"
                    cause = "Certificate has expired."
                    fix = "Renew the certificate immediately."
                elif days_remaining is not None and days_remaining < 14:
                    summary = f"Expires in {days_remaining} days — {issuer_org or issuer_cn}"
                    cause = f"Certificate expires in {days_remaining} days."
                    fix = "Renew the certificate urgently."
                elif days_remaining is not None and days_remaining < 30:
                    summary = f"Expires in {days_remaining} days — {issuer_org or issuer_cn}"
                    cause = f"Certificate expires soon ({days_remaining} days)."
                    fix = "Schedule certificate renewal."
                elif not hostname_match:
                    summary = f"Hostname mismatch — cert CN: {subject_cn}"
                    cause = f"Certificate CN ({subject_cn}) does not match the requested host ({host})."
                    fix = "Reissue the certificate with the correct hostname or add it as a SAN."
                else:
                    summary = f"Valid — {cert_type} — expires {expiry_str} ({days_remaining}d) — {issuer_org or issuer_cn}"

                return ok_check("TLS Certificate", summary, details, cause, fix)
    except ssl.SSLCertVerificationError as exc:
        details["error"] = str(exc)
        return ok_check("TLS Certificate", "Certificate verification failed", details,
                        str(exc), "Check the certificate chain, expiry, and hostname match.")
    except ssl.SSLError as exc:
        details["error"] = str(exc)
        return ok_check("TLS Certificate", "SSL/TLS error", details,
                        str(exc), "Check TLS configuration and supported protocols on the server.")
    except socket.timeout:
        return ok_check("TLS Certificate", "Connection timed out on port 443", details,
                        "Could not establish a TLS connection.", "Check firewall rules and that port 443 is open.")
    except ConnectionRefusedError:
        return ok_check("TLS Certificate", "Connection refused on port 443", details,
                        "Port 443 is not accepting connections.", "Ensure HTTPS is enabled on the server.")
    except Exception as exc:
        details["error"] = str(exc)
        return ok_check("TLS Certificate", "TLS check failed", details,
                        str(exc), "Investigate the TLS/SSL configuration.")


def check_security_headers(url_or_host: str) -> Dict[str, Any]:
    """Check HTTP security headers."""
    url = url_or_host if url_or_host.startswith(("http://", "https://")) else f"https://{url_or_host}"
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        checks = {
            "Strict-Transport-Security": {
                "present": "strict-transport-security" in headers,
                "value": headers.get("strict-transport-security", ""),
                "description": "HSTS — forces HTTPS connections",
                "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            },
            "Content-Security-Policy": {
                "present": "content-security-policy" in headers,
                "value": headers.get("content-security-policy", "")[:200],  # truncate long CSP
                "description": "CSP — controls resource loading",
                "recommendation": "Define a Content-Security-Policy appropriate for the site",
            },
            "X-Frame-Options": {
                "present": "x-frame-options" in headers,
                "value": headers.get("x-frame-options", ""),
                "description": "Clickjacking protection",
                "recommendation": "Add: X-Frame-Options: SAMEORIGIN",
            },
            "X-Content-Type-Options": {
                "present": "x-content-type-options" in headers,
                "value": headers.get("x-content-type-options", ""),
                "description": "Prevents MIME-type sniffing",
                "recommendation": "Add: X-Content-Type-Options: nosniff",
            },
            "Referrer-Policy": {
                "present": "referrer-policy" in headers,
                "value": headers.get("referrer-policy", ""),
                "description": "Controls referrer information",
                "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
            },
            "Permissions-Policy": {
                "present": "permissions-policy" in headers,
                "value": headers.get("permissions-policy", "")[:200],
                "description": "Controls browser feature access",
                "recommendation": "Add a Permissions-Policy header to restrict browser features",
            },
            "X-XSS-Protection": {
                "present": "x-xss-protection" in headers,
                "value": headers.get("x-xss-protection", ""),
                "description": "Legacy XSS filter (CSP is preferred)",
                "recommendation": "CSP is the modern replacement; this header is optional",
            },
        }

        present_count = sum(1 for c in checks.values() if c["present"])
        total = len(checks)
        missing = [name for name, c in checks.items() if not c["present"]]

        # Also capture server header and technology hints
        server = headers.get("server", "")
        powered_by = headers.get("x-powered-by", "")

        details = {
            "url_tested": resp.url,
            "headers": checks,
            "present_count": present_count,
            "total": total,
            "missing": missing,
            "server": server,
            "x_powered_by": powered_by,
        }

        cause = ""
        fix = ""
        if present_count < 3:
            cause = f"Only {present_count}/{total} security headers present."
            fix = "Add missing security headers to the web server or Cloudflare configuration."

        return ok_check("Security Headers", f"{present_count}/{total} headers present", details, cause, fix)
    except Exception as exc:
        return ok_check("Security Headers", "Could not check headers", {"error": str(exc)},
                        "The site was unreachable.", "Ensure the site is accessible.")


def check_http_response(url_or_host: str) -> Dict[str, Any]:
    """Detailed HTTP response analysis — status, redirects, timing, server info."""
    url = url_or_host if url_or_host.startswith(("http://", "https://")) else f"https://{url_or_host}"
    details: Dict[str, Any] = {"url_tested": url}

    try:
        # Test HTTPS
        start = time.perf_counter()
        resp = requests.get(url, timeout=10, allow_redirects=True)
        elapsed = round((time.perf_counter() - start) * 1000, 1)

        redirect_chain = []
        for r in resp.history:
            redirect_chain.append({
                "url": r.url,
                "status": r.status_code,
                "location": r.headers.get("Location", ""),
            })

        details.update({
            "final_url": resp.url,
            "status_code": resp.status_code,
            "reason": resp.reason,
            "response_time_ms": elapsed,
            "redirect_chain": redirect_chain,
            "redirect_count": len(redirect_chain),
            "server": resp.headers.get("Server", ""),
            "content_type": resp.headers.get("Content-Type", ""),
            "content_length": resp.headers.get("Content-Length", ""),
            "x_powered_by": resp.headers.get("X-Powered-By", ""),
        })

        # Check if Cloudflare
        cf_ray = resp.headers.get("CF-RAY", "")
        cf_cache = resp.headers.get("CF-Cache-Status", "")
        details["cloudflare"] = {
            "is_cloudflare": bool(cf_ray),
            "cf_ray": cf_ray,
            "cf_cache_status": cf_cache,
        }

        # Test HTTP → HTTPS redirect
        if url.startswith("https://"):
            http_url = url.replace("https://", "http://", 1)
            try:
                http_resp = requests.get(http_url, timeout=5, allow_redirects=False)
                http_redirects_to_https = (
                    http_resp.status_code in (301, 302, 307, 308)
                    and http_resp.headers.get("Location", "").startswith("https://")
                )
                details["http_to_https_redirect"] = {
                    "tested": http_url,
                    "status": http_resp.status_code,
                    "redirects_to_https": http_redirects_to_https,
                    "location": http_resp.headers.get("Location", ""),
                }
            except Exception:
                details["http_to_https_redirect"] = {"tested": http_url, "error": "Could not connect on HTTP"}

        summary = f"HTTP {resp.status_code} — {elapsed}ms"
        if redirect_chain:
            summary += f" ({len(redirect_chain)} redirect(s))"
        if cf_ray:
            summary += " — via Cloudflare"

        return ok_check("HTTP Response", summary, details,
                        "" if resp.ok else f"Non-success status: {resp.status_code}",
                        "" if resp.ok else "Review server configuration, origin, and proxy settings.")
    except Exception as exc:
        details["error"] = str(exc)
        return ok_check("HTTP Response", "Connection failed", details,
                        str(exc), "Check DNS, firewall, and server availability.")


def check_http2_support(host: str) -> Dict[str, Any]:
    """Check HTTP/2 (and ALPN) support."""
    details: Dict[str, Any] = {"host": host}
    try:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                protocol = ssock.selected_alpn_protocol()
                details["alpn_negotiated"] = protocol
                details["supports_h2"] = protocol == "h2"

                if protocol == "h2":
                    return ok_check("HTTP/2 Support", "HTTP/2 supported (h2 via ALPN)", details)
                else:
                    return ok_check("HTTP/2 Support", f"HTTP/1.1 only (ALPN: {protocol or 'none'})", details,
                                    "Server does not support HTTP/2.",
                                    "Enable HTTP/2 on the web server or Cloudflare proxy.")
    except Exception as exc:
        details["error"] = str(exc)
        return ok_check("HTTP/2 Support", "Could not test HTTP/2", details)


def check_caa_records(domain: str) -> Dict[str, Any]:
    """Check CAA (Certificate Authority Authorization) records."""
    r = resolve_records(domain, "CAA")
    if not r.get("records"):
        # Try parent domain
        parent = extract_domain(domain)
        if parent != domain:
            r = resolve_records(parent, "CAA")
            if r.get("records"):
                r["note"] = f"CAA records found on parent domain {parent}"

    if not r.get("records"):
        return ok_check("CAA Records", "CAA not configured — optional", {"domain": domain})

    # Parse CAA records
    parsed = []
    for rec in r["records"]:
        parts = rec.split(None, 2)
        if len(parts) >= 3:
            flags = parts[0]
            tag = parts[1]
            value = parts[2].strip('"')
            parsed.append({"flags": flags, "tag": tag, "value": value})

    issue_cas = [p["value"] for p in parsed if p["tag"] == "issue"]
    wildcard_cas = [p["value"] for p in parsed if p["tag"] == "issuewild"]
    iodef = [p["value"] for p in parsed if p["tag"] == "iodef"]

    details = {
        "records": parsed,
        "issue_cas": issue_cas,
        "wildcard_cas": wildcard_cas,
        "iodef": iodef,
        "note": r.get("note", ""),
    }

    summary = f"{len(issue_cas)} CA(s) authorised"
    if wildcard_cas:
        summary += f", {len(wildcard_cas)} wildcard CA(s)"
    if iodef:
        summary += ", violation reporting configured"

    return ok_check("CAA Records", summary, details)


def check_cf_ssl_mode(host: str) -> Dict[str, Any]:
    """Detect Cloudflare SSL/TLS mode by comparing direct origin vs proxied response."""
    details: Dict[str, Any] = {"host": host}

    # First check if the site is behind Cloudflare
    ips = resolve_records(host, "A").get("records", [])
    cf_proxied = any(is_cloudflare_ip(ip) for ip in ips)
    details["cloudflare_proxied"] = cf_proxied

    if not cf_proxied:
        return ok_check("Cloudflare SSL Mode", "Not behind Cloudflare proxy", details)

    # Test HTTPS
    try:
        resp = requests.get(f"https://{host}", timeout=10, allow_redirects=True)
        details["https_status"] = resp.status_code
        details["https_works"] = resp.ok
        cf_ray = resp.headers.get("CF-RAY", "")
        details["cf_ray"] = cf_ray
    except Exception as exc:
        details["https_error"] = str(exc)
        details["https_works"] = False

    # Test HTTP to see if it redirects to HTTPS
    try:
        http_resp = requests.get(f"http://{host}", timeout=5, allow_redirects=False)
        details["http_status"] = http_resp.status_code
        details["http_redirects_to_https"] = (
            http_resp.status_code in (301, 302, 307, 308)
            and http_resp.headers.get("Location", "").startswith("https://")
        )
    except Exception:
        details["http_status"] = None

    # Infer mode
    if details.get("https_works"):
        if details.get("http_redirects_to_https"):
            mode = "Full or Full (Strict) — HTTPS enforced"
        else:
            mode = "Flexible or Full — HTTPS works but HTTP not redirected"
    else:
        mode = "Off or misconfigured — HTTPS not working"

    details["inferred_mode"] = mode

    cause = ""
    fix = ""
    if not details.get("https_works"):
        cause = "HTTPS is not working through Cloudflare."
        fix = "Check Cloudflare SSL/TLS mode and ensure the origin server has a valid certificate."
    elif not details.get("http_redirects_to_https"):
        cause = "HTTP is not redirecting to HTTPS."
        fix = "Enable 'Always Use HTTPS' in Cloudflare or add a redirect rule."

    return ok_check("Cloudflare SSL Mode", mode, details, cause, fix)


# ---------------------------------------------------------------------------
# Email header analysis
# ---------------------------------------------------------------------------

# Known mail relay/filtering services — SPF results through these are expected
KNOWN_MAIL_SERVICES = [
    # Service name, domain patterns to match in headers/DKIM
    ("CyMail", ["cymail.io", "smtp.cymail.io"]),
    ("Microsoft 365", ["protection.outlook.com", "outlook.com", "microsoft.com"]),
    ("Google Workspace", ["google.com", "googlemail.com"]),
    ("Mimecast", ["mimecast.com"]),
    ("Proofpoint", ["proofpoint.com", "pphosted.com"]),
    ("Barracuda", ["barracudanetworks.com", "bsn.barracuda.com"]),
    ("Sophos", ["sophos.com"]),
    ("SpamExperts", ["spamexperts.com", "antispamcloud.com"]),
    ("Mailgun", ["mailgun.org", "mailgun.com"]),
    ("SendGrid", ["sendgrid.net"]),
    ("Amazon SES", ["amazonses.com"]),
    ("Postmark", ["postmarkapp.com"]),
]


def _detect_mail_services(hops: list, dkim_details: dict, all_headers: str) -> List[Dict[str, str]]:
    """Detect known mail relay/filtering services from headers."""
    detected: List[Dict[str, str]] = []
    seen: set = set()
    search_text = all_headers.lower()

    for service_name, patterns in KNOWN_MAIL_SERVICES:
        if service_name in seen:
            continue
        for pattern in patterns:
            if pattern.lower() in search_text:
                detected.append({"service": service_name, "matched": pattern})
                seen.add(service_name)
                break

    return detected


def _parse_received_header(header: str) -> Dict[str, Any]:
    """Parse a single Received: header into structured fields."""
    result: Dict[str, Any] = {"raw": header.strip()}

    # Extract 'from' host
    from_match = re.search(r'from\s+(\S+)', header, re.IGNORECASE)
    if from_match:
        result["from_host"] = from_match.group(1).strip("()")

    # Extract 'by' host
    by_match = re.search(r'by\s+(\S+)', header, re.IGNORECASE)
    if by_match:
        result["by_host"] = by_match.group(1).strip("()")

    # Extract 'with' protocol
    with_match = re.search(r'with\s+(\S+)', header, re.IGNORECASE)
    if with_match:
        result["protocol"] = with_match.group(1).rstrip(";")

    # Extract IP addresses
    ip_matches = re.findall(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', header)
    if ip_matches:
        result["ips"] = ip_matches

    # Extract timestamp — usually after the semicolon
    semi_pos = header.rfind(";")
    if semi_pos >= 0:
        date_str = header[semi_pos + 1:].strip()
        parsed = email.utils.parsedate_to_datetime(date_str) if date_str else None
        if parsed:
            result["timestamp"] = parsed.isoformat()
            result["timestamp_utc"] = parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            result["_dt"] = parsed
    return result


def analyse_email_headers(raw_headers: str) -> Dict[str, Any]:
    """Parse raw email headers and extract routing, auth, and timing information."""

    parser = HeaderParser()
    msg = parser.parsestr(raw_headers)

    # ---- Basic envelope ----
    envelope = {
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "cc": msg.get("Cc", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "return_path": msg.get("Return-Path", ""),
        "reply_to": msg.get("Reply-To", ""),
    }

    # Parse the Date header
    if envelope["date"]:
        try:
            dt = email.utils.parsedate_to_datetime(envelope["date"])
            envelope["date_parsed"] = dt.strftime("%Y-%m-%d %H:%M:%S %Z")
        except Exception:
            pass

    # ---- Received hops (in reverse order — most recent first) ----
    received_headers = msg.get_all("Received", [])
    hops: List[Dict[str, Any]] = []
    for rh in received_headers:
        parsed = _parse_received_header(rh)
        hops.append(parsed)

    # Calculate delays between hops
    timed_hops = [h for h in hops if "_dt" in h]
    total_delay_seconds = 0
    if len(timed_hops) >= 2:
        for i in range(len(timed_hops) - 1):
            newer = timed_hops[i]["_dt"]
            older = timed_hops[i + 1]["_dt"]
            delay = (newer - older).total_seconds()
            timed_hops[i]["delay_seconds"] = max(0, round(delay, 1))
            total_delay_seconds += max(0, delay)

    # Clean internal _dt fields
    for h in hops:
        h.pop("_dt", None)

    # ---- Authentication results ----
    auth_results_raw = msg.get_all("Authentication-Results", [])
    auth_results: List[Dict[str, Any]] = []
    for ar in auth_results_raw:
        entry: Dict[str, Any] = {"raw": ar.strip()}
        # Parse SPF
        spf_match = re.search(r'spf\s*=\s*(\w+)', ar, re.IGNORECASE)
        if spf_match:
            entry["spf"] = spf_match.group(1).lower()
        # Parse DKIM
        dkim_match = re.search(r'dkim\s*=\s*(\w+)', ar, re.IGNORECASE)
        if dkim_match:
            entry["dkim"] = dkim_match.group(1).lower()
        # Parse DMARC
        dmarc_match = re.search(r'dmarc\s*=\s*(\w+)', ar, re.IGNORECASE)
        if dmarc_match:
            entry["dmarc"] = dmarc_match.group(1).lower()
        # Parse compauth/composite
        compauth_match = re.search(r'compauth\s*=\s*(\w+)', ar, re.IGNORECASE)
        if compauth_match:
            entry["compauth"] = compauth_match.group(1).lower()
        auth_results.append(entry)

    # Summarise auth
    auth_summary: Dict[str, str] = {}
    for ar in auth_results:
        for key in ("spf", "dkim", "dmarc", "compauth"):
            if key in ar and key not in auth_summary:
                auth_summary[key] = ar[key]

    # ---- SPF specific headers ----
    received_spf = msg.get("Received-SPF", "")
    spf_result = ""
    if received_spf:
        spf_match = re.match(r'(\w+)', received_spf.strip())
        if spf_match:
            spf_result = spf_match.group(1).lower()

    # ---- DKIM-Signature ----
    dkim_sig = msg.get("DKIM-Signature", "")
    dkim_details: Dict[str, str] = {}
    if dkim_sig:
        for part in dkim_sig.split(";"):
            p = part.strip()
            if "=" in p:
                k, v = p.split("=", 1)
                dkim_details[k.strip()] = v.strip()

    # ---- Spam / SCL headers ----
    spam_headers: Dict[str, str] = {}
    spam_keys = [
        "X-Spam-Status", "X-Spam-Score", "X-Spam-Flag",
        "X-MS-Exchange-Organization-SCL", "X-Microsoft-Antispam",
        "X-Forefront-Antispam-Report", "X-Google-DKIM-Signature",
        "X-Gm-Message-State", "X-MS-Exchange-Organization-AuthSource",
        "X-MS-Exchange-Organization-AuthAs",
        "X-OriginatorOrg", "X-MS-Exchange-CrossTenant-AuthSource",
        "X-Mailer", "X-MimeOLE", "User-Agent",
    ]
    for key in spam_keys:
        val = msg.get(key, "")
        if val:
            spam_headers[key] = val.strip()

    # ---- Detect known mail services ----
    detected_services = _detect_mail_services(hops, dkim_details, raw_headers)
    service_names = [s["service"] for s in detected_services]
    has_known_relay = len(detected_services) > 0

    # ---- Determine issues ----
    issues: List[str] = []
    warnings: List[str] = []
    info_notes: List[str] = []

    if detected_services:
        info_notes.append("Known service(s): " + ", ".join(service_names))

    # SPF — downgrade severity if a known relay is involved
    spf_val = auth_summary.get("spf", "")
    if spf_val in ("fail", "softfail", "permerror", "temperror"):
        if has_known_relay and spf_val in ("fail", "softfail"):
            info_notes.append(f"SPF {spf_val} — expected when relayed via {', '.join(service_names)}")
        else:
            issues.append(f"SPF {spf_val}")
    elif spf_val == "none":
        warnings.append("No SPF result")

    # DKIM — if the signing domain is a known relay, that's normal
    dkim_val = auth_summary.get("dkim", "")
    dkim_domain = dkim_details.get("d", "").strip()
    dkim_is_relay = any(
        pattern.lower() in dkim_domain.lower()
        for _, patterns in KNOWN_MAIL_SERVICES
        for pattern in patterns
    ) if dkim_domain else False

    if dkim_val in ("fail", "permerror", "temperror"):
        issues.append(f"DKIM {dkim_val}")
    elif dkim_val == "none":
        warnings.append("No DKIM result")
    elif dkim_val == "pass" and dkim_is_relay and dkim_domain:
        info_notes.append(f"DKIM signed by relay ({dkim_domain}) — normal for this service")

    # DMARC
    if auth_summary.get("dmarc") in ("fail",):
        if has_known_relay:
            warnings.append(f"DMARC {auth_summary['dmarc']} — may be expected via relay")
        else:
            issues.append(f"DMARC {auth_summary['dmarc']}")
    elif auth_summary.get("dmarc") == "none":
        warnings.append("No DMARC result")

    if total_delay_seconds > 300:
        warnings.append(f"Total delivery took {int(total_delay_seconds)}s ({int(total_delay_seconds/60)}min)")

    # Find the slowest hop
    slowest_hop = None
    slowest_delay = 0
    for h in hops:
        d = h.get("delay_seconds", 0)
        if d > slowest_delay:
            slowest_delay = d
            slowest_hop = h.get("by_host", "unknown")

    if slowest_delay > 30:
        warnings.append(f"Slowest hop: {int(slowest_delay)}s at {slowest_hop}")

    status = "ok"
    if issues:
        status = "fail"
    elif warnings:
        status = "warn"

    summary_parts = []
    if auth_summary:
        auth_str = ", ".join(f"{k.upper()}={v}" for k, v in auth_summary.items())
        summary_parts.append(auth_str)
    summary_parts.append(f"{len(hops)} hop(s)")
    if total_delay_seconds > 0:
        summary_parts.append(f"{int(total_delay_seconds)}s total transit")
    if detected_services:
        summary_parts.append("via " + ", ".join(service_names))

    return {
        "status": status,
        "summary": " | ".join(summary_parts),
        "issues": issues,
        "warnings": warnings,
        "info_notes": info_notes,
        "detected_services": detected_services,
        "envelope": envelope,
        "hops": hops,
        "hop_count": len(hops),
        "total_delay_seconds": round(total_delay_seconds, 1),
        "slowest_hop": {"host": slowest_hop, "delay_seconds": slowest_delay} if slowest_hop else None,
        "auth_summary": auth_summary,
        "auth_results": auth_results,
        "received_spf": received_spf,
        "spf_result": spf_result,
        "dkim_signature": dkim_details,
        "spam_headers": spam_headers,
    }


# ---------------------------------------------------------------------------
# Domain WHOIS (lightweight — expiry only)
# ---------------------------------------------------------------------------

def check_whois(domain: str) -> Dict[str, Any]:
    """Attempt to get domain expiry via WHOIS. Best-effort."""
    try:
        import whois as python_whois
        w = python_whois.whois(domain)
        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        registrar = w.registrar or "Unknown"
        details = {"domain": domain, "registrar": registrar}
        if expiry:
            from datetime import datetime, timezone
            if isinstance(expiry, datetime):
                now = datetime.now(timezone.utc) if expiry.tzinfo else datetime.now()
                days_remaining = (expiry - now).days
                details["expiry"] = expiry.strftime("%Y-%m-%d")
                details["days_remaining"] = days_remaining
                if days_remaining < 0:
                    return ok_check("Domain Registration", f"EXPIRED ({abs(days_remaining)} days ago)", details,
                                    "The domain has expired.", "Renew the domain immediately.")
                elif days_remaining < 30:
                    return ok_check("Domain Registration", f"Expires in {days_remaining} days!", details,
                                    f"Domain expires in {days_remaining} days.", "Renew the domain urgently.")
                elif days_remaining < 90:
                    return ok_check("Domain Registration", f"Expires {details['expiry']} ({days_remaining} days)", details,
                                    f"Domain expires in {days_remaining} days.", "Schedule domain renewal.")
                return ok_check("Domain Registration",
                                f"Expires {details['expiry']} ({days_remaining} days) — {registrar}", details)
        details["note"] = "Expiry date not available from WHOIS"
        return ok_check("Domain Registration", f"Registered via {registrar}", details)
    except ImportError:
        return ok_check("Domain Registration", "WHOIS module not installed", {},
                        "python-whois is not installed.", "Run: pip install python-whois")
    except Exception as exc:
        return ok_check("Domain Registration", "WHOIS lookup failed", {"error": str(exc)})


# ---------------------------------------------------------------------------
# Email diagnostics
# ---------------------------------------------------------------------------

DNSBL_SERVERS = [
    ("Spamhaus ZEN", "zen.spamhaus.org"),
    ("Barracuda", "b.barracudacentral.org"),
    ("SpamCop", "bl.spamcop.net"),
    ("SORBS", "dnsbl.sorbs.net"),
    ("UCEProtect L1", "dnsbl-1.uceprotect.net"),
    ("Invaluement", "dnsbl.invaluement.com"),
]


def check_smtp_connectivity(domain: str) -> Dict[str, Any]:
    """Test SMTP connectivity to each MX host — banner, STARTTLS, EHLO."""
    mx_result = resolve_records(domain, "MX")
    if not mx_result.get("records"):
        return ok_check("SMTP Connectivity", "No MX records — cannot test SMTP", {"domain": domain},
                        "No MX records found for the domain.", "Publish MX records first.")

    mx_hosts = []
    for rec in mx_result["records"]:
        parts = rec.split(None, 1)
        if len(parts) == 2:
            mx_hosts.append({"priority": int(parts[0]), "exchange": parts[1].rstrip(".")})
    mx_hosts.sort(key=lambda x: x["priority"])

    results = []
    all_ok = True
    for mx in mx_hosts:
        host = mx["exchange"]
        entry: Dict[str, Any] = {"host": host, "priority": mx["priority"]}
        try:
            start = time.perf_counter()
            with smtplib.SMTP(host, 25, timeout=8) as smtp:
                elapsed = round((time.perf_counter() - start) * 1000, 1)
                entry["connect_time_ms"] = elapsed
                entry["banner"] = smtp.ehlo_resp.decode(errors="replace") if smtp.ehlo_resp else ""

                # Test EHLO
                code, msg = smtp.ehlo("clearsignal.test")
                entry["ehlo_code"] = code
                extensions = [line.decode(errors="replace") if isinstance(line, bytes) else str(line)
                              for line in (smtp.ehlo_resp or b"").split(b"\n")]
                entry["extensions"] = extensions

                # Test STARTTLS
                if smtp.has_extn("starttls"):
                    try:
                        smtp.starttls()
                        entry["starttls"] = True
                        entry["tls_version"] = smtp.sock.version() if hasattr(smtp.sock, "version") else "unknown"
                    except Exception as tls_exc:
                        entry["starttls"] = False
                        entry["starttls_error"] = str(tls_exc)
                        all_ok = False
                else:
                    entry["starttls"] = False
                    entry["starttls_note"] = "STARTTLS not advertised"
                    all_ok = False

                entry["status"] = "ok"
        except smtplib.SMTPConnectError as exc:
            entry["status"] = "fail"
            entry["error"] = f"Connection refused: {exc}"
            all_ok = False
        except socket.timeout:
            entry["status"] = "fail"
            entry["error"] = "Connection timed out"
            all_ok = False
        except Exception as exc:
            entry["status"] = "fail"
            entry["error"] = str(exc)
            all_ok = False

        results.append(entry)

    ok_count = sum(1 for r in results if r["status"] == "ok")
    tls_count = sum(1 for r in results if r.get("starttls") is True)
    summary = f"{ok_count}/{len(results)} MX reachable, {tls_count}/{len(results)} support STARTTLS"

    cause = ""
    fix = ""
    if not all_ok:
        failed = [r["host"] for r in results if r["status"] != "ok"]
        no_tls = [r["host"] for r in results if r["status"] == "ok" and not r.get("starttls")]
        if failed:
            cause = f"Unreachable: {', '.join(failed)}"
            fix = "Check firewall rules and MX server availability."
        elif no_tls:
            cause = f"No STARTTLS: {', '.join(no_tls)}"
            fix = "Enable STARTTLS on the mail server to support encrypted transport."

    return ok_check("SMTP Connectivity", summary, {"mx_hosts": results}, cause, fix)


def check_blacklists(domain: str) -> Dict[str, Any]:
    """Check mail server IPs against major DNS blacklists."""
    # Get MX IPs
    mx_result = resolve_records(domain, "MX")
    mx_ips: Dict[str, str] = {}  # ip -> mx_host
    for rec in mx_result.get("records", []):
        parts = rec.split(None, 1)
        if len(parts) == 2:
            host = parts[1].rstrip(".")
            ip = first_ip_for_name(host)
            if ip:
                mx_ips[ip] = host

    # Also check the domain's own A record
    a_result = resolve_records(domain, "A")
    for ip in a_result.get("records", []):
        if ip not in mx_ips:
            mx_ips[ip] = domain

    if not mx_ips:
        return ok_check("Blacklist Check", "No IPs to check", {"domain": domain},
                        "Could not determine any IPs to check against blacklists.",
                        "Ensure MX or A records exist for the domain.")

    results: List[Dict[str, Any]] = []
    listed_count = 0

    for ip, source_host in mx_ips.items():
        try:
            reversed_ip = ".".join(reversed(ip.split(".")))
        except Exception:
            continue

        for bl_name, bl_server in DNSBL_SERVERS:
            query_name = f"{reversed_ip}.{bl_server}"
            try:
                dns.resolver.resolve(query_name, "A")
                # If it resolves, the IP is listed
                results.append({
                    "ip": ip, "source": source_host, "blacklist": bl_name,
                    "server": bl_server, "listed": True,
                })
                listed_count += 1
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                results.append({
                    "ip": ip, "source": source_host, "blacklist": bl_name,
                    "server": bl_server, "listed": False,
                })
            except dns.exception.Timeout:
                results.append({
                    "ip": ip, "source": source_host, "blacklist": bl_name,
                    "server": bl_server, "listed": False, "note": "timeout",
                })
            except Exception:
                results.append({
                    "ip": ip, "source": source_host, "blacklist": bl_name,
                    "server": bl_server, "listed": False, "note": "lookup error",
                })

    total_checks = len(results)
    if listed_count > 0:
        listed_items = [f"{r['ip']} on {r['blacklist']}" for r in results if r["listed"]]
        return ok_check("Blacklist Check", f"LISTED on {listed_count} blacklist(s)",
                        {"checks": results, "listed_count": listed_count, "total_checks": total_checks,
                         "ips_checked": list(mx_ips.keys())},
                        f"Listed: {'; '.join(listed_items[:5])}",
                        "Request delisting from each blacklist. Check for compromised accounts or open relays.")
    return ok_check("Blacklist Check", f"Clean — {len(mx_ips)} IP(s) checked against {len(DNSBL_SERVERS)} lists",
                    {"checks": results, "listed_count": 0, "total_checks": total_checks,
                     "ips_checked": list(mx_ips.keys())})


def check_mta_sts(domain: str) -> Dict[str, Any]:
    """Check MTA-STS TXT record and policy file."""
    # Check _mta-sts TXT
    txt_records = get_txt_records(f"_mta-sts.{domain}")
    sts_txt = [t for t in txt_records if t.lower().startswith("v=sts")]

    # Check policy file
    policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    policy_content = None
    policy_error = None
    try:
        resp = requests.get(policy_url, timeout=5, allow_redirects=True)
        if resp.ok:
            policy_content = resp.text.strip()
        else:
            policy_error = f"HTTP {resp.status_code}"
    except Exception as exc:
        policy_error = str(exc)

    # Check TLSRPT
    tlsrpt_records = get_txt_records(f"_smtp._tls.{domain}")

    details = {
        "txt_record": sts_txt[0] if sts_txt else None,
        "policy_url": policy_url,
        "policy_content": policy_content,
        "policy_error": policy_error,
        "tlsrpt_records": tlsrpt_records,
    }

    if sts_txt and policy_content:
        # Parse policy mode
        mode = ""
        for line in policy_content.splitlines():
            if line.strip().startswith("mode:"):
                mode = line.split(":", 1)[1].strip()
        details["policy_mode"] = mode
        summary = f"MTA-STS active (mode={mode})"
        if tlsrpt_records:
            summary += " + TLSRPT configured"
        return ok_check("MTA-STS", summary, details)
    elif sts_txt and not policy_content:
        return ok_check("MTA-STS", "TXT record exists but policy file missing/unreachable", details,
                        "MTA-STS TXT record found but the policy file is not accessible.",
                        f"Publish the policy at {policy_url}")
    else:
        return ok_check("MTA-STS", "MTA-STS not configured — optional", details)


def check_autodiscover(domain: str) -> Dict[str, Any]:
    """Check Microsoft Autodiscover and Mozilla Autoconfig endpoints."""
    results: Dict[str, Any] = {}

    # Microsoft Autodiscover
    autodiscover_urls = [
        f"https://autodiscover.{domain}/autodiscover/autodiscover.xml",
        f"https://{domain}/autodiscover/autodiscover.xml",
    ]
    # Autodiscover SRV record
    srv_result = resolve_records(f"_autodiscover._tcp.{domain}", "SRV")
    results["autodiscover_srv"] = srv_result.get("records", [])

    # Autodiscover CNAME
    cname_result = resolve_records(f"autodiscover.{domain}", "CNAME")
    results["autodiscover_cname"] = cname_result.get("records", [])

    for url in autodiscover_urls:
        try:
            resp = requests.get(url, timeout=5, allow_redirects=True, verify=True)
            results[url] = {"status": resp.status_code, "reachable": True}
        except requests.exceptions.SSLError:
            results[url] = {"status": None, "reachable": False, "error": "SSL error"}
        except Exception as exc:
            results[url] = {"status": None, "reachable": False, "error": str(exc)}

    # Mozilla Autoconfig
    autoconfig_url = f"https://autoconfig.{domain}/mail/config-v1.1.xml"
    try:
        resp = requests.get(autoconfig_url, timeout=5, allow_redirects=True)
        results["autoconfig"] = {"url": autoconfig_url, "status": resp.status_code, "reachable": True}
    except Exception as exc:
        results["autoconfig"] = {"url": autoconfig_url, "reachable": False, "error": str(exc)}

    # Determine summary
    has_srv = bool(srv_result.get("records"))
    has_cname = bool(cname_result.get("records"))
    has_autodiscover = any(results.get(u, {}).get("reachable") for u in autodiscover_urls)
    has_autoconfig = results.get("autoconfig", {}).get("reachable", False)

    parts = []
    if has_srv:
        parts.append("Autodiscover SRV")
    if has_cname:
        parts.append("Autodiscover CNAME")
    if has_autodiscover:
        parts.append("Autodiscover endpoint")
    if has_autoconfig:
        parts.append("Mozilla Autoconfig")

    if parts:
        return ok_check("Autodiscover", "Found: " + ", ".join(parts), results)
    return ok_check("Autodiscover", "Autodiscover not configured — optional", results)


def check_dane_tlsa(domain: str) -> Dict[str, Any]:
    """Check DANE TLSA records for MX hosts."""
    mx_result = resolve_records(domain, "MX")
    if not mx_result.get("records"):
        return ok_check("DANE/TLSA", "No MX records to check", {"domain": domain})

    results = []
    for rec in mx_result.get("records", []):
        parts = rec.split(None, 1)
        if len(parts) != 2:
            continue
        mx_host = parts[1].rstrip(".")
        tlsa_name = f"_25._tcp.{mx_host}"
        tlsa_result = resolve_records(tlsa_name, "TLSA")
        results.append({
            "mx_host": mx_host,
            "tlsa_name": tlsa_name,
            "records": tlsa_result.get("records", []),
            "rcode": tlsa_result.get("rcode", ""),
        })

    has_tlsa = any(r["records"] for r in results)
    if has_tlsa:
        return ok_check("DANE/TLSA", "TLSA records found", {"mx_tlsa": results})
    return ok_check("DANE/TLSA", "DANE not configured — optional", {"mx_tlsa": results})


def check_bimi(domain: str) -> Dict[str, Any]:
    """Check BIMI (Brand Indicators for Message Identification) record."""
    txt = get_txt_records(f"default._bimi.{domain}")
    bimi = [t for t in txt if "v=bimi1" in t.lower()]
    if bimi:
        # Parse out l= (logo) and a= (authority) tags
        record = bimi[0]
        logo = ""
        authority = ""
        for part in record.split(";"):
            p = part.strip()
            if p.startswith("l="):
                logo = p[2:]
            elif p.startswith("a="):
                authority = p[2:]
        return ok_check("BIMI", "BIMI record found",
                        {"record": record, "logo_url": logo, "authority_url": authority})
    return ok_check("BIMI", "BIMI not configured — optional", {"txt": txt})


# ---------------------------------------------------------------------------
# Combined DNS diagnostic (for ticket tab — unchanged behaviour)
# ---------------------------------------------------------------------------

def check_dns_diagnostic(host: str) -> Dict[str, Any]:
    parts = [
        check_delegation_trace(host),
        check_dnssec_validation(host),
        check_parent_child_ns(host),
        check_cloudflare(host),
        check_resolver_comparison(host),
    ]
    failures = [p for p in parts
                if any(term in p["summary"].lower()
                       for term in ["stopped", "failed", "mismatch", "possible", "disagree"])
                and p["name"] != "Cloudflare"]
    summary = "Advanced DNS diagnostics completed"
    if failures:
        summary += " with warnings"
    return ok_check("DNS Diagnostic", summary, {"checks": parts},
                    next((p["likely_root_cause"] for p in parts if p.get("likely_root_cause")), ""),
                    next((p["recommended_fix"] for p in parts if p.get("recommended_fix")), ""))


# ---------------------------------------------------------------------------
# Port / Service Scanner
# ---------------------------------------------------------------------------

PORT_PRESETS = {
    "quick": {
        "label": "Quick Scan",
        "ports": [
            (22, "tcp", "SSH"),
            (25, "tcp", "SMTP"),
            (53, "tcp", "DNS"),
            (80, "tcp", "HTTP"),
            (443, "tcp", "HTTPS"),
            (3389, "tcp", "RDP"),
        ],
    },
    "mail": {
        "label": "Mail Server",
        "ports": [
            (25, "tcp", "SMTP"),
            (110, "tcp", "POP3"),
            (143, "tcp", "IMAP"),
            (465, "tcp", "SMTPS"),
            (587, "tcp", "SMTP Submission"),
            (993, "tcp", "IMAPS"),
            (995, "tcp", "POP3S"),
        ],
    },
    "web": {
        "label": "Web Server",
        "ports": [
            (80, "tcp", "HTTP"),
            (443, "tcp", "HTTPS"),
            (8080, "tcp", "HTTP Alt"),
            (8443, "tcp", "HTTPS Alt"),
        ],
    },
    "remote": {
        "label": "Remote Access",
        "ports": [
            (22, "tcp", "SSH"),
            (3389, "tcp", "RDP"),
            (5900, "tcp", "VNC"),
            (4081, "tcp", "Splashtop/RMM"),
        ],
    },
    "voip": {
        "label": "VoIP",
        "ports": [
            (5060, "tcp", "SIP"),
            (5061, "tcp", "SIP TLS"),
            (5060, "udp", "SIP UDP"),
        ],
    },
    "management": {
        "label": "Management / Monitoring",
        "ports": [
            (161, "udp", "SNMP"),
            (161, "tcp", "SNMP TCP"),
            (162, "udp", "SNMP Trap"),
            (4081, "tcp", "Splashtop/RMM"),
            (22, "tcp", "SSH"),
            (443, "tcp", "HTTPS Mgmt"),
        ],
    },
    "full": {
        "label": "Comprehensive",
        "ports": [
            (22, "tcp", "SSH"),
            (25, "tcp", "SMTP"),
            (53, "tcp", "DNS"),
            (80, "tcp", "HTTP"),
            (110, "tcp", "POP3"),
            (143, "tcp", "IMAP"),
            (161, "tcp", "SNMP TCP"),
            (161, "udp", "SNMP"),
            (443, "tcp", "HTTPS"),
            (465, "tcp", "SMTPS"),
            (587, "tcp", "SMTP Submission"),
            (993, "tcp", "IMAPS"),
            (995, "tcp", "POP3S"),
            (3389, "tcp", "RDP"),
            (4081, "tcp", "Splashtop/RMM"),
            (5060, "tcp", "SIP"),
            (5061, "tcp", "SIP TLS"),
        ],
    },
}


def _scan_tcp_port(host: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
    """Scan a single TCP port — connect, grab banner if possible."""
    result: Dict[str, Any] = {"port": port, "protocol": "tcp", "state": "closed"}
    try:
        start = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            elapsed = round((time.perf_counter() - start) * 1000, 1)
            result["state"] = "open"
            result["response_time_ms"] = elapsed

            # Try banner grab
            try:
                sock.settimeout(1.0)
                if port in (80, 8080, 8443):
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n")
                banner = sock.recv(512)
                if banner:
                    result["banner"] = banner.decode(errors="replace").strip()[:200]
            except Exception:
                pass

            # TLS info — only probe if the port is already open, reuse connection
            if port in (443, 465, 993, 995, 8443, 5061):
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((host, port), timeout=1.5) as sock2:
                        with ctx.wrap_socket(sock2, server_hostname=host) as ssock:
                            result["tls_version"] = ssock.version()
                except Exception:
                    pass

    except socket.timeout:
        result["state"] = "filtered"
    except ConnectionRefusedError:
        result["state"] = "closed"
    except OSError as exc:
        err_str = str(exc).lower()
        if "refused" in err_str:
            result["state"] = "closed"
        elif "timed out" in err_str or "timeout" in err_str:
            result["state"] = "filtered"
        else:
            result["state"] = "error"
            result["error"] = str(exc)

    return result


def _scan_udp_port(host: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
    """Scan a single UDP port — best-effort, UDP scanning is unreliable."""
    result: Dict[str, Any] = {"port": port, "protocol": "udp", "state": "open|filtered"}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # Send appropriate probe
        if port == 161:
            # SNMP v2c GET request for sysDescr
            snmp_get = (
                b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01"
                b"\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
            )
            sock.sendto(snmp_get, (host, port))
        elif port == 53:
            # DNS query for version.bind
            dns_query = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03"
            sock.sendto(dns_query, (host, port))
        elif port in (5060,):
            # SIP OPTIONS probe
            sock.sendto(b"OPTIONS sip:probe@probe SIP/2.0\r\n\r\n", (host, port))
        else:
            sock.sendto(b"\x00", (host, port))

        try:
            data, _ = sock.recvfrom(1024)
            result["state"] = "open"
            if data:
                if port == 161 and len(data) > 10:
                    result["banner"] = "SNMP responding"
                elif port == 53:
                    result["banner"] = "DNS responding"
                else:
                    result["banner"] = f"{len(data)} bytes response"
        except socket.timeout:
            result["state"] = "open|filtered"
            result["note"] = "No response (may be filtered or service not responding)"

        sock.close()
    except Exception as exc:
        result["state"] = "error"
        result["error"] = str(exc)

    return result


def check_port_scan(host: str, preset: str = "full", custom_ports: Optional[List[Dict]] = None) -> Dict[str, Any]:
    """Scan ports based on preset or custom list."""
    ports_to_scan: List[Tuple[int, str, str]] = []

    if custom_ports:
        for cp in custom_ports:
            ports_to_scan.append((int(cp.get("port", 0)), cp.get("protocol", "tcp"), cp.get("service", "")))
    elif preset in PORT_PRESETS:
        ports_to_scan = PORT_PRESETS[preset]["ports"]
    else:
        ports_to_scan = PORT_PRESETS["full"]["ports"]

    results: List[Dict[str, Any]] = []
    open_count = 0
    closed_count = 0
    filtered_count = 0

    for port, proto, service_name in ports_to_scan:
        if proto == "udp":
            scan = _scan_udp_port(host, port)
        else:
            scan = _scan_tcp_port(host, port)

        scan["service"] = service_name
        results.append(scan)

        if scan["state"] == "open":
            open_count += 1
        elif scan["state"] == "closed":
            closed_count += 1
        else:
            filtered_count += 1

    preset_label = PORT_PRESETS.get(preset, {}).get("label", preset) if not custom_ports else "Custom"

    summary = f"{open_count} open, {closed_count} closed, {filtered_count} filtered — {preset_label} ({len(results)} ports)"

    return ok_check(
        "Port Scan",
        summary,
        {
            "host": host,
            "preset": preset,
            "preset_label": preset_label,
            "results": results,
            "open_count": open_count,
            "closed_count": closed_count,
            "filtered_count": filtered_count,
            "total_scanned": len(results),
        },
    )


# ---------------------------------------------------------------------------
# Main dispatcher
# ---------------------------------------------------------------------------

def run_checks(payload: Dict[str, Any]) -> Dict[str, Any]:
    target = payload.get("target", {})
    checks = payload.get("checks", [])
    selector = payload.get("dkim_selector", "")

    host = target.get("host") or target.get("domain") or target.get("input")
    ip = target.get("ip")
    url = target.get("url") or host
    domain = target.get("domain") or host

    output = []
    for check in checks:
        if check == "ping" and host:
            output.append(check_ping(host))
        elif check == "traceroute" and host:
            output.append(check_traceroute(host))
        elif check == "forward_lookup" and host:
            output.append(check_forward_lookup(host))
        elif check == "reverse_lookup":
            reverse_ip = ip
            if not reverse_ip and host:
                reverse_ip = first_ip_for_name(host)
            if reverse_ip:
                output.append(check_reverse_lookup(reverse_ip))
            else:
                output.append(ok_check("Reverse Lookup", "Could not determine IP",
                                       {"target": target.get("input", "")},
                                       "Target did not resolve to an IP.", "Ensure the hostname resolves first."))
        elif check == "dns_diagnostic" and host:
            output.append(check_dns_diagnostic(host))
        elif check == "website_check" and url:
            output.append(check_website(url))
        elif check == "mx_check" and domain:
            output.append(check_mx(domain))
        elif check == "spf_check" and domain:
            output.append(check_spf(domain))
        elif check == "dkim_check" and domain:
            output.append(check_dkim(domain, selector))
        elif check == "dmarc_check" and domain:
            output.append(check_dmarc(domain))
        # New standalone checks
        elif check == "full_record_scan" and host:
            output.append(check_full_record_scan(host))
        elif check == "soa" and host:
            output.append(check_soa(host))
        elif check == "ns_detail" and host:
            output.append(check_ns_detail(host))
        elif check == "delegation_trace" and host:
            output.append(check_delegation_trace(host))
        elif check == "dnssec" and host:
            output.append(check_dnssec_validation(host))
        elif check == "parent_child_ns" and host:
            output.append(check_parent_child_ns(host))
        elif check == "cloudflare" and host:
            output.append(check_cloudflare(host))
        elif check == "resolver_comparison" and host:
            output.append(check_resolver_comparison(host))
        elif check == "whois" and domain:
            output.append(check_whois(extract_domain(domain)))
        # Email diagnostic checks
        elif check == "smtp_connectivity" and domain:
            output.append(check_smtp_connectivity(domain))
        elif check == "blacklist_check" and domain:
            output.append(check_blacklists(domain))
        elif check == "mta_sts" and domain:
            output.append(check_mta_sts(domain))
        elif check == "autodiscover" and domain:
            output.append(check_autodiscover(domain))
        elif check == "dane_tlsa" and domain:
            output.append(check_dane_tlsa(domain))
        elif check == "bimi" and domain:
            output.append(check_bimi(domain))
        # Website/SSL diagnostic checks
        elif check == "tls_certificate" and host:
            output.append(check_tls_certificate(host))
        elif check == "security_headers" and (url or host):
            output.append(check_security_headers(url or host))
        elif check == "http_response" and (url or host):
            output.append(check_http_response(url or host))
        elif check == "http2_support" and host:
            output.append(check_http2_support(host))
        elif check == "caa_records" and domain:
            output.append(check_caa_records(domain))
        elif check == "cf_ssl_mode" and host:
            output.append(check_cf_ssl_mode(host))
        # Port scanner
        elif check == "port_scan" and host:
            scan_preset = payload.get("scan_preset", "full")
            custom_ports = payload.get("custom_ports")
            output.append(check_port_scan(host, preset=scan_preset, custom_ports=custom_ports))
        # Email header analysis (payload contains raw_headers instead of target)
        elif check == "email_header_analysis":
            raw_headers = payload.get("raw_headers", "")
            if raw_headers:
                analysis = analyse_email_headers(raw_headers)
                output.append({
                    "name": "Email Header Analysis",
                    "status": analysis["status"],
                    "summary": analysis["summary"],
                    "details": analysis,
                    "likely_root_cause": "; ".join(analysis.get("issues", [])),
                    "recommended_fix": "",
                })

    statuses = [c.get("status", "ok") for c in output]
    if "fail" in statuses:
        overall = "fail"
    elif "warn" in statuses:
        overall = "warn"
    else:
        overall = "ok"

    return {"ok": True, "status": overall, "target": target, "checks": output}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    payload = json.load(sys.stdin)
    result = run_checks(payload)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
