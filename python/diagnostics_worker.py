#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import platform

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
    "198.41.0.4",
    "199.9.14.201",
    "192.33.4.12",
    "199.7.91.13",
]

PUBLIC_RESOLVERS = {
    "Cloudflare": "1.1.1.1",
    "Google": "8.8.8.8",
    "Quad9": "9.9.9.9",
}

CLOUDFLARE_NETS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32",
    "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32",
]
CLOUDFLARE_RANGES = [ipaddress.ip_network(c) for c in CLOUDFLARE_NETS]


def _infer_status(summary: str, cause: str) -> str:
    """Derive a machine-readable status from the human summary."""
    lower = summary.lower()
    fail_terms = ("fail", "error", "stopped", "not found", "not installed", "no ", "could not", "missing")
    warn_terms = ("warning", "disagree", "possible", "mismatch", "multiple", "proxied", "inconsistent", "lame")
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
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "command": command,
        }
    except Exception as exc:
        return {
            "ok": False,
            "returncode": 1,
            "stdout": "",
            "stderr": str(exc),
            "command": command,
        }


def first_ip_for_name(name: str) -> Optional[str]:
    try:
        infos = socket.getaddrinfo(name, 53, proto=socket.IPPROTO_UDP)
        for info in infos:
            if info[4]:
                return info[4][0]
    except Exception:
        return None
    return None


def make_resolver(nameserver: Optional[str] = None, timeout: float = 3.0) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    if nameserver:
        resolver.nameservers = [nameserver]
    return resolver


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


def query_ns_from_server(zone: str, server: str, timeout: float = 3.0) -> Tuple[List[str], str]:
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


def resolve_with_server(qname: str, rdtype: str, server: str, timeout: float = 3.0) -> Tuple[str, List[str], str]:
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


def check_ping(target: str) -> Dict[str, Any]:
    count_flag = "-n" if IS_WINDOWS else "-c"
    result = safe_run(["ping", count_flag, "4", target], timeout=10)
    return ok_check(
        "Ping",
        "Reachable" if result["ok"] else "Ping failed",
        result,
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
        return ok_check(
            "Traceroute",
            "Traceroute utility not installed",
            {"ok": False, "stderr": f"{tool_name} is not available on this host."},
            f"The GLPI host is missing {tool_name}.",
            f"Install {tool_name} on the GLPI host.",
        )
    result = safe_run(cmd, timeout=30)
    return ok_check(
        "Traceroute",
        "Traceroute completed" if result["ok"] else "Traceroute failed or timed out",
        result,
        "" if result["ok"] else "Path visibility is limited, blocked, or the utility timed out.",
        "" if result["ok"] else "Check outbound network permissions and confirm the target is reachable from the GLPI host.",
    )


def check_forward_lookup(host: str) -> Dict[str, Any]:
    try:
        a_records = [r.to_text() for r in dns.resolver.resolve(host, "A")]
    except Exception:
        a_records = []
    try:
        aaaa_records = [r.to_text() for r in dns.resolver.resolve(host, "AAAA")]
    except Exception:
        aaaa_records = []
    details = {"A": a_records, "AAAA": aaaa_records}
    found = a_records + aaaa_records
    return ok_check(
        "Forward Lookup",
        ", ".join(found) if found else "No A or AAAA records found",
        details,
        "" if found else "The hostname does not currently publish A or AAAA records, or lookup failed.",
        "" if found else "Create or correct the hostname record in Cloudflare DNS or the authoritative DNS provider.",
    )


def check_reverse_lookup(ip: str) -> Dict[str, Any]:
    try:
        rev = dns.reversename.from_address(ip)
        ptrs = [r.to_text() for r in dns.resolver.resolve(rev, "PTR")]
        return ok_check("Reverse Lookup", ", ".join(ptrs), {"PTR": ptrs})
    except Exception as exc:
        return ok_check(
            "Reverse Lookup",
            "PTR lookup failed",
            {"error": str(exc)},
            "No reverse DNS is configured for this IP or the PTR lookup failed.",
            "Configure the PTR record with the IP owner or upstream provider.",
        )


def check_mx(domain: str) -> Dict[str, Any]:
    try:
        mx = [f"{r.preference} {str(r.exchange).rstrip('.')}" for r in dns.resolver.resolve(domain, "MX")]
        return ok_check("MX Check", f"{len(mx)} MX record(s) found", {"mx": mx})
    except Exception as exc:
        return ok_check(
            "MX Check",
            "MX lookup failed",
            {"error": str(exc)},
            "No MX records were returned for the domain or the lookup failed.",
            "Publish valid MX records in Cloudflare DNS or the authoritative DNS provider if the domain should receive email.",
        )


def check_spf(domain: str) -> Dict[str, Any]:
    txt = get_txt_records(domain)
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    if not spf:
        return ok_check(
            "SPF Check",
            "No SPF record found",
            {"txt": txt},
            "The domain has no SPF policy.",
            "Create a single SPF TXT record in Cloudflare DNS beginning with v=spf1.",
        )
    if len(spf) > 1:
        return ok_check(
            "SPF Check",
            "Multiple SPF records found",
            {"spf": spf},
            "Multiple SPF records cause SPF permerror.",
            "Merge the SPF mechanisms into one record in Cloudflare DNS.",
        )
    terminal = any(spf[0].strip().endswith(x) for x in ["-all", "~all", "?all", "+all"])
    return ok_check(
        "SPF Check",
        "Valid-looking SPF record found" + ("" if terminal else " (no terminal all mechanism detected)"),
        {"spf": spf[0], "all_mechanism_present": terminal},
        "" if terminal else "The SPF policy has no clear terminal all mechanism.",
        "" if terminal else "Review the SPF policy and consider ending it with -all or ~all in Cloudflare DNS.",
    )


def check_dkim(domain: str, selector: str) -> Dict[str, Any]:
    if not selector:
        return ok_check(
            "DKIM Check",
            "No selector supplied",
            {"selectors_tried": []},
            "DKIM cannot be validated without a selector.",
            "Enter the active DKIM selector from the mail platform before running the check.",
        )
    fqdn = f"{selector}._domainkey.{domain}"
    txt = get_txt_records(fqdn)
    dkim = [t for t in txt if "v=DKIM1" in t.upper() or "p=" in t]
    return ok_check(
        "DKIM Check",
        "DKIM record found" if dkim else "No DKIM record found",
        {"selector": selector, "fqdn": fqdn, "records": txt},
        "" if dkim else "The DKIM selector does not resolve or the record is missing.",
        "" if dkim else "Publish the DKIM TXT record for the correct selector in Cloudflare DNS.",
    )


def check_dmarc(domain: str) -> Dict[str, Any]:
    txt = get_txt_records(f"_dmarc.{domain}")
    dmarc = [t for t in txt if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        return ok_check(
            "DMARC Check",
            "No DMARC record found",
            {"txt": txt},
            "The domain has no DMARC policy.",
            "Create a _dmarc TXT record in Cloudflare DNS starting with v=DMARC1.",
        )
    record = dmarc[0]
    policy = ""
    rua = ""
    for part in record.split(";"):
        p = part.strip()
        if p.startswith("p="):
            policy = p[2:]
        if p.startswith("rua="):
            rua = p[4:]
    return ok_check(
        "DMARC Check",
        f"DMARC record found (policy={policy or 'unknown'})",
        {"record": record, "policy": policy, "rua": rua},
        "" if policy else "DMARC policy tag was not detected cleanly.",
        "" if policy else "Review the DMARC record syntax in Cloudflare DNS.",
    )


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
        })

        parsed = urllib.parse.urlparse(response.url)
        hostname = parsed.hostname
        cert_summary = {}
        if hostname:
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        cert_summary = {
                            "subject": cert.get("subject", []),
                            "issuer": cert.get("issuer", []),
                            "notAfter": cert.get("notAfter"),
                        }
            except Exception as exc:
                cert_summary = {"error": str(exc)}
        details["tls_certificate"] = cert_summary

        return ok_check(
            "Website Check",
            f"HTTP {response.status_code}",
            details,
            "" if response.ok else "The website returned a non-success status code.",
            "" if response.ok else "Review the origin, Cloudflare proxying, SSL/TLS mode, and any firewall rules.",
        )
    except Exception as exc:
        details["error"] = str(exc)
        return ok_check(
            "Website Check",
            "Website check failed",
            details,
            "The site was unreachable, timed out, or failed TLS/HTTP negotiation.",
            "Check DNS, Cloudflare proxy mode, SSL/TLS configuration, and the origin server health.",
        )


def check_delegation_trace(fqdn: str) -> Dict[str, Any]:
    hops: List[Dict[str, Any]] = []
    current_servers = ROOT_SERVERS[:]
    failure = None

    for zone in zone_chain_for_fqdn(fqdn):
        found_ns: List[str] = []
        last_error = ""
        for server in current_servers:
            ns, err = query_ns_from_server(zone, server)
            if ns:
                found_ns = ns
                hops.append({"zone": zone, "queried_server": server, "ns_records": ns})
                break
            last_error = err

        if not found_ns:
            failure = {"zone": zone, "error": last_error or "No NS returned"}
            hops.append({"zone": zone, "queried_servers": current_servers, "error": failure["error"]})
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
            "Delegation Trace",
            f"Delegation stopped at {failure['zone']}",
            {"hops": hops, "failure": failure},
            f"Authoritative delegation appears incomplete or broken at {failure['zone']}.",
            "If Cloudflare hosts the child zone, ensure the parent publishes the exact Cloudflare-assigned nameservers and that the child zone is active.",
        )
    return ok_check("Delegation Trace", "Full delegation path resolved successfully", {"hops": hops})


def check_dnssec_validation(fqdn: str, rdtype: str = "A") -> Dict[str, Any]:
    server = PUBLIC_RESOLVERS["Cloudflare"]
    try:
        q1 = dns.message.make_query(fqdn, rdtype, want_dnssec=True)
        r1 = dns.query.udp(q1, server, timeout=3)
        normal_rcode = dns.rcode.to_text(r1.rcode())
        normal_answers: List[str] = []
        for rrset in r1.answer:
            if rrset.rdtype == dns.rdatatype.from_text(rdtype):
                normal_answers.extend([r.to_text() for r in rrset])

        q2 = dns.message.make_query(fqdn, rdtype, want_dnssec=True)
        q2.flags |= dns.flags.CD
        r2 = dns.query.udp(q2, server, timeout=3)
        cd_rcode = dns.rcode.to_text(r2.rcode())
        cd_answers: List[str] = []
        for rrset in r2.answer:
            if rrset.rdtype == dns.rdatatype.from_text(rdtype):
                cd_answers.extend([r.to_text() for r in rrset])

        if normal_rcode == "SERVFAIL" and cd_answers:
            return ok_check(
                "DNSSEC Validation",
                "Possible DNSSEC mismatch detected",
                {
                    "standard_rcode": normal_rcode,
                    "cd_rcode": cd_rcode,
                    "standard_answers": normal_answers,
                    "cd_answers": cd_answers,
                },
                "Standard validation failed but checking-disabled returned data, which strongly suggests a DS/DNSKEY mismatch.",
                "If Cloudflare DNSSEC was disabled, remove the DS record at the registrar. If DNSSEC should remain enabled, regenerate and publish the correct DS record from Cloudflare.",
            )

        return ok_check(
            "DNSSEC Validation",
            f"Standard={normal_rcode}; CD={cd_rcode}",
            {
                "standard_rcode": normal_rcode,
                "cd_rcode": cd_rcode,
                "standard_answers": normal_answers,
                "cd_answers": cd_answers,
            },
        )
    except Exception as exc:
        return ok_check(
            "DNSSEC Validation",
            "DNSSEC validation test failed",
            {"error": str(exc)},
            "The DNSSEC check could not be completed cleanly.",
            "Retry the test and review the zone DNSSEC status in Cloudflare.",
        )


def check_parent_child_ns_mismatch(fqdn: str) -> Dict[str, Any]:
    try:
        parent_ns = [str(r.target).rstrip(".") for r in dns.resolver.resolve(fqdn, "NS")]
    except Exception as exc:
        return ok_check(
            "Parent vs Child NS",
            "Parent NS lookup failed",
            {"error": str(exc)},
            "The subdomain does not appear to publish NS records publicly.",
            "Create or correct the child delegation at the parent DNS provider, using the active Cloudflare child nameservers if applicable.",
        )

    direct_results = []
    mismatches = []
    for ns in parent_ns:
        ip = first_ip_for_name(ns)
        if not ip:
            mismatches.append({"nameserver": ns, "error": "Could not resolve nameserver IP"})
            continue
        rcode, answers, error = resolve_with_server(fqdn, "NS", ip)
        record = {"nameserver": ns, "ip": ip, "rcode": rcode, "answers": answers, "error": error}
        direct_results.append(record)
        if error or rcode not in ("NOERROR",) or (answers and sorted(a.rstrip('.') for a in answers) != sorted(parent_ns)):
            mismatches.append(record)

    if mismatches:
        return ok_check(
            "Parent vs Child NS",
            "Possible lame or inconsistent delegation detected",
            {"parent_ns": parent_ns, "direct_results": direct_results, "mismatches": mismatches},
            "Parent-published child nameservers do not all answer consistently for the child zone.",
            "Ensure the parent delegation matches the live Cloudflare child nameservers and remove stale NS entries.",
        )
    return ok_check("Parent vs Child NS", "Parent and child NS responses look consistent", {"parent_ns": parent_ns, "direct_results": direct_results})


def is_cloudflare_ip(ip_text: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_text)
        return any(ip_obj in net for net in CLOUDFLARE_RANGES)
    except Exception:
        return False


def check_cloudflare_proxy(host: str) -> Dict[str, Any]:
    ips: List[str] = []
    for t in ("A", "AAAA"):
        try:
            ips.extend([r.to_text() for r in dns.resolver.resolve(host, t)])
        except Exception:
            pass

    if not ips:
        return ok_check(
            "Cloudflare Proxy Check",
            "No A or AAAA records returned",
            {"ips": []},
            "The hostname did not return IP addresses for proxy detection.",
            "Check the record exists and the hostname resolves publicly.",
        )

    cf_ips = [ip for ip in ips if is_cloudflare_ip(ip)]
    if cf_ips:
        return ok_check(
            "Cloudflare Proxy Check",
            "Record appears proxied by Cloudflare",
            {"ips": ips, "cloudflare_ips": cf_ips},
            "The hostname resolves to Cloudflare IP space, which indicates orange-cloud proxying.",
            "For troubleshooting, temporarily switch the record to DNS only in Cloudflare and retest direct resolution.",
        )
    return ok_check("Cloudflare Proxy Check", "Record does not appear proxied by Cloudflare", {"ips": ips})


def check_global_resolver_comparison(host: str, rdtype: str = "A") -> Dict[str, Any]:
    results = []
    for name, ip in PUBLIC_RESOLVERS.items():
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [ip]
            resolver.timeout = 3
            resolver.lifetime = 3
            start = time.perf_counter()
            answers = [r.to_text() for r in resolver.resolve(host, rdtype)]
            elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
            results.append({
                "resolver": name,
                "ip": ip,
                "rcode": "NOERROR",
                "answers": answers,
                "response_time_ms": elapsed_ms,
            })
        except dns.resolver.NXDOMAIN:
            results.append({"resolver": name, "ip": ip, "rcode": "NXDOMAIN", "answers": []})
        except dns.resolver.NoAnswer:
            results.append({"resolver": name, "ip": ip, "rcode": "NOANSWER", "answers": []})
        except dns.resolver.NoNameservers as exc:
            results.append({"resolver": name, "ip": ip, "rcode": "SERVFAIL", "answers": [], "error": str(exc)})
        except dns.exception.Timeout:
            results.append({"resolver": name, "ip": ip, "rcode": "TIMEOUT", "answers": []})
        except Exception as exc:
            results.append({"resolver": name, "ip": ip, "rcode": "ERROR", "answers": [], "error": str(exc)})

    rcodes = {r["rcode"] for r in results}
    answer_sets = {tuple(r.get("answers", [])) for r in results}

    if len(rcodes) > 1 or len(answer_sets) > 1:
        return ok_check(
            "Global Resolver Comparison",
            "Resolvers disagree",
            {"resolvers": results},
            "Resolver disagreement commonly points to DNSSEC failure, stale delegation, propagation inconsistency, or negative caching differences.",
            "If Cloudflare is authoritative, verify zone activation, correct assigned nameservers, and DNSSEC DS values before changing records further.",
        )
    return ok_check("Global Resolver Comparison", "Resolvers are consistent", {"resolvers": results})


def check_dns_diagnostic(host: str) -> Dict[str, Any]:
    parts = [
        check_delegation_trace(host),
        check_dnssec_validation(host),
        check_parent_child_ns_mismatch(host),
        check_cloudflare_proxy(host),
        check_global_resolver_comparison(host),
    ]

    failures = [p for p in parts if any(term in p["summary"].lower() for term in ["stopped", "failed", "mismatch", "possible", "disagree", "proxied"]) and p["name"] != "Cloudflare Proxy Check"]
    summary = "Advanced DNS diagnostics completed"
    if failures:
        summary = "Advanced DNS diagnostics completed with warnings"

    return ok_check(
        "DNS Diagnostic",
        summary,
        {"checks": parts},
        next((p["likely_root_cause"] for p in parts if p.get("likely_root_cause")), ""),
        next((p["recommended_fix"] for p in parts if p.get("recommended_fix")), ""),
    )


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
                output.append(ok_check(
                    "Reverse Lookup",
                    "Could not determine IP for reverse lookup",
                    {"target": target.get("input", "")},
                    "The target did not resolve to an IP address for PTR lookup.",
                    "Ensure the hostname resolves before running a reverse lookup.",
                ))
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

    # Derive overall status from individual check statuses
    statuses = [c.get("status", "ok") for c in output]
    if "fail" in statuses:
        overall = "fail"
    elif "warn" in statuses:
        overall = "warn"
    else:
        overall = "ok"

    return {
        "ok": True,
        "status": overall,
        "target": target,
        "checks": output,
    }


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
