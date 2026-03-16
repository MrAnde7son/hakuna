"""
Enhanced internet-reachability detection using existing inventory data.

Three detection methods:
1. Inbound NetConn analysis — ESTABLISHED connections from public IPs on service ports
2. Listening port heuristic — public IP + listening on internet-facing ports
3. Plugin-based inference — public CA certs, CDN/WAF headers, cloud LB signatures
"""
import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

# Ports commonly exposed to the internet
_INTERNET_SERVICE_PORTS = {
    21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    1433, 3306, 3389, 5432, 8080, 8443, 8888,
}

# Well-known public Certificate Authorities
_PUBLIC_CAS = {
    "digicert", "let's encrypt", "comodo", "sectigo", "globalsign",
    "godaddy", "entrust", "amazon", "google trust services", "identrust",
    "thawte", "geotrust", "rapidssl", "symantec", "verisign", "zerosssl",
    "buypass", "isrg", "usertrust", "starfield", "comodoca",
    "r3", "e1", "r4",  # Let's Encrypt intermediates
}

# CDN / WAF signatures in plugin output
_CDN_WAF_PATTERNS = [
    (re.compile(r"cloudflare|cf-ray|cf-cache-status", re.I), "Cloudflare"),
    (re.compile(r"akamai|x-akamai|akamaized", re.I), "Akamai"),
    (re.compile(r"cloudfront|x-amz-cf", re.I), "AWS CloudFront"),
    (re.compile(r"fastly|x-fastly", re.I), "Fastly"),
    (re.compile(r"incapsula|imperva", re.I), "Imperva"),
]

# Cloud load balancer signatures
_CLOUD_LB_PATTERNS = [
    (re.compile(r"ELB|ALB|elastic.load.balancing", re.I), "AWS ELB/ALB"),
    (re.compile(r"azure.front.door|azure.application.gateway", re.I), "Azure LB"),
    (re.compile(r"google.frontend|gfe|google.cloud.load.balancer", re.I), "GCP LB"),
]

# Plugin families to scan for HTTP/CDN/LB signatures (performance filter)
_PLUGIN_FAMILIES_HTTP = {
    "web servers", "service detection", "general", "cgi abuses",
}

# Confidence ranking
_CONFIDENCE_RANK = {"confirmed": 4, "high": 3, "medium": 2, "low": 1}


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class ReachabilityEvidence:
    method: str
    detail: str
    confidence: str


@dataclass
class ReachabilityResult:
    is_internet_facing: bool = False
    confidence: Optional[str] = None        # confirmed / high / medium / low
    methods: List[str] = field(default_factory=list)
    evidence: List[ReachabilityEvidence] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_public_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return not any(addr in net for net in _RFC1918)
    except ValueError:
        return False


def _highest_confidence(items: List[ReachabilityEvidence]) -> Optional[str]:
    if not items:
        return None
    return max(items, key=lambda e: _CONFIDENCE_RANK.get(e.confidence, 0)).confidence


# ---------------------------------------------------------------------------
# Method 1: Inbound NetConn analysis
# ---------------------------------------------------------------------------

def _check_inbound_connections(netconns: list) -> List[ReachabilityEvidence]:
    """
    Look for ESTABLISHED connections from public IPs on service ports.
    This suggests the asset is receiving inbound traffic from the internet.
    """
    evidence = []
    public_inbound = []

    for nc in netconns:
        state = (nc.get("state") or "").upper()
        if state != "ESTABLISHED":
            continue
        remote_addr = nc.get("remote_addr") or ""
        local_port = nc.get("local_port")
        if not remote_addr or local_port is None:
            continue
        # Connection on a service port from a public IP
        if local_port in _INTERNET_SERVICE_PORTS and _is_public_ip(remote_addr):
            public_inbound.append((remote_addr, local_port))

    if public_inbound:
        # Deduplicate by unique remote IPs
        unique_ips = set(ip for ip, _ in public_inbound)
        ports_hit = set(p for _, p in public_inbound)
        evidence.append(ReachabilityEvidence(
            method="inbound_netconn",
            detail=f"{len(unique_ips)} public IP(s) connected on port(s) {sorted(ports_hit)}",
            confidence="high",
        ))

    return evidence


# ---------------------------------------------------------------------------
# Method 2: Listening port heuristic
# ---------------------------------------------------------------------------

def _check_listening_ports(asset_ip: str, environment_tag: str, netconns: list) -> List[ReachabilityEvidence]:
    """
    Public IP listening on internet-facing ports = strong signal.
    Private IP in DMZ listening on those ports = medium signal.
    """
    evidence = []
    listening_service_ports = set()

    for nc in netconns:
        state = (nc.get("state") or "").upper()
        if state not in ("LISTEN", "LISTENING"):
            continue
        local_port = nc.get("local_port")
        if local_port in _INTERNET_SERVICE_PORTS:
            listening_service_ports.add(local_port)

    if not listening_service_ports:
        return evidence

    is_public = _is_public_ip(asset_ip) if asset_ip else False
    env = (environment_tag or "").lower()

    if is_public:
        evidence.append(ReachabilityEvidence(
            method="public_listener",
            detail=f"Public IP listening on port(s) {sorted(listening_service_ports)}",
            confidence="high",
        ))
    elif env in ("dmz", "external"):
        evidence.append(ReachabilityEvidence(
            method="dmz_listener",
            detail=f"DMZ asset listening on port(s) {sorted(listening_service_ports)}",
            confidence="medium",
        ))

    return evidence


# ---------------------------------------------------------------------------
# Method 3a: Public CA detection
# ---------------------------------------------------------------------------

def _check_public_ca(certificates: list) -> List[ReachabilityEvidence]:
    """
    A non-self-signed cert from a well-known public CA suggests
    the service was intended to be publicly accessible.
    """
    evidence = []

    for cert in certificates:
        if cert.get("is_self_signed"):
            continue
        issuer_o = (cert.get("issuer_o") or "").lower()
        issuer_cn = (cert.get("issuer_cn") or "").lower()
        combined = f"{issuer_o} {issuer_cn}"
        if any(ca in combined for ca in _PUBLIC_CAS):
            subject = cert.get("subject_cn") or "unknown"
            issuer = cert.get("issuer_o") or cert.get("issuer_cn") or "unknown"
            evidence.append(ReachabilityEvidence(
                method="public_ca_cert",
                detail=f"Certificate for '{subject}' issued by public CA '{issuer}'",
                confidence="medium",
            ))
            break  # One match is enough

    return evidence


# ---------------------------------------------------------------------------
# Method 3b: CDN / WAF detection
# ---------------------------------------------------------------------------

def _check_cdn_waf(findings: list, easm_data: Optional[dict] = None) -> List[ReachabilityEvidence]:
    """
    CDN/WAF presence in HTTP headers (from plugin output) is a strong
    indicator the asset is internet-facing.
    """
    evidence = []
    detected = set()

    # Check EASM data first (most reliable)
    if easm_data:
        cdn = easm_data.get("cdn_provider")
        waf = easm_data.get("waf")
        if cdn:
            detected.add(cdn)
        if waf:
            detected.add(waf)

    # Scan plugin outputs for CDN/WAF signatures
    for f in findings:
        family = (f.get("plugin_family") or "").lower()
        if family and family not in _PLUGIN_FAMILIES_HTTP:
            continue
        output = f.get("plugin_output") or ""
        if not output:
            continue
        for pattern, name in _CDN_WAF_PATTERNS:
            if pattern.search(output):
                detected.add(name)

    if detected:
        evidence.append(ReachabilityEvidence(
            method="cdn_waf_detected",
            detail=f"CDN/WAF detected: {', '.join(sorted(detected))}",
            confidence="high",
        ))

    return evidence


# ---------------------------------------------------------------------------
# Method 3c: Cloud load balancer signatures
# ---------------------------------------------------------------------------

def _check_cloud_lb(findings: list) -> List[ReachabilityEvidence]:
    """
    Cloud load balancer signatures in plugin output suggest the asset
    sits behind a public-facing LB.
    """
    evidence = []
    detected = set()

    for f in findings:
        family = (f.get("plugin_family") or "").lower()
        if family and family not in _PLUGIN_FAMILIES_HTTP:
            continue
        output = f.get("plugin_output") or ""
        if not output:
            continue
        for pattern, name in _CLOUD_LB_PATTERNS:
            if pattern.search(output):
                detected.add(name)

    if detected:
        evidence.append(ReachabilityEvidence(
            method="cloud_lb_detected",
            detail=f"Cloud load balancer detected: {', '.join(sorted(detected))}",
            confidence="medium",
        ))

    return evidence


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_internet_reachability(
    asset_ip: str,
    environment_tag: str,
    netconns: list,
    certificates: list,
    findings: list,
    easm_data: Optional[dict] = None,
) -> ReachabilityResult:
    """
    Run all detection methods and return aggregated result.

    Parameters:
        asset_ip:         IP address of the asset
        environment_tag:  Current environment classification
        netconns:         List of dicts with keys: state, remote_addr, local_port
        certificates:     List of dicts with keys: is_self_signed, issuer_o, issuer_cn, subject_cn
        findings:         List of dicts with keys: plugin_family, plugin_output
        easm_data:        Optional EASM enrichment dict from the asset

    Returns:
        ReachabilityResult with aggregated detection outcome
    """
    all_evidence: List[ReachabilityEvidence] = []

    # Method 1: Inbound connections from public IPs
    all_evidence.extend(_check_inbound_connections(netconns))

    # Method 2: Listening ports on public/DMZ assets
    all_evidence.extend(_check_listening_ports(asset_ip, environment_tag, netconns))

    # Method 3a: Public CA certificates
    all_evidence.extend(_check_public_ca(certificates))

    # Method 3b: CDN/WAF detection
    all_evidence.extend(_check_cdn_waf(findings, easm_data))

    # Method 3c: Cloud load balancer signatures
    all_evidence.extend(_check_cloud_lb(findings))

    if not all_evidence:
        return ReachabilityResult()

    methods = list(dict.fromkeys(e.method for e in all_evidence))  # ordered unique
    confidence = _highest_confidence(all_evidence)

    return ReachabilityResult(
        is_internet_facing=True,
        confidence=confidence,
        methods=methods,
        evidence=all_evidence,
    )
