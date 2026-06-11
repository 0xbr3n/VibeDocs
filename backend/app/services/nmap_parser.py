"""
Nmap parser. Accepts:
  * Nmap XML       (`-oX`, or the per-file `<nmaprun ...>` shape)
  * Greppable      (`-oG`)
  * Verbose stdout (`-v`/`-vv` console capture or `-oN <file>` "normal" output)

Returns a flat ports table sorted by host then port — suitable for inserting
as a 'Discovered Services' table at the end of an Infra VAPT report.

The verbose-stdout parser handles the format consultants most often paste
into the tool (`nmap -v ... | tee scan.txt`). It walks the file line-by-line
looking for "Nmap scan report for <host>" headers and the per-port table
rows that follow ("PORT STATE SERVICE …") — both the `Discovered open port`
lines from the verbose progress AND the canonical port table at the end of
each host block. Cross-source dedupe so the same `host/port` pair isn't
double-counted between the discovery and summary sections.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, asdict
from pathlib import Path
import defusedxml.ElementTree as ET


@dataclass
class PortEntry:
    host: str
    hostname: str
    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str

    def to_dict(self) -> dict:
        return asdict(self)


def parse_nmap(path: str | Path) -> list[PortEntry]:
    """Sniff format from the first ~2 KB and dispatch.

    XML is unmistakable. Greppable always begins each data line with
    `Host: <ip>`. Verbose stdout has the recognisable banner `Starting
    Nmap` or per-host `Nmap scan report for <host>` headers. If we can't
    tell, fall through every parser and return whichever yields rows.
    """
    p = Path(path)
    raw = p.read_bytes()
    head = raw[:4096].decode("utf-8", errors="ignore")
    if head.lstrip().startswith("<?xml") or "<nmaprun" in head:
        return _parse_xml(p)
    if re.search(r"^Host:\s+\S+.*Ports:", head, re.MULTILINE):
        return _parse_greppable(p)
    if "Nmap scan report" in head or "Starting Nmap" in head:
        return _parse_verbose(p)
    # Last-ditch: try them in fastest-to-strictest order and keep the first
    # parser that finds any rows.
    for parser in (_parse_greppable, _parse_verbose, _parse_xml):
        try:
            rows = parser(p)
        except Exception:
            rows = []
        if rows:
            return rows
    return []


def _parse_xml(path: Path) -> list[PortEntry]:
    out: list[PortEntry] = []
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return out
    for host in tree.getroot().findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']") or host.find("address")
        ip = addr_el.get("addr", "") if addr_el is not None else ""
        hn_el = host.find("hostnames/hostname")
        hostname = hn_el.get("name", "") if hn_el is not None else ""
        for port in host.findall("ports/port"):
            state_el = port.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            if state and state != "open":
                continue
            service_el = port.find("service")
            service = service_el.get("name", "") if service_el is not None else ""
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
            try:
                portnum = int(port.get("portid", "0"))
            except ValueError:
                continue
            out.append(PortEntry(
                host=ip, hostname=hostname, port=portnum,
                protocol=port.get("protocol", ""),
                state=state, service=service,
                product=product, version=version,
            ))
    return sorted(out, key=lambda e: (e.host, e.port))


# Greppable example line:
# Host: 10.0.0.1 (server-1)\tPorts: 22/open/tcp//ssh//OpenSSH 8.4//, 80/open/tcp//http//nginx 1.18//\tIgnored State: closed (998)
_GREP_PORT = re.compile(r"(\d+)/(\w+)/(\w+)//([^/]*)//([^/]*)//")


def _parse_greppable(path: Path) -> list[PortEntry]:
    out: list[PortEntry] = []
    for line in path.read_text(errors="ignore").splitlines():
        if not line.startswith("Host:"):
            continue
        m = re.match(r"Host:\s*(\S+)\s*(?:\(([^)]*)\))?\s*Ports:\s*(.+?)(?:\t|$)", line)
        if not m:
            continue
        host, hostname, ports = m.group(1), m.group(2) or "", m.group(3)
        for entry in ports.split(","):
            entry = entry.strip()
            pm = _GREP_PORT.match(entry)
            if not pm:
                continue
            port, state, proto, service, prodver = pm.groups()
            product, _, version = prodver.partition(" ")
            out.append(PortEntry(
                host=host, hostname=hostname, port=int(port),
                protocol=proto, state=state, service=service,
                product=product, version=version,
            ))
    return sorted(out, key=lambda e: (e.host, e.port))


# ============================================================
# Verbose stdout (`-v` / `-oN`) parser
# ============================================================
# Captures two complementary signals from the same file:
#
#  1. Inline progress lines emitted during scanning, e.g.
#       Discovered open port 22/tcp on 172.23.11.133
#     These give us host + port + protocol but no service / version.
#
#  2. Per-host port tables at the end of each "Nmap scan report for ..."
#     block, e.g.
#       PORT      STATE SERVICE     REASON         VERSION
#       22/tcp    open  ssh         syn-ack ttl 57 OpenSSH 8.0 (protocol 2.0)
#     These have service + version but only appear after the scan
#     finishes for that host.
#
# We merge by (host, port, protocol) — table rows win when both sources
# have data for the same port. That way we never lose ports discovered
# mid-scan even if the final table is truncated.

_VERB_DISCOVERED = re.compile(
    r"Discovered\s+open\s+port\s+(\d+)/(\w+)\s+on\s+(\S+)",
    re.IGNORECASE,
)
_VERB_REPORT     = re.compile(
    r"^Nmap\s+scan\s+report\s+for\s+(.+?)\s*$",
    re.IGNORECASE,
)
# Captures a port-table data row. Header looks like:
#   PORT      STATE SERVICE     REASON         VERSION
# Data rows look like:
#   22/tcp    open  ssh         syn-ack ttl 57 OpenSSH 8.0 (protocol 2.0)
#   8093/tcp  open  ssl/unknown syn-ack ttl 57
# The VERSION column is optional and may be blank.
_VERB_PORT_ROW = re.compile(
    r"^\s*(?P<port>\d+)/(?P<proto>\w+)\s+(?P<state>open|filtered|closed)"
    r"\s+(?P<service>\S+)"
    r"(?:\s+(?P<rest>.+))?\s*$"
)
# "REASON" column in nmap verbose output is one or two tokens like
# "syn-ack" or "syn-ack ttl 57". We strip it from the version field.
_VERB_REASON = re.compile(
    r"^(?:syn-ack|reset|no-response|user-set|conn-refused|host-unreach|"
    r"net-unreach|admin-prohibited|port-unreach|proto-unreach)"
    r"(?:\s+ttl\s+\d+)?\s*"
)
# Hostnames inside the "report for" line can be either:
#   Nmap scan report for 10.0.0.1
#   Nmap scan report for box.example.com (10.0.0.1)
_REPORT_WITH_PARENS = re.compile(r"^(?P<name>.+?)\s+\((?P<ip>[\d.:a-fA-F]+)\)$")


def _split_report_host(blob: str) -> tuple[str, str]:
    """Returns (host_ip, hostname). When the report header only carries one
    of the two we leave the other blank."""
    blob = blob.strip()
    m = _REPORT_WITH_PARENS.match(blob)
    if m:
        return m.group("ip"), m.group("name")
    return blob, ""


def _strip_reason(s: str) -> str:
    m = _VERB_REASON.match(s)
    return s[m.end():] if m else s


def _parse_verbose(path: Path) -> list[PortEntry]:
    """Walk verbose stdout / -oN output and build PortEntry rows."""
    # (host_or_hostname, port, proto) -> PortEntry. Allows merge between the
    # "Discovered open port" line and the per-host port table.
    by_key: dict[tuple[str, int, str], PortEntry] = {}
    hostnames: dict[str, str] = {}   # host_ip -> friendly name (or vice-versa)
    current_host = ""
    current_hostname = ""

    # Pre-pass: collect every "Discovered open port" — these don't depend
    # on the current_host because they include the host inline.
    text = path.read_text(errors="ignore")
    for m in _VERB_DISCOVERED.finditer(text):
        port = int(m.group(1)); proto = m.group(2); host = m.group(3)
        k = (host, port, proto)
        if k not in by_key:
            by_key[k] = PortEntry(
                host=host, hostname="", port=port, protocol=proto,
                state="open", service="", product="", version="",
            )

    # Second pass: walk per-host blocks for service + version data.
    for raw in text.splitlines():
        rep = _VERB_REPORT.match(raw)
        if rep:
            ip, name = _split_report_host(rep.group(1))
            current_host = ip
            current_hostname = name
            if name and ip:
                hostnames[ip] = name
            continue

        if not current_host:
            continue

        row = _VERB_PORT_ROW.match(raw)
        if not row:
            continue
        # Skip header & summary lines that happen to look like data rows
        if row.group("state") not in ("open", "filtered", "closed"):
            continue
        if row.group("state") != "open":
            continue
        port = int(row.group("port")); proto = row.group("proto")
        rest = (row.group("rest") or "").strip()
        rest = _strip_reason(rest).strip()
        product = ""
        version = ""
        if rest:
            # First whitespace-separated token is the product/banner; the
            # remainder is the version. Quick + reasonably accurate.
            head, _, tail = rest.partition(" ")
            product = head
            version = tail.strip()

        k = (current_host, port, proto)
        existing = by_key.get(k)
        if existing is None:
            by_key[k] = PortEntry(
                host=current_host, hostname=current_hostname,
                port=port, protocol=proto, state="open",
                service=row.group("service"),
                product=product, version=version,
            )
        else:
            # Merge: table-row data wins because it's richer.
            existing.hostname = existing.hostname or current_hostname
            existing.service = row.group("service") or existing.service
            existing.product = product or existing.product
            existing.version = version or existing.version

    # Backfill hostnames from the report headers onto rows we collected
    # earlier via "Discovered open port" lines (those don't include the
    # hostname).
    for entry in by_key.values():
        if not entry.hostname:
            entry.hostname = hostnames.get(entry.host, "")

    return sorted(by_key.values(), key=lambda e: (e.host, e.port))


def summarise(entries: list[PortEntry]) -> dict:
    hosts = {e.host for e in entries}
    return {"hosts": len(hosts), "open_ports": len(entries)}
