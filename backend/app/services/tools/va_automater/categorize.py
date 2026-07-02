"""Multi-field weighted categorization with persistent plugin_id -> category map.

Each finding is scored against every category rule. The highest scorer wins.
Plugin IDs with confirmed mappings (stored in a JSON sidecar) skip the rule
engine entirely - on subsequent runs, known findings are categorized instantly.

Default rules combine signals from:
  - finding_name (exact + variant keywords)
  - plugin_family (Nessus's own coarse categorization - very reliable)
  - solution / synopsis text
  - exclusion keywords to avoid common misclassifications

Categories (v0.2, slimmed from v0.1):
  - SSL Misconfigurations     (renamed from SSL/TLS)
  - Information Disclosure
  - Outdated Software & Patches  (merged: OS patches, outdated versions, EOL)
  - Default / Weak Credentials
  - Web Application
  - Uncategorized             (catch-all - includes SMB/NetBIOS, open ports, etc.)

Note: SMB/NetBIOS and Open Ports/Services were dropped as standalone categories
in v0.2 - findings now fall to Uncategorized and the user can promote specific
plugin IDs via the persistent pid_map JSON if they want them broken out.
"""
from __future__ import annotations
from pathlib import Path
import json
import pandas as pd

from .identifiers import normalize_name

UNCATEGORIZED = "Uncategorized"


# ============================================================
# Curated exact finding-name -> category overrides.
#
# Many Nessus credentialed-enumeration / detection plugins have generic
# titles that don't score well on keywords and would otherwise land in
# Uncategorized. This map pins the EXACT finding names (normalized via
# normalize_name: lowercased, all non-alphanumerics dropped) to their
# category. It is checked AFTER the persistent pid_map but BEFORE the
# per-rule hardcoded plugin_ids and keyword scoring, so a curated name
# wins over plugin-id rule membership (deliberate: these are explicit
# human decisions about where each finding belongs).
#
# Keep this list in lock-step with the identical block in
# va_pipeline_standalone.py so the SSO/server infra pipeline and the
# offline standalone produce IDENTICAL groupings.
# ============================================================
_EXACT_NAME_CATEGORY_RAW: dict[str, str] = {
    # ---- SSL / TLS misconfigurations ----
    "HSTS Missing From HTTPS Server": "SSL Misconfigurations",
    "SSL/TLS Recommended Cipher Suites": "SSL Misconfigurations",

    # ---- Information disclosure (credentialed enumeration / detection /
    #      banner & host-info leakage) ----
    "BIOS Info (SMB)": "Information Disclosure",
    "BIOS Info (SSH)": "Information Disclosure",
    "BIOS Info (WMI)": "Information Disclosure",
    "DCE Services Enumeration": "Information Disclosure",
    "Docker Container Number of Changed Files": "Information Disclosure",
    "Docker Service Detection": "Information Disclosure",
    "Embedded Web Server Detection": "Information Disclosure",
    "Enumerate IPv4 Interfaces via SSH": "Information Disclosure",
    "Enumerate IPv6 Interfaces via SSH": "Information Disclosure",
    "Enumerate Local Group Memberships": "Information Disclosure",
    "Enumerate Users via WMI": "Information Disclosure",
    "Enumerate the Network Interface configuration via SSH": "Information Disclosure",
    "Enumerate the Network Routing configuration via SSH": "Information Disclosure",
    "Enumerate the PATH Variables": "Information Disclosure",
    "Explorer Search History": "Information Disclosure",
    "Host Active Directory Configuration (Linux)": "Information Disclosure",
    "Host Active Directory Configuration (Windows)": "Information Disclosure",
    "Host Fully Qualified Domain Name (FQDN) Resolution": "Information Disclosure",
    "IBM DataPower Gateway Detection": "Information Disclosure",
    "IP Assignment Method Detection": "Information Disclosure",
    "JQuery Detection": "Information Disclosure",
    "Java Detection and Identification (Linux / Unix)": "Information Disclosure",
    "Java Detection and Identification (Windows)": "Information Disclosure",
    "Kibana Detection": "Information Disclosure",
    "LDAP Server Detection": "Information Disclosure",
    "Linux Time Zone Information": "Information Disclosure",
    "Linux User List Enumeration": "Information Disclosure",
    "MSSQL Host Information in NTLM SSP": "Information Disclosure",
    "MUICache Program Execution History": "Information Disclosure",
    "McAfee Agent Detection": "Information Disclosure",
    "McAfee Agent Detection (Linux/MacOS)": "Information Disclosure",
    "Memory Information (via DMI)": "Information Disclosure",
    "Microsoft .NET Core for Windows": "Information Disclosure",
    "Microsoft .NET Framework Detection": "Information Disclosure",
    "Microsoft Internet Information Services (IIS) Sites Enumeration": "Information Disclosure",
    "Microsoft Windows Installed Software Enumeration (credentialed check)": "Information Disclosure",
    "Microsoft Windows Installed Software Version Enumeration": "Information Disclosure",
    "Microsoft Windows NTLMSSP Authentication Request Remote Network Name Disclosure": "Information Disclosure",
    "Microsoft Windows SMB Last Logged On User Disclosure": "Information Disclosure",
    "Microsoft Windows SMB LsaQueryInformationPolicy Function SID Enumeration": "Information Disclosure",
    "Microsoft Windows SMB Registry : Enumerate the list of SNMP communities": "Information Disclosure",
    "Microsoft Windows SMB Registry : OS Version and Processor Architecture": "Information Disclosure",
    "Microsoft Windows SMB Service Config Enumeration": "Information Disclosure",
    "Microsoft Windows SMB Service Enumeration": "Information Disclosure",
    "Microsoft Windows SMB Share Permissions Enumeration": "Information Disclosure",
    "Microsoft Windows SMB Shares Enumeration": "Information Disclosure",
    "Microsoft Windows Start Menu Software Version Enumeration": "Information Disclosure",
    "Microsoft Windows Startup Software Enumeration": "Information Disclosure",
    "RPC Services Enumeration": "Information Disclosure",
    "SMB QuickFixEngineering (QFE) Enumeration": "Information Disclosure",
    "System Information Enumeration (via DMI)": "Information Disclosure",
    "Unix / Linux - Local Users Information : Passwords Never Expire": "Information Disclosure",
    "Unix / Linux Running Processes Information": "Information Disclosure",
    "User Download Folder Files": "Information Disclosure",
    "User Shell Folders Settings": "Information Disclosure",
    "UserAssist Execution History": "Information Disclosure",
    "WMI Antivirus Enumeration": "Information Disclosure",
    "WMI Encryptable Volume Enumeration": "Information Disclosure",
    "WMI IIS ISAPI Extension Enumeration": "Information Disclosure",
    "WMI QuickFixEngineering (QFE) Enumeration": "Information Disclosure",
    "WMI Trusted Platform Module Enumeration": "Information Disclosure",
    "WMI Windows Feature Enumeration": "Information Disclosure",
    "Windows ComputerSystemProduct Enumeration (WMI)": "Information Disclosure",
    "Windows DNS Server Enumeration": "Information Disclosure",
    "Windows Disabled Command Prompt Enumeration": "Information Disclosure",
    "Windows Display Driver Enumeration": "Information Disclosure",
    "Windows Enumerate Accounts": "Information Disclosure",
    "Windows Explorer Recently Executed Programs": "Information Disclosure",
    "Windows Explorer Typed Paths": "Information Disclosure",
    "Windows Printer Driver Enumeration": "Information Disclosure",
    "Windows Product Key Retrieval": "Information Disclosure",
    "Windows Services Registry ACL": "Information Disclosure",
    "Windows Store Application Enumeration": "Information Disclosure",
    "Windows System Driver Enumeration (Windows)": "Information Disclosure",
    "Microsoft Windows 'Administrators' Group User List": "Information Disclosure",
    "Microsoft Windows Remote Listeners Enumeration (WMI)": "Information Disclosure",
    "Microsoft Windows SAM user enumeration": "Information Disclosure",
    "Microsoft Windows SMB : Obtains the Password Policy": "Information Disclosure",
    "Microsoft Windows SMB Shares Access": "Information Disclosure",
    "Microsoft Windows Unquoted Service Path Enumeration": "Information Disclosure",
    "NetBIOS Multiple IP Address Enumeration": "Information Disclosure",
    "Network Interfaces Enumeration (WMI)": "Information Disclosure",
    "Windows NetBIOS / SMB Remote Host Information Disclosure": "Information Disclosure",
}

# Normalized-key lookup built once at import. Keys are normalize_name() output.
EXACT_NAME_CATEGORY: dict[str, str] = {
    normalize_name(k): v for k, v in _EXACT_NAME_CATEGORY_RAW.items()
}


DEFAULT_RULES: dict[str, dict] = {
    "SSL Misconfigurations": {
        # Hard-coded plugin IDs for the most commonly-seen SSL/TLS findings
        # in enterprise infra VA engagements. Plugin IDs override keyword
        # scoring (priority 998) — ensures correct routing regardless of how
        # Nessus renames or restructures these plugins between releases.
        "plugin_ids": [
            # ---- Protocol version weaknesses ----
            "20007",   # SSL Version 2 and 3 Protocol Detection
            "35362",   # SSL Version 2 Protocol Detection (standalone)
            "35363",   # SSL Version 3 Protocol Detection (standalone)
            "104743",  # TLS Version 1.0 Protocol Detection (deprecated)
            "121010",  # TLS Version 1.1 Protocol Detection (deprecated)
            "149627",  # TLS Version 1.0 Protocol Deprecated
            "157038",  # TLS Version 1.0 and 1.1 Protocol Detection (combined)
            "160902",  # TLS 1.0 and 1.1 Protocol Detection (alternate)
            # ---- Weak / export cipher suites ----
            "26928",   # SSL Weak Cipher Suites Supported (DES, IDEA, RC2, ≤56-bit)
            "42873",   # SSL Medium Strength Cipher Suites Supported (SWEET32 / 3DES)
            "65821",   # SSL RC4 Cipher Suites Supported (Bar Mitzvah)
            "44925",   # SSL NULL Cipher Suites Supported (no encryption)
            "83875",   # SSL/TLS EXPORT_RSA ≤512-bit Cipher Suites Supported (FREAK)
            "83738",   # SSL/TLS EXPORT_DHE ≤512-bit Export Cipher Suites (Logjam)
            "135900",  # SSL/TLS Weak Cipher Suites Detected (combined check)
            # ---- Diffie-Hellman / key exchange ----
            "89058",   # SSL / TLS Diffie-Hellman Modulus ≤1024 Bits (Logjam)
            "94437",   # OpenSSL AES-NI Padding Oracle MitM Information Disclosure
            "87732",   # SSL/TLS Diffie-Hellman Key Exchange Insufficient DH Group Strength
            # ---- Certificate issues ----
            "57582",   # SSL Self-Signed Certificate
            "51192",   # SSL Certificate Cannot Be Trusted (untrusted/unknown CA)
            "35291",   # SSL Certificate Signed Using Weak Hashing Algorithm (MD5/SHA1)
            "45411",   # SSL Certificate with Wrong Hostname
            "45410",   # SSL Certificate commonName Mismatch
            "10863",   # SSL Certificate Expiry (expired cert)
            "15901",   # SSL Certificate Expiry — Future Expiry (near-expiry warning)
            "69551",   # SSL Certificate Chain Contains RSA Keys Less Than 2048 bits
            "73412",   # SSL Certificate Chain Contains Certificates with No Subject's Common Name
            "90317",   # SSL Certificate Cannot Be Trusted (alternate chain validation)
            "69152",   # SSL Certificate Hostname Validation Failure
            "42981",   # SSL Certificate with No Subject Alternative Name
            "58429",   # SSL Certificate Signed with an Obsolete Digest Algorithm (SHA-1)
            # ---- Known attack patterns / vulnerabilities ----
            "78479",   # SSLv3 Padding Oracle On Downgraded Legacy Encryption (POODLE) — network
            "78416",   # SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)
            "58751",   # SSL/TLS BEAST Attack (CBC Initialization Vector — IV)
            "42880",   # SSL CRIME Attack (TLS Compression)
            "85524",   # OpenSSL Bleichenbacher PKCS#1 v1.5 (ROBOT Attack)
            "105791",  # TLS ROBOT Vulnerability
            "119626",  # TLS ROBOT Vulnerability Detection (updated)
            "73830",   # Lucky 13 Attack (CBC padding oracle — CVE-2013-0169)
            "51892",   # OpenSSL Heartbleed (CVE-2014-0160)
            # ---- OCSP / HSTS ----
            "58768",   # SSL Certificate Chain Contains Certificates with No OCSP Information
            # ---- OpenSSL version disclosure ----
            "73998",   # OpenSSL Version Detection (version in banner — may indicate outdated)
            # ---- STARTTLS downgrade risk ----
            "36000",   # STARTTLS Command Support (email services — plaintext downgrade risk)
            "41881",   # IMAP Service STARTTLS Plaintext Command Injection
            "42088",   # POP3 Service STARTTLS Plaintext Command Injection
        ],
        "name_kw": [
            "ssl", "tls", "cipher", "sweet32", "poodle", "beast", "freak",
            "logjam", "crime", "drown", "robot attack", "lucky 13", "raccoon",
            "diffie-hellman", "dhe ", "ecdhe", "rsa key", "modulus",
            "certificate", "cert ", "x.509", "self-signed", "hsts", "ocsp",
            "perfect forward secrecy", "heartbleed", "bleichenbacher",
            "rc4", "null cipher", "export cipher", "weak cipher",
            "deprecated protocol", "protocol detection",
        ],
        "family_kw": ["general"],
        "solution_kw": [
            "disable sslv2", "disable sslv3", "disable tlsv1.0", "disable tls 1.0",
            "disable tlsv1.1", "disable tls 1.1", "use strong cipher",
            "obtain a new certificate", "replace the certificate",
            "renew the certificate", "reconfigure the ssl", "reconfigure the tls",
            "disable rc4", "disable null cipher", "enable perfect forward secrecy",
            "use a certificate signed by a trusted ca",
        ],
        "exclude_name_kw": [],
        "weights": {"name_kw": 3, "family_kw": 1, "solution_kw": 2, "synopsis_kw": 1},
    },
    "Information Disclosure": {
        # Hard-coded plugin IDs for the most commonly-seen information
        # disclosure findings: HTTP/SMTP/FTP/SSH/SNMP banner leakage,
        # DNS zone transfers, directory listings, and verbose error pages.
        "plugin_ids": [
            # ---- HTTP banner / header disclosure ----
            "10107",   # HTTP Server Type and Version (Apache/IIS/nginx version in banner)
            "86420",   # HTTP TRACE / TRACK Methods Allowed
            "48243",   # PHP expose_php Information Disclosure
            "11213",   # HTTP CONNECT Tunnel Detection
            "24260",   # HyperText Transfer Protocol (HTTP) Information
            "40984",   # Web Server Transmits Cleartext Credentials
            "11411",   # HTTP WWW Authentication Disclosure
            "50344",   # Microsoft IIS HTTP Request Parsing Information Leakage
            # ---- SMTP / mail banner disclosure ----
            "10027",   # SMTP Service Detection (version in banner)
            "10085",   # SMTP Server Detection (banner leaks version)
            "11719",   # SMTP Server EHLO/VRFY/EXPN Information Disclosure
            # ---- FTP banner disclosure ----
            "10092",   # FTP Server Detection (banner leaks version/type)
            "10088",   # FTP 'PASV' Mode IP Address Leak
            # ---- SSH banner / version disclosure ----
            "17975",   # SSH Server Type and Version Information
            "10881",   # SSH Protocol Versions Supported
            "70658",   # SSH Server Algorithms Supported (weak algo disclosure)
            # ---- SNMP information disclosure ----
            "34460",   # SNMP Query Running Process List Disclosure
            "33276",   # SNMP Enumeration (system info, uptime, interfaces)
            "10267",   # SNMP Agent Detection (community string exposes system info)
            "26917",   # SNMP Request Network Interfaces Enumeration
            "10264",   # SNMP Query Routing Information Disclosure
            # ---- DNS information disclosure ----
            "10028",   # DNS Server Zone Transfer (critical — full domain data exposure)
            "12217",   # DNS Server Cache Snooping Remote Information Disclosure
            "35450",   # DNS Request IPv6 Address Disclosure
            "43415",   # DNS Host and Domain Name Information Disclosure
            # ---- Windows / NetBIOS info disclosure ----
            "10397",   # Microsoft Windows LAN Manager Information Disclosure
            "10785",   # Microsoft Windows SMB NativeLanMan Disclosure
            # ---- Miscellaneous banners / service fingerprinting ----
            "11154",   # Unix Operating System Type and Version Detection
            "25220",   # TCP/IP Timestamps Supported (leaks OS uptime)
            "11936",   # OS Identification (passive fingerprinting)
            "22964",   # Service Detection (generic banner grab)
            "10336",   # Finger Service Detection (username enumeration)
            # ---- Web server info disclosure ----
            "11032",   # Web Server robots.txt Information Disclosure
            "10621",   # Web Server Directory Contents Disclosure
            "45590",   # Common Web Application Information Disclosure
        ],
        "name_kw": [
            "information disclosure", "info disclosure", "version disclosure",
            "banner disclosure", "banner", "http server type", "http server version",
            "server header", "service banner", "version detection", "fingerprint",
            "internal ip disclosure", "private ip disclosure",
            "directory listing", "directory browsing", "directory indexing",
            "trace method", "http trace", "verbose error",
            "robots.txt", "zone transfer", "cache snooping",
            "cleartext credentials", "cleartext authentication",
            "unencrypted credentials", "plaintext credentials",
            "error page", "stack trace", "debug information",
            "server version", "server type", "os detection", "os identification",
        ],
        "family_kw": [
            "service detection", "web servers", "general",
            "smtp problems", "ftp",
        ],
        "solution_kw": [
            "disable banner", "remove version", "configure the server to suppress",
            "disable trace", "disable the http track",
            "restrict zone transfer", "disable dns zone transfer",
            "suppress server version", "hide server version",
            "restrict access to robots.txt",
        ],
        # `vulnerabilities` (plural) is added alongside `vulnerability`
        # so a "Multiple Vulnerabilities" title never sneaks into
        # Information Disclosure when its family or banner-ish keywords
        # accidentally cross-hit — those titles are virtually always
        # patch advisories.
        "exclude_name_kw": [
            "outdated", "end of life", "eol", "unsupported",
            "vulnerability", "vulnerabilities", "multiple vulnerab",
            "cve-", "vmsa-", "rhsa-", "msrc-",
        ],
        "weights": {"name_kw": 3, "family_kw": 1, "solution_kw": 2, "synopsis_kw": 1},
    },
    # Merged from old "Missing OS Patches" + "Outdated Software / Version" + "End-of-Life Software".
    # Family signal is weighted heavily because the OS-patch families (Windows : Microsoft
    # Bulletins, *_Local_Security_Checks) are the strongest single indicator.
    #
    # Keyword coverage expanded 2026-05-15 after the team flagged several
    # Nessus findings landing in Uncategorized that should clearly be
    # patch advisories — VMware Workstation (VMSA-...), Oracle Java SE
    # (April CPU), Microsoft .NET Core (April 2026), ASP.NET Core DoS
    # (March 2026). The common signals across those: title says
    # "Multiple Vulnerabilities", carries a vendor advisory ID
    # (VMSA-/RHSA-/MSRC-/CVE-/KB...), has a version comparator
    # ("X < Y"), or is date-stamped "(<Month> YYYY)". Solution text
    # often reads "Update to <product> X.Y.Z" or "... to version X.Y.Z
    # or later" — neither was caught by the prior `update to version`
    # substring which required the words to be adjacent.
    "Outdated Software & Patches": {
        # Plugin IDs for critical/high-profile CVEs and commonly-seen vendor
        # advisories that either (a) have short/ambiguous names that might
        # score weakly on keywords alone, or (b) are so frequently seen on
        # internal infra that we want to guarantee correct routing.
        # NOTE: most OS-patch findings are handled by family_kw (MS Bulletins,
        # *_Local_Security_Checks families) — plugin_ids here are only for
        # findings that DON'T belong to those families but are clearly patch-level.
        "plugin_ids": [
            # Plugin ID overrides for high-profile CVEs / commonly-seen advisories
            # that might score weakly on keywords alone (e.g. short titles, no
            # family match). Most OS-patch findings are already handled by
            # family_kw (MS Bulletins, *_Local_Security_Checks) — these are
            # application-layer and cross-platform vulnerabilities.
            #
            # ---- Critical Windows OS / SMB patches ----
            "97737",   # MS17-010: SMBv1 RCE (EternalBlue / WannaCry / NotPetya)
            "91360",   # MS16-114: Windows SMB Server RCE
            "125313",  # BlueKeep RDP RCE (CVE-2019-0708)
            "128185",  # DejaBlue RDP RCE (CVE-2019-1182 / CVE-2019-1226)
            "134428",  # SMBGhost: SMBv3 Compression RCE (CVE-2020-0796)
            "151571",  # PrintNightmare: Windows Print Spooler RCE (CVE-2021-34527)
            "139459",  # Zerologon: Windows Netlogon Privilege Escalation (CVE-2020-1472)
            # ---- Microsoft Exchange Server ----
            "147196",  # ProxyLogon: Exchange Server SSRF+RCE (CVE-2021-26855)
            "148233",  # ProxyShell: Exchange Server RCE (CVE-2021-34473)
            "149073",  # ProxyOracle: Exchange Server RCE (CVE-2021-31196)
            # ---- Apache / Log4j ----
            "156327",  # Log4Shell: Apache Log4j RCE (CVE-2021-44228)
            "156860",  # Log4Shell variant: Apache Log4j JNDI RCE
            "157097",  # Apache Log4j 1.x EOL Multiple Vulnerabilities
            # ---- Apache HTTP Server ----
            "141187",  # Apache HTTP Server 2.4.x < 2.4.46 (multiple CVEs)
            "152648",  # Apache HTTP Server 2.4.49 Path Traversal (CVE-2021-41773)
            "153799",  # Apache HTTP Server 2.4.50 RCE (CVE-2021-42013)
            # ---- VMware ----
            "149676",  # VMware vCenter Server VMSA-2021-0010 Multiple Vulnerabilities
            "151253",  # VMware ESXi OpenSLP Heap Overflow RCE (CVE-2021-21974)
            "157846",  # VMware vCenter Server Multiple Vulnerabilities (VMSA-2021-0020)
            # ---- Citrix ----
            "132480",  # Citrix ADC / NetScaler Gateway RCE (CVE-2019-19781)
            # ---- F5 BIG-IP ----
            "139038",  # F5 BIG-IP TMUI RCE (CVE-2020-5902)
            # ---- Pulse Secure / Ivanti ----
            "128589",  # Pulse Connect Secure Arbitrary File Disclosure (CVE-2019-11510)
            # ---- Fortinet ----
            "131847",  # Fortinet FortiOS SSL VPN Path Traversal (CVE-2018-13379)
        ],
        "name_kw": [
            # OS-patch indicators
            "security update", "cumulative update", "rollup", "hotfix",
            "ms14-", "ms15-", "ms16-", "ms17-",
            "kb40", "kb41", "kb42", "kb43", "kb44", "kb45",
            "kb46", "kb47", "kb48", "kb49", "kb50", "kb51", "kb52", "kb53",
            "kb54", "kb55", "kb56", "kb57", "kb58", "kb59",
            # Vendor advisory IDs (strong signal — these always represent
            # patches/fixed-in-version advisories from the vendor).
            "vmsa-", "rhsa-", "msrc-", "cve-", "kbid",
            "(eol)", "patch tuesday",
            # Title patterns common to roll-up patch advisories.
            "multiple vulnerabilities", "multiple vulnerabilites",
            # Oracle Critical Patch Update naming convention.
            "critical patch update", " cpu)", " cpu )",
            # Version comparators that appear in titles like
            # "Foo X < Y" or "Foo X <= Y".
            " < ", " <= ",
            # Date-stamped patch titles: "(Month YYYY)". We match the
            # opening parenthesis to be specific — English "may" /
            # "june" as standalone words won't hit because of the
            # leading "(".
            "(january ", "(february ", "(march ", "(april ", "(may ",
            "(june ", "(july ", "(august ", "(september ", "(october ",
            "(november ", "(december ",
            # Version-out-of-date indicators
            "less than", "prior to", "before", "outdated",
            "obsolete version", "obsolete", "no longer maintained",
            "deprecated",
            # EOL indicators
            "end of life", "end-of-life", " eol ",
            "unsupported version", "no longer supported", "out of support",
            "obsolete operating system",
        ],
        "family_kw": [
            "windows : microsoft bulletins", "ms bulletins",
            "centos local security checks", "red hat local security checks",
            "ubuntu local security checks", "debian local security checks",
            "fedora local security checks", "amazon linux local security checks",
            "suse local security checks", "oracle linux local security checks",
            "solaris local security checks", "macos local security checks",
            "alma linux local security checks", "rocky linux local security checks",
            "scientific linux local security checks",
            "euleros local security checks", "photon os local security checks",
            "web servers", "cgi abuses", "databases", "firewalls",
        ],
        "solution_kw": [
            "install the patch", "install the security update", "apply the patch",
            "microsoft has released a set of patches", "install the rollup",
            # NEW: broader update/upgrade patterns. "update to" (without
            # the rigid "...version") catches "Update to .NET Core
            # 8.0.26" — the product name sits between "update" and
            # "version" in modern Microsoft solution text. "to version"
            # catches "Update ASP.NET Core to version 8.0.25" where
            # "update to" / "upgrade to" is split by a product name.
            "update to", "upgrade to", "update the", "upgrade the",
            "to version", "to a version", "to the latest", "to the version",
            "to a fixed version", "fixed in version", "fixed in release",
            "or later", "or newer",
            "upgrade to version", "update to version",
            "vendor advises upgrading", "vendor recommends upgrading",
            "apply the latest version", "install the latest version",
            "download and install", "fixed version", "patched version",
            "upgrade to a supported version", "migrate to a supported",
            "vendor no longer supports", "consult the vendor",
            "see vendor advisory", "vendor security advisory",
            "refer to vmsa", "refer to the vendor",
            # Common in MSRC / Microsoft advisory solutions.
            "microsoft has released", "see https://msrc",
            # Oracle CPU solution text.
            "critical patch update",
        ],
        "exclude_name_kw": [
            "ssl certificate", "tls certificate",
            "service detection", "version detection", "fingerprint",
        ],
        # `force_include_kw` bypasses `exclude_name_kw` when the title
        # carries an unambiguous outdated-software signal. The Nessus
        # plugins "PHP Unsupported Version Detection" and "Microsoft
        # SQL Server Unsupported Version Detection" are the canonical
        # examples: titles contain both "unsupported version" (strong
        # outdated signal) AND "version detection" (which would
        # otherwise exclude the rule entirely). Anything matching one
        # of these tokens IS outdated software, regardless of any
        # excluded keywords also being present.
        "force_include_kw": [
            "unsupported", "outdated", "obsolete",
            "end of life", "end-of-life", " eol ",
            "no longer supported", "no longer maintained",
            "deprecated",
        ],
        # `plugin_output_kw` scans the Nessus per-host plugin_output
        # block — which is where the "Installed version : X.Y /
        # Supported versions : A.B / End of support date : YYYY"
        # template appears for unsupported-product detections. Some of
        # those plugins have a terse solution column ("Upgrade to a
        # supported version.") that already gets caught by
        # `solution_kw`, but the plugin_output match is a belt-and-
        # braces signal that catches the rare case where solution text
        # is missing/different.
        "plugin_output_kw": [
            "installed version", "supported version", "supported versions",
            "minimum supported version", "end of support date",
            "end-of-support", "out of support", "no longer supported",
            "unsupported installation", "unsupported installations",
        ],
        "weights": {
            "name_kw": 2, "family_kw": 3, "solution_kw": 2,
            "synopsis_kw": 1, "plugin_output_kw": 2,
            "force_include_kw": 3,
        },
    },
    "Default / Weak Credentials": {
        "name_kw": [
            "default credentials", "default password", "default account",
            "weak credentials", "weak password", "blank password", "no password",
            "anonymous login", "anonymous access", "guest account",
        ],
        "family_kw": ["default unix accounts", "default password"],
        "solution_kw": [
            "change the default", "set a strong password", "disable the account",
        ],
        "exclude_name_kw": [],
        "weights": {"name_kw": 4, "family_kw": 3, "solution_kw": 2, "synopsis_kw": 1},
    },
    "Web Application": {
        "name_kw": [
            "cross-site scripting", "xss", "sql injection", "csrf",
            "directory traversal", "path traversal", "file inclusion",
            "command injection", "ldap injection", "xml injection", "xxe",
            "clickjacking", "x-frame-options", "content security policy", " csp ",
            "cookie", "session", "wordpress", "joomla", "drupal",
        ],
        "family_kw": ["web servers", "cgi abuses"],
        "solution_kw": [
            "set the x-frame-options", "set the content-security-policy",
            "set the httponly", "set the secure flag",
            "input validation", "output encoding",
        ],
        "exclude_name_kw": [],
        "weights": {"name_kw": 3, "family_kw": 2, "solution_kw": 2, "synopsis_kw": 1},
    },
    # New 2026-05-16: the recurring grouped category for local
    # privilege-escalation / hardening misconfigurations that show up
    # on every internal Infra VA. Maps to the "Insecure Service
    # Configurations (Grouped)" library finding via
    # `infra_pipeline.CATEGORY_TO_LIBRARY`. Title/plugin-output driven
    # because these Nessus plugins are configuration audits (no CVE),
    # so the family is usually a generic "Windows" / local-security
    # bucket — the name + the solution text are the reliable signals.
    "Insecure Service Configurations": {
        # Hard-coded Nessus plugin IDs that always route here regardless
        # of keyword scoring. Covers the recurring findings seen on every
        # internal Infra VA engagement. Add new IDs as they appear in scans.
        "plugin_ids": [
            # ---- Network / OS configuration ----
            "10114",   # ICMP Timestamp Request Remote Date Disclosure
            "50686",   # IP Forwarding Enabled
            "10664",   # ICMP Netmask Request Information Disclosure
            "34252",   # IPv6 Multicast Listener Discovery (MLD) Detection
            # ---- Windows hardening ----
            "103569",  # Windows Defender Antimalware/Antivirus Signature Definition Check
            "132101",  # Windows Speculative Execution Configuration Check
            "35453",   # Microsoft Windows Update Reboot Required
            "92368",   # Microsoft Windows Unquoted Service Path Enumeration
            "63155",   # Microsoft Windows SMB : Obtaining Network Security Information
            "73574",   # Microsoft Windows SMB File Sharing Misconfiguration
            "65821",   # Microsoft Windows Unquoted Service Path Enumeration (via WMI)
            # ---- Kerberos / Active Directory hardening ----
            "156898",  # Kerberos 'Pre-Authentication' Not Required (AS-REP Roasting)
            "156897",  # Kerberos SPN Enumeration (Kerberoastable accounts)
            "156899",  # Active Directory Password Policy Too Permissive
            "146751",  # Microsoft Windows LAPS Not Enabled
            "24272",   # Null Session/NetBIOS — Net User Enumerable
            "10396",   # Microsoft Windows LAN Manager Information Disclosure
            "49174",   # Microsoft Windows Remote Desktop Protocol Encryption Level
            # ---- SMB ----
            "57608",   # SMB Signing Not Required
            "96982",   # SMB Protocol Version 1 Server Detection (EternalBlue surface)
            "11011",   # Microsoft Windows SMB Service Detection
            "26920",   # Microsoft Windows SMB NULL Session Authentication
            "42411",   # Microsoft Windows SMB Shares Unprivileged Access
            "73174",   # Microsoft Windows SMB : User Enumeration
            # ---- RDP / Remote Access ----
            "18405",   # Microsoft Windows Remote Desktop Protocol Server Man-in-the-Middle Weakness (NLA)
            "58453",   # Terminal Services Doesn't Use Network Level Authentication (NLA)
            "30218",   # Terminal Services Encryption Level is not FIPS-140 Compliant
            "84502",   # Remote Desktop Protocol (RDP) Enabled
            # ---- NetBIOS / LLMNR / mDNS ----
            "10150",   # Windows NetBIOS / SMB Remote Host Information Disclosure
            "56468",   # Time of Last System Startup
            "100787",  # Link-Local Multicast Name Resolution (LLMNR) Detection
            "35716",   # Ethernet Card Manufacturer Detection (mDNS/Bonjour)
            "11143",   # NetBIOS Name Service Information Disclosure
            # ---- SNMP ----
            "10551",   # SNMP Agent Default Community Names (public/private)
            "41028",   # SNMP Agent Community Name Information Disclosure
            "10264",   # SNMP Request Network Interfaces Enumeration
            # ---- Print Spooler / PrintNightmare ----
            "153580",  # Windows Print Spooler Service Running (PrintNightmare exposure)
            # ---- Miscellaneous hardening ----
            "65057",   # Microsoft Windows Credential Guard Not Enabled
            "106716",  # WDigest Authentication Enabled
            "126527",  # Microsoft Windows LSA Protection Not Enabled
            "10205",   # rlogin Service Detection
            "10407",   # Rsh Service Detection
            "10281",   # Telnet Service Detection
            "22964",   # SSH Protocol Version 1 Session Key Retrieval
            "10902",   # FTP Server Allows Unauthenticated Anonymous Access
        ],
        "name_kw": [
            # ---- Service path / binary permission issues ----
            "unquoted service path", "unquoted search path",
            "insecure service", "service path",
            "writable service", "modifiable service",
            "weak service permission", "service permission",
            "insecure permission", "weak permission",
            "world writable", "world-writable", "writable by",
            "suid", "sgid", "setuid", "setgid", " suid bit",
            "service binary", "trusted service path",
            # ---- Registry / file system permissions ----
            "registry key", "registry value", "registry permission",
            "alwaysinstallelevated", "autologon", "auto-logon",
            "auto logon", "winlogon", "run key", "runonce",
            "insecure registry", "weak registry",
            "weak file permission", "insecure file permission",
            "sudoers", "nopasswd", "writable path",
            # ---- Code injection surface ----
            "dll hijack", "dll search order", "phantom dll",
            # ---- Administrative interfaces ----
            "exposed administrative interface", "debug interface enabled",
            "dangerous extension handling",
            # ---- Generic misconfig indicators ----
            "default configuration", "default install",
            "insecure configuration", "misconfiguration",
            # ---- SMB hardening (recurs on every internal scan) ----
            "smb signing",                  # SMB Signing Not Required
            "smb signing not required",
            "smb signing disabled",
            "smb version 1", "smb1 ", "smb v1", "smbv1",
            "smb protocol version 1",
            "smb null session",
            "smb shares unprivileged",
            # ---- RDP / Terminal Services hardening ----
            "network level authentication",
            "nla not required",
            "nla is not",
            "terminal services encryption",
            "rdp weak encryption",
            "remote desktop protocol",
            # ---- NetBIOS / Name resolution multicast ----
            "netbios", "nbt-ns",
            "llmnr",                        # Link-Local Multicast Name Resolution
            "link-local multicast",
            "multicast dns", "mdns",        # Bonjour / Avahi
            # ---- Legacy / insecure remote access protocols ----
            "telnet service", "telnet server",
            "rsh service", "rlogin service", "rexec service",
            "finger service",
            # ---- SNMP insecure config ----
            "snmp default community",
            "snmp community name",
            "snmp agent default",
            # ---- Network / OS configuration checks ----
            "icmp timestamp",               # ICMP Timestamp Request Remote Date Disclosure
            "ip forwarding",                # IP Forwarding Enabled
            "ip_forward",
            "speculative execution",        # Windows Speculative Execution (Meltdown/Spectre)
            "antimalware",                  # Windows Defender Antimalware/AV checks
            "antivirus signature",
            "signature definition",
            "windows defender",
            "defender antivirus",
            "reboot required",              # Windows Update Reboot Required
            "restart required",
            # ---- Windows hardening checks ----
            "credential guard",             # Credential Guard not enabled
            "wdigest",                      # WDigest stores plaintext credentials
            "wdigest authentication",
            "lsass protection",
            "secure boot",
            "print spooler",               # PrintNightmare surface
            "spooler service",
            "winrm",                       # WinRM insecure config
            "windows remote management",
            "powershell execution policy",
            "powershell remoting",
            "ntlm authentication",         # NTLM v1 or downgrade
            "ntlmv1",
            # ---- NFS / RPC ----
            "nfs share", "nfs export",
            "rpc portmapper",
            # ---- Active Directory / Kerberos hardening ----
            "kerberoast",                  # Kerberoastable service accounts
            "as-rep roast", "asrep roast", # AS-REP roasting (no pre-auth)
            "pre-authentication not required",
            "kerberos pre-auth",
            "laps not enabled",            # Local Administrator Password Solution
            "local admin password",
            "laps",
            "password policy",             # AD password policy weakness
            "account lockout",
            # ---- LSA / credential protection ----
            "lsa protection",
            "lsass protection not enabled",
            "protected process",
            # ---- FTP anonymous ----
            "anonymous ftp",
            "ftp anonymous",
            "ftp allows anonymous",
            "unauthenticated anonymous",
            # ---- SSH legacy protocols ----
            "ssh protocol version 1",
            "ssh v1",
        ],
        "family_kw": [
            "windows", "policy compliance", "firewalls", "misc.",
            "netbios", "smb",
        ],
        "solution_kw": [
            # ---- Service path / permission fixes ----
            "enclose the path", "quote the path", "use quotes",
            "restrict permissions", "tighten permissions",
            "remove the suid", "remove suid", "remove the setuid",
            "set the registry", "correct the registry",
            "disable alwaysinstallelevated", "remove world-writable",
            "harden the configuration", "apply the cis",
            "least privilege", "restrict write access",
            "remove write permission",
            # ---- Network / OS configuration fixes ----
            "filter icmp", "block icmp", "disable icmp",
            "disable ip forwarding",
            "apply vendor recommended",
            "update signatures", "update definitions",
            "enable auto-update", "update-mpsignature",
            # ---- SMB / RDP fixes ----
            "enable smb signing", "require smb signing",
            "disable smb 1", "disable smb v1", "disable smbv1",
            "enable nla", "require nla",
            "enable network level authentication",
            # ---- Multicast / NetBIOS ----
            "disable llmnr", "disable netbios",
            "disable mdns", "disable bonjour",
            # ---- Legacy protocol fixes ----
            "disable telnet", "disable rsh", "disable rlogin",
            # ---- SNMP ----
            "change the community string", "use snmpv3",
            "disable snmp", "restrict snmp",
            # ---- Windows hardening ----
            "enable credential guard",
            "disable wdigest",
            "enable lsass protection",
            "disable print spooler",
            # ---- Active Directory / Kerberos ----
            "enable pre-authentication",
            "require kerberos pre-authentication",
            "deploy laps", "enable laps",
            "enforce account lockout",
            "enforce password policy",
            "review service accounts",
            # ---- LSA protection ----
            "enable lsa", "configure lsa",
            "enable protected process",
            # ---- FTP / SSH legacy ----
            "disable anonymous ftp", "disable ftp",
            "disable ssh v1", "disable ssh protocol 1",
            "use ssh protocol 2",
        ],
        # Don't poach genuine outdated/SSL/credential findings.
        "exclude_name_kw": [
            "ssl certificate", "tls certificate",
            "outdated", "end of life", "unsupported version",
            "default credentials", "default password",
            # These sound like misconfig but are really credential/web-app findings
            "default content", "default page",
        ],
        # name_kw heavily weighted: titles like "SMB Signing Not Required"
        # and "Microsoft Windows Unquoted Service Path Enumeration" are
        # unambiguous on the name alone. family is weak (generic "Windows").
        "weights": {"name_kw": 4, "family_kw": 1, "solution_kw": 3,
                    "synopsis_kw": 1},
    },
    # Removed in v0.2: "SMB / NetBIOS" and "Open Ports / Services" - findings that
    # would have hit those rules now fall to Uncategorized, where the user reviews
    # them and edits the pid_map JSON to assign whatever category they prefer.
}


def _kw_hit(text: str, keywords: list[str]) -> bool:
    if not keywords:
        return False
    return any(k in text for k in keywords)


def _score_one(row: dict, rule: dict) -> int:
    name = str(row.get("finding_name", "") or "").lower()
    family = str(row.get("plugin_family", "") or "").lower()
    solution = str(row.get("solution", "") or "").lower()
    synopsis = str(row.get("synopsis", "") or "").lower()
    plugin_output = str(row.get("plugin_output", "") or "").lower()

    # Force-include bypasses the exclude list. Used for titles that
    # carry an unambiguous category signal (e.g. "unsupported",
    # "outdated") even when they also contain a normally-excluded
    # phrase like "version detection". Also acts as a strong score
    # contributor so the rule wins on titles where another category
    # might otherwise tie.
    force_include = rule.get("force_include_kw") or []
    force_match = _kw_hit(name, force_include) if force_include else False

    if not force_match and rule.get("exclude_name_kw") \
            and _kw_hit(name, rule["exclude_name_kw"]):
        return 0

    w = rule.get("weights", {})
    score = 0
    if _kw_hit(name, rule.get("name_kw", [])):
        score += w.get("name_kw", 1)
    if _kw_hit(family, rule.get("family_kw", [])):
        score += w.get("family_kw", 1)
    if _kw_hit(solution, rule.get("solution_kw", [])):
        score += w.get("solution_kw", 1)
    if _kw_hit(synopsis, rule.get("name_kw", [])):
        score += w.get("synopsis_kw", 1)
    # Plugin output often contains the "Installed version: X / Supported
    # versions: Y.Z" block that Nessus emits for EOL findings — a strong
    # outdated signal that doesn't appear in the structured solution
    # column. Match outdated-style keywords against it so a finding
    # whose solution is terse still scores correctly.
    if rule.get("plugin_output_kw"):
        if _kw_hit(plugin_output, rule["plugin_output_kw"]):
            score += w.get("plugin_output_kw", 1)
    if force_match:
        # Bonus on top of name_kw — force-include is a strong signal,
        # not a substitute. Bumps the rule's score so it overtakes any
        # other category that might also have a partial title match.
        score += w.get("force_include_kw", 2)
    return score


def categorize_one(
    row: dict,
    rules: dict | None = None,
    pid_map: dict | None = None,
) -> tuple[str, int]:
    """Return (category, confidence_score) for a single finding.

    Priority order (highest wins):
      1. pid_map     — confirmed mappings from the persistent JSON sidecar (score 999)
      2. exact name  — curated EXACT_NAME_CATEGORY overrides (score 998)
      3. plugin_ids  — hardcoded plugin ID lists inside each rule (score 998)
      4. keyword scoring via _score_one
    """
    rules = rules if rules is not None else DEFAULT_RULES
    pid = str(row.get("plugin_id", "") or "").strip()

    # 1. Persistent pid_map wins over everything.
    if pid_map and pid and pid in pid_map:
        return pid_map[pid], 999

    # 2. Curated exact finding-name overrides. Checked BEFORE plugin_ids so an
    #    explicit human categorization wins over plugin-id rule membership.
    name_norm = normalize_name(row.get("finding_name", ""))
    if name_norm and name_norm in EXACT_NAME_CATEGORY:
        return EXACT_NAME_CATEGORY[name_norm], 998

    # 3. Hardcoded plugin_ids inside a rule — reliable for well-known
    #    Nessus plugins that don't match keyword patterns well.
    if pid:
        for cat, rule in rules.items():
            if pid in (rule.get("plugin_ids") or ()):
                return cat, 998

    # 4. Keyword-based scoring.
    best_cat, best_score = UNCATEGORIZED, 0
    for cat, rule in rules.items():
        s = _score_one(row, rule)
        if s > best_score:
            best_cat, best_score = cat, s
    return best_cat, best_score


def categorize_dataframe(
    df: pd.DataFrame,
    rules: dict | None = None,
    pid_map: dict | None = None,
) -> pd.DataFrame:
    """Add 'category' and 'category_score' columns."""
    out = df.copy().reset_index(drop=True)
    cats, scores = [], []
    for _, r in out.iterrows():
        c, s = categorize_one(r.to_dict(), rules, pid_map)
        cats.append(c)
        scores.append(s)
    out["category"] = cats
    out["category_score"] = scores
    return out


# -----------------------------------------------------------
# Persistent plugin_id -> category map
# -----------------------------------------------------------
def load_pid_map(path: Path) -> dict[str, str]:
    """Load persistent plugin_id -> category mapping. Empty dict if missing."""
    path = Path(path)
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {str(k): str(v) for k, v in data.items()}
    except (json.JSONDecodeError, OSError):
        return {}


def save_pid_map(path: Path, mapping: dict[str, str]) -> None:
    """Save plugin_id -> category mapping atomically."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2, sort_keys=True)
    tmp.replace(path)


def merge_into_pid_map(
    existing: dict,
    df: pd.DataFrame,
    confirm_threshold: int = 4,
) -> tuple[dict, int]:
    """Add high-confidence (plugin_id -> category) entries from a categorized df.

    Only entries with category != Uncategorized, score >= threshold, and
    no existing mapping are added. Returns (new_map, n_added).
    """
    new = dict(existing)
    added = 0
    for _, r in df.iterrows():
        pid = str(r.get("plugin_id", "") or "").strip()
        cat = r.get("category", UNCATEGORIZED)
        score = r.get("category_score", 0)
        if pid and cat != UNCATEGORIZED and score >= confirm_threshold and pid not in new:
            new[pid] = cat
            added += 1
    return new, added
