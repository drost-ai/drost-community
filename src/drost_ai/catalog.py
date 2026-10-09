"""Declarative Drost-owned catalog of executable-backed security tools."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Iterable


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    executable: str
    category: str
    description: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


# This inventory intentionally describes capabilities rather than preserving
# another project's MCP names or schemas. Each entry becomes a Drost MCP tool
# with the shared, explicit argv schema defined by the Drost server.
TOOL_GROUPS: dict[str, tuple[tuple[str, str], ...]] = {
    "network": (
        ("nmap", "nmap"),
        ("rustscan", "rustscan"),
        ("masscan", "masscan"),
        ("autorecon", "autorecon"),
        ("arp_scan", "arp-scan"),
        ("netbios_scan", "nbtscan"),
        ("packet_capture", "tcpdump"),
        ("packet_analysis", "tshark"),
        ("network_mapper", "netdiscover"),
        ("socat", "socat"),
    ),
    "enumeration": (
        ("amass", "amass"),
        ("subfinder", "subfinder"),
        ("fierce", "fierce"),
        ("dnsenum", "dnsenum"),
        ("theharvester", "theHarvester"),
        ("enum4linux", "enum4linux"),
        ("enum4linux_ng", "enum4linux-ng"),
        ("rpcclient", "rpcclient"),
        ("smbmap", "smbmap"),
        ("netexec", "nxc"),
        ("responder", "responder"),
        ("recon_ng", "recon-ng"),
        ("spiderfoot", "spiderfoot"),
        ("sherlock", "sherlock"),
        ("shodan", "shodan"),
        ("censys", "censys"),
    ),
    "web": (
        ("gobuster", "gobuster"),
        ("ffuf", "ffuf"),
        ("feroxbuster", "feroxbuster"),
        ("dirb", "dirb"),
        ("dirsearch", "dirsearch"),
        ("nikto", "nikto"),
        ("nuclei", "nuclei"),
        ("sqlmap", "sqlmap"),
        ("wpscan", "wpscan"),
        ("wfuzz", "wfuzz"),
        ("xsser", "xsser"),
        ("dotdotpwn", "dotdotpwn"),
        ("katana", "katana"),
        ("hakrawler", "hakrawler"),
        ("gau", "gau"),
        ("waybackurls", "waybackurls"),
        ("arjun", "arjun"),
        ("paramspider", "paramspider"),
        ("x8", "x8"),
        ("jaeles", "jaeles"),
        ("dalfox", "dalfox"),
        ("httpx", "httpx"),
        ("anew", "anew"),
        ("qsreplace", "qsreplace"),
        ("uro", "uro"),
        ("wafw00f", "wafw00f"),
        ("zap", "zaproxy"),
        ("burp", "burpsuite"),
        ("curl", "curl"),
        ("httpie", "http"),
    ),
    "credentials": (
        ("hydra", "hydra"),
        ("medusa", "medusa"),
        ("patator", "patator"),
        ("john", "john"),
        ("hashcat", "hashcat"),
        ("hash_identifier", "hash-identifier"),
        ("ophcrack", "ophcrack"),
        ("evil_winrm", "evil-winrm"),
    ),
    "exploitation": (
        ("metasploit", "msfconsole"),
        ("msfvenom", "msfvenom"),
        ("exploit_search", "searchsploit"),
    ),
    "binary": (
        ("gdb", "gdb"),
        ("radare2", "radare2"),
        ("ghidra", "ghidra"),
        ("binwalk", "binwalk"),
        ("ropgadget", "ROPgadget"),
        ("ropper", "ropper"),
        ("checksec", "checksec"),
        ("objdump", "objdump"),
        ("strings", "strings"),
        ("xxd", "xxd"),
        ("file", "file"),
        ("one_gadget", "one_gadget"),
        ("pwninit", "pwninit"),
        ("pwntools", "pwn"),
    ),
    "forensics": (
        ("volatility", "vol"),
        ("foremost", "foremost"),
        ("steghide", "steghide"),
        ("exiftool", "exiftool"),
        ("testdisk", "testdisk"),
        ("scalpel", "scalpel"),
        ("bulk_extractor", "bulk_extractor"),
        ("zsteg", "zsteg"),
        ("hashpump", "hashpump"),
        ("sleuthkit_fls", "fls"),
        ("sleuthkit_icat", "icat"),
    ),
    "cloud_container_iac": (
        ("prowler", "prowler"),
        ("scout_suite", "scout"),
        ("trivy", "trivy"),
        ("kube_hunter", "kube-hunter"),
        ("kube_bench", "kube-bench"),
        ("docker_bench", "docker-bench-security"),
        ("checkov", "checkov"),
        ("terrascan", "terrascan"),
    ),
    "wireless": (
        ("aircrack", "aircrack-ng"),
        ("airmon", "airmon-ng"),
        ("airodump", "airodump-ng"),
        ("aireplay", "aireplay-ng"),
        ("kismet", "kismet"),
    ),
}


def _tool_name(slug: str) -> str:
    normalized = re.sub(r"[^a-z0-9_]+", "_", slug.lower()).strip("_")
    return f"drost_{normalized}"


def _description(slug: str, executable: str, category: str) -> str:
    label = slug.replace("_", " ")
    return (
        f"Run {label} from the Drost {category.replace('_', ' ')} toolkit. "
        f"The container executes `{executable}` directly with the supplied argv tokens; "
        "shell parsing is never used."
    )


def build_catalog() -> tuple[ToolSpec, ...]:
    specs: list[ToolSpec] = []
    seen: set[str] = set()
    for category, entries in TOOL_GROUPS.items():
        for slug, executable in entries:
            name = _tool_name(slug)
            if name in seen:
                raise ValueError(f"duplicate Drost tool name: {name}")
            seen.add(name)
            specs.append(
                ToolSpec(
                    name=name,
                    executable=executable,
                    category=category,
                    description=_description(slug, executable, category),
                )
            )
    return tuple(specs)


CATALOG = build_catalog()


def category_counts(specs: Iterable[ToolSpec] = CATALOG) -> dict[str, int]:
    counts: dict[str, int] = {}
    for spec in specs:
        counts[spec.category] = counts.get(spec.category, 0) + 1
    return dict(sorted(counts.items()))
