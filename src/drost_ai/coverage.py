"""Trace the reference functional inventory to Drost-owned tools."""

from __future__ import annotations

from .catalog import CATALOG


REFERENCE_FUNCTIONS = frozenset(
    """
    nmap gobuster dirb nikto sqlmap hydra john hashcat
    rustscan masscan autorecon nbtscan arp-scan responder nxc enum4linux-ng rpcclient enum4linux
    ffuf feroxbuster dirsearch dotdotpwn xsser wfuzz gau waybackurls arjun paramspider x8 jaeles dalfox
    httpx wafw00f burpsuite zaproxy katana hakrawler
    nuclei wpscan graphql-scanner jwt-analyzer
    medusa patator hash-identifier ophcrack hashcat-utils
    gdb radare2 binwalk ropgadget checksec objdump ghidra pwntools one-gadget ropper angr libc-database pwninit
    volatility3 vol steghide hashpump foremost exiftool strings xxd file photorec testdisk scalpel bulk-extractor
    stegsolve zsteg outguess
    prowler scout-suite trivy kube-hunter kube-bench docker-bench-security checkov terrascan falco clair
    amass subfinder fierce dnsenum theharvester sherlock social-analyzer recon-ng maltego spiderfoot shodan-cli
    censys-cli have-i-been-pwned
    metasploit exploit-db searchsploit
    api-schema-analyzer postman insomnia curl httpie anew qsreplace uro
    kismet wireshark tshark tcpdump
    smbmap volatility sleuthkit autopsy evil-winrm airmon-ng airodump-ng aireplay-ng aircrack-ng
    msfvenom msfconsole
    """.split()
)


REFERENCE_ALIASES: dict[str, str] = {
    "angr": "drost_angr_analyze",
    "api-schema-analyzer": "drost_openapi_inspect",
    "autopsy": "drost_sleuthkit_fls",
    "bulk-extractor": "drost_bulk_extractor",
    "censys-cli": "drost_censys",
    "clair": "drost_trivy",
    "exploit-db": "drost_exploit_search",
    "graphql-scanner": "drost_graphql_request",
    "hashcat-utils": "drost_hashcat",
    "have-i-been-pwned": "drost_hibp_password_check",
    "insomnia": "drost_http_request",
    "httpie": "drost_httpie",
    "jwt-analyzer": "drost_jwt_decode",
    "libc-database": "drost_pwninit",
    "maltego": "drost_spiderfoot",
    "metasploit": "drost_metasploit",
    "msfconsole": "drost_metasploit",
    "one-gadget": "drost_one_gadget",
    "outguess": "drost_steghide",
    "photorec": "drost_testdisk",
    "postman": "drost_http_request",
    "pwntools": "drost_pwntools",
    "ropgadget": "drost_ropgadget",
    "scout-suite": "drost_scout_suite",
    "searchsploit": "drost_exploit_search",
    "shodan-cli": "drost_shodan",
    "sleuthkit": "drost_sleuthkit_fls",
    "social-analyzer": "drost_sherlock",
    "stegsolve": "drost_zsteg",
    "theharvester": "drost_theharvester",
    "burpsuite": "drost_zap",
    "waybackurls": "drost_urlfinder",
    "wpscan": "drost_whatweb",
    "falco": "drost_process_snapshot",
    "volatility": "drost_volatility",
    "volatility3": "drost_volatility",
    "wireshark": "drost_packet_analysis",
}


def reference_coverage() -> dict[str, str]:
    by_executable = {spec.executable: spec.name for spec in CATALOG}
    coverage: dict[str, str] = {}
    for reference in sorted(REFERENCE_FUNCTIONS):
        if reference in REFERENCE_ALIASES:
            coverage[reference] = REFERENCE_ALIASES[reference]
        elif reference in by_executable:
            coverage[reference] = by_executable[reference]
    return coverage


def uncovered_reference_functions() -> list[str]:
    covered = reference_coverage()
    return sorted(REFERENCE_FUNCTIONS - covered.keys())
