# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS go-tools

ARG TARGETOS
ARG TARGETARCH

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install github.com/tomnomnom/anew@latest \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install github.com/tomnomnom/waybackurls@latest \
    && mkdir -p /out \
    && find /go/bin -type f -name anew -exec cp {} /out/anew \; \
    && find /go/bin -type f -name waybackurls -exec cp {} /out/waybackurls \;

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install github.com/jaeles-project/jaeles@latest \
    && find /go/bin -type f -name jaeles -exec cp {} /out/jaeles \;

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install github.com/aquasecurity/kube-bench@latest \
    && find /go/bin -type f -name kube-bench -exec cp {} /out/kube-bench \;

RUN git clone --depth 1 --branch v1.19.9 https://github.com/tenable/terrascan.git /src/terrascan \
    && cd /src/terrascan \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/terrascan ./cmd/terrascan

FROM --platform=$TARGETPLATFORM rust:1.95-bookworm AS rust-tools

RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/usr/local/cargo/git \
    cargo install x8

ARG TARGETARCH

RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/usr/local/cargo/git \
    if [ "$TARGETARCH" = "amd64" ]; then \
        apt-get update \
        && apt-get install -y --no-install-recommends ca-certificates curl \
        && curl --fail --location https://github.com/io12/pwninit/releases/latest/download/pwninit -o /usr/local/cargo/bin/pwninit \
        && chmod 0755 /usr/local/cargo/bin/pwninit; \
    else \
        cargo install pwninit; \
    fi

FROM --platform=$TARGETPLATFORM debian:bookworm AS hashpump-tools

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates g++ git libssl-dev make \
    && git clone --depth 1 https://github.com/mheistermann/HashPump-partialhash.git /src/hashpump \
    && make -C /src/hashpump \
    && mkdir -p /out \
    && cp /src/hashpump/hashpump /out/hashpump

FROM kalilinux/kali-rolling:latest

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        aircrack-ng \
        amass \
        arjun \
        arp-scan \
        autopsy \
        autorecon \
        binutils \
        binwalk \
        bulk-extractor \
        burpsuite \
        ca-certificates \
        checksec \
        curl \
        dalfox \
        dirb \
        dirsearch \
        dnsenum \
        dotdotpwn \
        enum4linux \
        enum4linux-ng \
        evil-winrm \
        exploitdb \
        feroxbuster \
        ffuf \
        fierce \
        file \
        foremost \
        gdb \
        getallurls \
        ghidra \
        git \
        gobuster \
        hakrawler \
        hash-identifier \
        hashcat \
        hashcat-utils \
        httpie \
        httpx-toolkit \
        hydra \
        john \
        katana \
        kismet \
        libcap2-bin \
        libimage-exiftool-perl \
        maltego \
        masscan \
        medusa \
        metasploit-framework \
        mitmproxy \
        nbtscan \
        netexec \
        netdiscover \
        nikto \
        nmap \
        nuclei \
        ophcrack \
        paramspider \
        patator \
        python3 \
        python3-aiohttp \
        python3-bs4 \
        python3-flask \
        python3-mcp \
        python3-pip \
        python3-psutil \
        python3-pwntools \
        python3-requests \
        python3-selenium \
        python3-setuptools \
        python3-shodan \
        python3-venv \
        qsreplace \
        radare2 \
        recon-ng \
        responder \
        ropper \
        rustscan \
        samba-common-bin \
        scalpel \
        sherlock \
        sleuthkit \
        smbmap \
        socat \
        spiderfoot \
        sqlmap \
        steghide \
        subfinder \
        tcpdump \
        testdisk \
        theharvester \
        tini \
        trivy \
        tshark \
        uro \
        wafw00f \
        wfuzz \
        wireshark \
        wordlists \
        wpscan \
        xsser \
        xxd \
        zaproxy \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && setcap -r /usr/lib/nmap/nmap

RUN python3 -m venv --system-site-packages /opt/drost-analysis \
    && /opt/drost-analysis/bin/python -m pip install --no-cache-dir \
        angr==10.0.0 \
        volatility3==2.28.0 \
    && python3 -m venv --system-site-packages /opt/drost-checkov \
    && /opt/drost-checkov/bin/python -m pip install --no-cache-dir checkov==3.3.20 \
    && python3 -m venv --system-site-packages /opt/drost-kube-hunter \
    && /opt/drost-kube-hunter/bin/python -m pip install --no-cache-dir kube-hunter==0.6.8 \
    && python3 -m venv --system-site-packages /opt/drost-scout \
    && /opt/drost-scout/bin/python -m pip install --no-cache-dir ScoutSuite==5.14.0 \
    && python3 -m venv --system-site-packages /opt/drost-prowler \
    && /opt/drost-prowler/bin/python -m pip install --no-cache-dir prowler

RUN gem install --no-document zsteg -v 0.2.14 \
    && gem install --no-document one_gadget -v 2.1.1

COPY --from=go-tools /out/anew /usr/local/bin/anew
COPY --from=go-tools /out/waybackurls /usr/local/bin/waybackurls
COPY --from=go-tools /out/jaeles /usr/local/bin/jaeles
COPY --from=go-tools /out/kube-bench /usr/local/bin/kube-bench
COPY --from=go-tools /out/terrascan /usr/local/bin/terrascan
COPY --from=rust-tools /usr/local/cargo/bin/x8 /usr/local/bin/x8
COPY --from=rust-tools /usr/local/cargo/bin/pwninit /usr/local/bin/pwninit
COPY --from=hashpump-tools /out/hashpump /usr/local/bin/hashpump

RUN ln -sf /opt/drost-analysis/bin/vol /usr/local/bin/vol \
    && ln -sf /opt/drost-analysis/bin/vol /usr/local/bin/volatility3 \
    && ln -sf /opt/drost-checkov/bin/checkov /usr/local/bin/checkov \
    && ln -sf /opt/drost-kube-hunter/bin/kube-hunter /usr/local/bin/kube-hunter \
    && ln -sf /opt/drost-scout/bin/scout /usr/local/bin/scout \
    && ln -sf /opt/drost-prowler/bin/prowler /usr/local/bin/prowler \
    && ln -sf /usr/bin/getallurls /usr/local/bin/gau \
    && ln -sf /usr/bin/httpx-toolkit /usr/local/bin/httpx \
    && ln -sf /usr/bin/ROPgadget /usr/local/bin/ROPgadget \
    && ln -sf /usr/bin/shodan /usr/local/bin/shodan

RUN git clone --depth 1 https://github.com/docker/docker-bench-security.git /opt/docker-bench-security \
    && ln -s /opt/docker-bench-security/docker-bench-security.sh /usr/local/bin/docker-bench-security

WORKDIR /opt/drost-ai
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python3 -m venv --system-site-packages /opt/drost-ai-venv \
    && /opt/drost-ai-venv/bin/python -m pip install --no-cache-dir --no-deps --no-build-isolation /opt/drost-ai \
    && mkdir -p /workspace

ENV PATH="/opt/drost-ai-venv/bin:/opt/drost-analysis/bin:/opt/drost-checkov/bin:/opt/drost-kube-hunter/bin:/opt/drost-scout/bin:/opt/drost-prowler/bin:${PATH}" \
    DROST_WORKSPACE=/workspace \
    PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD ["drost-mcp", "--self-test"]

VOLUME ["/workspace"]

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sleep", "infinity"]
