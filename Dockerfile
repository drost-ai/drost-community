# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.26-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS go-tools

ARG TARGETOS
ARG TARGETARCH
ARG ANEW_VERSION=v0.1.1
ARG JAELES_VERSION=v0.0.0-20260620125341-d40305ffe42a
ARG KUBE_BENCH_VERSION=v0.16.0
ARG URLFINDER_VERSION=v0.0.3
ARG SUBZY_VERSION=v1.2.1

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install github.com/tomnomnom/anew@$ANEW_VERSION \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@$URLFINDER_VERSION \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install github.com/PentestPad/subzy@$SUBZY_VERSION \
    && mkdir -p /out \
    && find /go/bin -type f -name anew -exec cp {} /out/anew \; \
    && find /go/bin -type f -name urlfinder -exec cp {} /out/urlfinder \; \
    && find /go/bin -type f -name subzy -exec cp {} /out/subzy \;

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install github.com/jaeles-project/jaeles@$JAELES_VERSION \
    && find /go/bin -type f -name jaeles -exec cp {} /out/jaeles \;

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install github.com/aquasecurity/kube-bench@$KUBE_BENCH_VERSION \
    && find /go/bin -type f -name kube-bench -exec cp {} /out/kube-bench \;

RUN git clone --depth 1 --branch v1.19.9 https://github.com/tenable/terrascan.git /src/terrascan \
    && cd /src/terrascan \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/terrascan ./cmd/terrascan

RUN --mount=type=cache,target=/go/pkg/mod \
    mkdir -p /out/licenses/go-modules \
    && cd /go/pkg/mod \
    && find . -type f \
        \( -iname 'LICENSE' -o -iname 'LICENSE.*' -o -iname 'COPYING' -o -iname 'COPYING.*' -o -iname 'NOTICE' -o -iname 'NOTICE.*' \) \
        -exec cp --parents {} /out/licenses/go-modules/ \; \
    && mkdir -p /out/licenses/terrascan \
    && cp /src/terrascan/LICENSE /out/licenses/terrascan/LICENSE

FROM --platform=$TARGETPLATFORM rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS rust-tools

ARG X8_VERSION=4.3.2
ARG PWNINIT_VERSION=3.3.3

RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/usr/local/cargo/git \
    cargo install --version "$X8_VERSION" x8 \
    && cargo install --locked --version "$PWNINIT_VERSION" pwninit \
    && mkdir -p /out/licenses/rust-crates \
    && cd /usr/local/cargo \
    && find registry/src -type f \
        \( -iname 'LICENSE' -o -iname 'LICENSE.*' -o -iname 'COPYING' -o -iname 'COPYING.*' -o -iname 'NOTICE' -o -iname 'NOTICE.*' \) \
        -exec cp --parents {} /out/licenses/rust-crates/ \; \
    && if [ -d git/checkouts ]; then \
        find git/checkouts -type f \
            \( -iname 'LICENSE' -o -iname 'LICENSE.*' -o -iname 'COPYING' -o -iname 'COPYING.*' -o -iname 'NOTICE' -o -iname 'NOTICE.*' \) \
            -exec cp --parents {} /out/licenses/rust-crates/ \; ; \
    fi

FROM --platform=$TARGETPLATFORM debian:bookworm@sha256:2c037a04925515fdd6ea85ea14a682d0e79931f5e9f5d07b6dbfc6ba12f9e858 AS hashpump-tools

ARG HASHPUMP_COMMIT=b822764fa71209858c91378736d43d082c674e96

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates g++ git libssl-dev make \
    && git clone --depth 1 https://github.com/mheistermann/HashPump-partialhash.git /src/hashpump \
    && git -C /src/hashpump fetch --depth 1 origin "$HASHPUMP_COMMIT" \
    && git -C /src/hashpump checkout --detach "$HASHPUMP_COMMIT" \
    && make -C /src/hashpump \
    && mkdir -p /out/licenses/hashpump \
    && cp /src/hashpump/hashpump /out/hashpump \
    && cp /src/hashpump/LICENSE.TXT /out/licenses/hashpump/LICENSE.TXT

FROM kalilinux/kali-last-release:latest@sha256:3ea545e38849417fc933514e117014b98aa42fd87d239177fa4c9874dcb73d5f

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        aapt \
        adb \
        aircrack-ng \
        amass \
        apksigner \
        arjun \
        arp-scan \
        autopsy \
        autorecon \
        binutils \
        binwalk \
        bulk-extractor \
        ca-certificates \
        checksec \
        curl \
        dalfox \
        default-jre-headless \
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
        jq \
        katana \
        kismet \
        libcap2-bin \
        libimage-exiftool-perl \
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
        nodejs \
        node-playwright \
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
        python3-playwright \
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
        unzip \
        uro \
        wafw00f \
        whatweb \
        wfuzz \
        wireshark \
        wordlists \
        xsser \
        xxd \
        xz-utils \
        zaproxy \
        zipalign \
        chromium \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && setcap -r /usr/lib/nmap/nmap

# Android debugging toolchain. Pinned upstream builds are used because the
# Debian apktool package hangs on Android 15 APKs and its JADX package is older
# than the APK format support needed here.
ARG APKTOOL_VERSION=3.0.3
ARG APKTOOL_SHA256=dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423
ARG JADX_VERSION=1.5.6
ARG JADX_SHA256=545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974
ARG FRIDA_VERSION=17.24.3
ARG FRIDA_SERVER_ARM64_SHA256=a56beefc862e5cc6d02ba9a6203cc98057839c2097a62f8eaba867eb537b6d12
ARG FRIDA_SERVER_X86_64_SHA256=44aead87103ab9738771e5eff659640fb6bf566fe83b8629444c1be99f87ce68

RUN mkdir -p /opt/drost-android/apktool /opt/drost-android/jadx /opt/drost-android/frida \
        /usr/share/drost/licenses/android/apktool \
        /usr/share/drost/licenses/android/jadx \
        /usr/share/drost/licenses/android/frida \
    && curl -fsSL -o /tmp/apktool.jar "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" \
    && echo "${APKTOOL_SHA256}  /tmp/apktool.jar" | sha256sum -c - \
    && mv /tmp/apktool.jar /opt/drost-android/apktool/apktool.jar \
    && curl -fsSL -o /tmp/jadx.zip "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
    && echo "${JADX_SHA256}  /tmp/jadx.zip" | sha256sum -c - \
    && unzip -q /tmp/jadx.zip -d /opt/drost-android/jadx \
    && chmod 0755 /opt/drost-android/jadx/bin/jadx \
    && rm -f /tmp/jadx.zip \
    && curl -fsSL -o /tmp/frida-server-arm64.xz "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-arm64.xz" \
    && echo "${FRIDA_SERVER_ARM64_SHA256}  /tmp/frida-server-arm64.xz" | sha256sum -c - \
    && xz -dc /tmp/frida-server-arm64.xz > /opt/drost-android/frida/frida-server-arm64-v8a \
    && curl -fsSL -o /tmp/frida-server-x86_64.xz "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-x86_64.xz" \
    && echo "${FRIDA_SERVER_X86_64_SHA256}  /tmp/frida-server-x86_64.xz" | sha256sum -c - \
    && xz -dc /tmp/frida-server-x86_64.xz > /opt/drost-android/frida/frida-server-x86_64 \
    && rm -f /tmp/frida-server-*.xz \
    && chmod 0755 /opt/drost-android/frida/frida-server-* \
    && printf '#!/bin/sh\nexec java -Xmx2g -jar /opt/drost-android/apktool/apktool.jar "$@"\n' > /usr/local/bin/apktool \
    && chmod 0755 /usr/local/bin/apktool \
    && ln -sf /opt/drost-android/jadx/bin/jadx /usr/local/bin/jadx \
    && unzip -p /opt/drost-android/apktool/apktool.jar LICENSE > /usr/share/drost/licenses/android/apktool/LICENSE \
    && cp /opt/drost-android/jadx/LICENSE /usr/share/drost/licenses/android/jadx/LICENSE \
    && curl -fsSL -o /usr/share/drost/licenses/android/frida/COPYING "https://raw.githubusercontent.com/frida/frida/${FRIDA_VERSION}/COPYING"

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
    && /opt/drost-prowler/bin/python -m pip install --no-cache-dir prowler==3.11.3

RUN gem install --no-document zsteg -v 0.2.14 \
    && gem install --no-document one_gadget -v 2.1.1

COPY --from=go-tools /out/anew /usr/local/bin/anew
COPY --from=go-tools /out/urlfinder /usr/local/bin/urlfinder
COPY --from=go-tools /out/subzy /usr/local/bin/subzy
COPY --from=go-tools /out/jaeles /usr/local/bin/jaeles
COPY --from=go-tools /out/kube-bench /usr/local/bin/kube-bench
COPY --from=go-tools /out/terrascan /usr/local/bin/terrascan
COPY --from=go-tools /out/licenses /usr/share/drost/licenses/go
COPY --from=rust-tools /usr/local/cargo/bin/x8 /usr/local/bin/x8
COPY --from=rust-tools /usr/local/cargo/bin/pwninit /usr/local/bin/pwninit
COPY --from=rust-tools /out/licenses /usr/share/drost/licenses/rust
COPY --from=hashpump-tools /out/hashpump /usr/local/bin/hashpump
COPY --from=hashpump-tools /out/licenses /usr/share/drost/licenses/hashpump

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

ARG DOCKER_BENCH_COMMIT=154869da6418089decf7e1ab0cfca0e1cdfc5c49

RUN git clone --depth 1 https://github.com/docker/docker-bench-security.git /opt/docker-bench-security \
    && git -C /opt/docker-bench-security fetch --depth 1 origin "$DOCKER_BENCH_COMMIT" \
    && git -C /opt/docker-bench-security checkout --detach "$DOCKER_BENCH_COMMIT" \
    && rm -rf /opt/docker-bench-security/.git \
    && mkdir -p /usr/share/drost/licenses/docker-bench-security \
    && cp /opt/docker-bench-security/LICENSE.md /usr/share/drost/licenses/docker-bench-security/LICENSE.md \
    && ln -s /opt/docker-bench-security/docker-bench-security.sh /usr/local/bin/docker-bench-security

WORKDIR /opt/drost-ai
COPY pyproject.toml README.md LICENSE THIRD_PARTY_NOTICES.md SOURCE_OFFER.md ./
COPY src ./src

RUN python3 -m venv --system-site-packages /opt/drost-ai-venv \
    && /opt/drost-ai-venv/bin/python -m pip install --no-cache-dir --ignore-installed playwright==1.55.0 \
    && /opt/drost-ai-venv/bin/python -m pip install --no-cache-dir \
        frida==17.24.3 \
        frida-tools==14.11.0 \
        objection==1.12.5 \
        androguard==4.1.4 \
    && /opt/drost-ai-venv/bin/python -m pip install --no-cache-dir --no-deps --no-build-isolation /opt/drost-ai \
    && mkdir -p /workspace /usr/share/drost/licenses/drost-ai /usr/share/drost/licenses/android/python \
    && cp LICENSE THIRD_PARTY_NOTICES.md SOURCE_OFFER.md /usr/share/drost/licenses/drost-ai/ \
    && for dist in /opt/drost-ai-venv/lib/python*/site-packages/*.dist-info; do \
         case "$(basename "$dist")" in \
           frida-*|frida_tools-*|objection-*|androguard-*) \
             cp -r "$dist" /usr/share/drost/licenses/android/python/ ;; \
         esac; \
       done

LABEL org.opencontainers.image.licenses="Apache-2.0 AND LicenseRef-Drost-Third-Party"

ENV PATH="/opt/drost-ai-venv/bin:/opt/drost-analysis/bin:/opt/drost-checkov/bin:/opt/drost-kube-hunter/bin:/opt/drost-scout/bin:/opt/drost-prowler/bin:${PATH}" \
    DROST_WORKSPACE=/workspace \
    PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD ["drost-mcp", "--self-test"]

VOLUME ["/workspace"]

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sleep", "infinity"]
