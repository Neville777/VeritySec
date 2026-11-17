# VeritySec tool sandbox image.
# Build: docker build -t veritysec-tools:latest docker/tools

# ---- Stage 1: Go tools, pinned versions ----
FROM golang:1.25-bookworm AS gobuild
ENV CGO_ENABLED=1 GOBIN=/out
RUN go install github.com/projectdiscovery/katana/cmd/katana@v1.1.0 
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.6 
RUN go install github.com/hahwul/dalfox/v2@v2.9.2 
RUN go install github.com/lc/gau/v2/cmd/gau@v2.2.3 
RUN go install github.com/tomnomnom/waybackurls@v0.1.0 
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.2.9

# ---- Stage 2: final image ----
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates nmap sqlmap gobuster ffuf dirsearch wafw00f \
        dnsenum nbtscan arp-scan masscan \
        python3 python3-venv python3-pip \
    && python3 -m venv /opt/tools/venv \
    && /opt/tools/venv/bin/pip install --no-cache-dir arjun \
    && mkdir -p /opt/tools/bin \
    && ln -s /opt/tools/venv/bin/arjun /opt/tools/bin/arjun \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=gobuild /out/ /usr/local/bin/

# Bake official nuclei templates at build time (rebuild the image to refresh them).
# NUCLEI_CONFIG_DIR keeps nuclei's config (which records the templates dir) off $HOME,
# because the sandbox mounts /tmp (HOME) as an empty tmpfs.
ENV NUCLEI_CONFIG_DIR=/opt/nuclei-config
RUN nuclei -update-templates -update-template-dir /opt/nuclei-templates \
    && chmod -R a+rX /opt/nuclei-templates /opt/nuclei-config

ENV HOME=/tmp
ENV PATH=/usr/local/bin:/opt/tools/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin tools

WORKDIR /work
USER 10001:10001

ENTRYPOINT ["/usr/bin/env"]
