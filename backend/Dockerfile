FROM kalilinux/kali-rolling

# Python runtime + core utilities + all Kali-packaged pentest tools in one apt layer.
# Kali rolling gives us most tools via apt, eliminating the manual binary downloads,
# Go compilation, and Ruby gem chains required on the old Debian base.
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Python
    python3 python3-pip python3-venv \
    # Core utilities
    curl wget git netcat-openbsd dnsutils whois unzip \
    # Web testing
    nikto gobuster ffuf nuclei feroxbuster dirb \
    whatweb wafw00f sqlmap wpscan cewl \
    # Network / SSL
    nmap sslscan \
    # SMB / Active Directory / SNMP
    smbclient samba-common-bin snmp enum4linux-ng \
    # Password attacks
    hydra john \
    # Recon & exploit research
    dnsrecon exploitdb \
    # Impacket suite (impacket-secretsdump, impacket-smbexec, etc.)
    python3-impacket \
    && rm -rf /var/lib/apt/lists/*

# kerbrute — not in Kali apt; grab the release binary (graceful: skips on network failure)
RUN curl -fL --retry 3 --retry-delay 2 \
    "https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64" \
    -o /usr/local/bin/kerbrute && chmod +x /usr/local/bin/kerbrute \
    || echo "WARNING: kerbrute download failed — binary will not be available"

# SpiSuite — not in Kali; build from source
RUN curl -L https://go.dev/dl/go1.24.5.linux-amd64.tar.gz | tar xz -C /usr/local && \
    git clone --depth=1 https://github.com/waffl3ss/SpiSuite.git /opt/SpiSuite && \
    cd /opt/SpiSuite && \
    CGO_ENABLED=0 /usr/local/go/bin/go build -o /usr/local/bin/spisuite . && \
    rm -rf /usr/local/go

# trufflehog — not in Kali; official install script
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /usr/local/bin

# cloud_enum — not in Kali
RUN git clone --depth=1 https://github.com/initstring/cloud_enum /opt/cloud_enum && \
    pip install --no-cache-dir --break-system-packages dnspython requests requests-futures && \
    printf '#!/bin/sh\nexec python3 /opt/cloud_enum/cloud_enum.py "$@"\n' \
        > /usr/local/bin/cloud_enum && chmod +x /usr/local/bin/cloud_enum

# Thin wrapper scripts — each gives the agent a distinct binary name for a common
# curl/nc pattern, letting the seed add them as separate auto-approved tools without
# changing the binary-keyed tool-prompt logic.
RUN printf '#!/bin/sh\nexec curl -si --max-time 15 "$@"\n'                                                         > /usr/local/bin/curl-probe   && \
    printf '#!/bin/sh\nexec curl -sI --max-time 10 "$@"\n'                                                         > /usr/local/bin/curl-headers && \
    printf '#!/bin/sh\nexec curl -si -X OPTIONS -H "Origin: https://evil.com" -H "Access-Control-Request-Method: GET" --max-time 10 "$@"\n' \
                                                                                                                    > /usr/local/bin/curl-cors    && \
    printf '#!/bin/sh\nexec curl -si -H "Accept: application/json" --max-time 15 "$@"\n'                          > /usr/local/bin/curl-json    && \
    printf '#!/bin/sh\nexec curl -siL --max-time 15 "$@"\n'                                                        > /usr/local/bin/curl-redirect && \
    printf '#!/bin/sh\nexec nc -nv -w 5 "$@"\n'                                                                    > /usr/local/bin/nc-banner    && \
    chmod +x /usr/local/bin/curl-probe /usr/local/bin/curl-headers /usr/local/bin/curl-cors \
             /usr/local/bin/curl-json /usr/local/bin/curl-redirect /usr/local/bin/nc-banner

# User-added apt packages — edit user-tools.txt and run: docker-compose up --build backend
COPY user-tools.txt /tmp/user-tools.txt
RUN if grep -qvE '^\s*#|^\s*$' /tmp/user-tools.txt; then \
      apt-get update && \
      grep -vE '^\s*#|^\s*$' /tmp/user-tools.txt | sed 's/\s*#.*//' | xargs apt-get install -y --no-install-recommends && \
      rm -rf /var/lib/apt/lists/*; \
    fi

# User-added pip packages — edit user-pip.txt and run: docker-compose up --build backend
COPY user-pip.txt /tmp/user-pip.txt
RUN if grep -qvE '^\s*#|^\s*$' /tmp/user-pip.txt; then \
      grep -vE '^\s*#|^\s*$' /tmp/user-pip.txt | sed 's/\s*#.*//' | \
      xargs pip install --no-cache-dir --break-system-packages; \
    fi

# pip tools not packaged in Kali
RUN pip install --no-cache-dir --break-system-packages \
    bbot

WORKDIR /app

# Use a virtualenv at /opt/venv — outside /app so the host volume mount doesn't wipe it.
# Kali's system Python has pentest tool deps (uvicorn, fastapi, etc.) installed as apt
# packages; isolating here prevents version conflicts.
COPY requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

ENV PATH="/opt/venv/bin:$PATH"

COPY . .

RUN mkdir -p /wordlists

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
