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
    # Impacket (apt subset kept because netexec/smbmap/certipy-ad declare it as a dep)
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

# nxc protocol wrappers — nxc SMB/LDAP/WinRM/MSSQL/RDP each get their own binary
# so all five variants appear in the agent prompt independently (dedup is by binary name).
RUN printf '#!/bin/sh\nexec nxc smb "$@"\n'   > /usr/local/bin/nxc-smb   && \
    printf '#!/bin/sh\nexec nxc ldap "$@"\n'  > /usr/local/bin/nxc-ldap  && \
    printf '#!/bin/sh\nexec nxc winrm "$@"\n' > /usr/local/bin/nxc-winrm && \
    printf '#!/bin/sh\nexec nxc mssql "$@"\n' > /usr/local/bin/nxc-mssql && \
    printf '#!/bin/sh\nexec nxc rdp "$@"\n'   > /usr/local/bin/nxc-rdp   && \
    chmod +x /usr/local/bin/nxc-smb /usr/local/bin/nxc-ldap \
             /usr/local/bin/nxc-winrm /usr/local/bin/nxc-mssql /usr/local/bin/nxc-rdp

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

# nmap-sweep — host discovery (ping sweep) gets its own binary so it doesn't collide
# with nmap service-scan entries in the agent prompt dedup.
# nuclei-network — network protocol CVE templates for internal host scanning.
RUN printf '#!/bin/sh\nexec nmap -sn "$@"\n'                                           > /usr/local/bin/nmap-sweep     && \
    printf '#!/bin/sh\nexec nuclei -t network/ -severity medium,high,critical "$@"\n' > /usr/local/bin/nuclei-network && \
    chmod +x /usr/local/bin/nmap-sweep /usr/local/bin/nuclei-network

# ── pipx ──────────────────────────────────────────────────────────────────────
# pipx installs each Python CLI tool in its own isolated virtualenv and symlinks
# the binary into PIPX_BIN_DIR. Tools never share Python packages with each other
# or with apt, so adding a new tool can never break an existing one.
ENV PIPX_HOME=/opt/pipx
ENV PIPX_BIN_DIR=/usr/local/bin
RUN pip install --no-cache-dir --break-system-packages pipx

# User-added apt packages — edit user-tools.txt and run: docker-compose up --build backend
COPY user-tools.txt /tmp/user-tools.txt
RUN if grep -qvE '^\s*#|^\s*$' /tmp/user-tools.txt; then \
      apt-get update && \
      grep -vE '^\s*#|^\s*$' /tmp/user-tools.txt | sed 's/\s*#.*//' | xargs apt-get install -y --no-install-recommends && \
      rm -rf /var/lib/apt/lists/*; \
    fi

# User-added Python tools — edit user-pip.txt and run: docker-compose up --build backend
# Each package is installed via pipx into its own isolated venv. Use pip package names
# or git+ URLs. No dependency conflicts are possible between tools.
COPY user-pip.txt /tmp/user-pip.txt
RUN if grep -qvE '^\s*#|^\s*$' /tmp/user-pip.txt; then \
      grep -vE '^\s*#|^\s*$' /tmp/user-pip.txt | sed 's/\s*#.*//' | \
      while IFS= read -r pkg; do \
        pipx install "$pkg" || echo "WARNING: pipx install $pkg failed, continuing"; \
      done; \
    fi

# Built-in Python tools not in Kali apt ──────────────────────────────────────

# bbot — recursive attack surface mapping
RUN pipx install bbot

# certipy-ad — ADCS enumeration and ESC1-8 exploitation
RUN pipx install certipy-ad

# ldapdomaindump — structured AD object dump (users, groups, OUs, GPOs, computers)
RUN pipx install ldapdomaindump

# Full impacket suite (40+ scripts). The apt python3-impacket only ships ~5.
# impacket's pip package names scripts as GetNPUsers.py etc. rather than the
# canonical impacket-GetNPUsers form — create symlinks so the agent finds them.
RUN pipx install impacket && \
    for f in GetNPUsers GetUserSPNs psexec smbexec wmiexec lookupsid \
              findDelegation ntlmrelayx secretsdump Get-GPPPassword GetLAPSPassword; do \
      src="${PIPX_HOME}/venvs/impacket/bin/${f}.py"; \
      [ -f "$src" ] && ln -sf "$src" "${PIPX_BIN_DIR}/impacket-${f}" || true; \
    done

# ── App venv ──────────────────────────────────────────────────────────────────
# The FastAPI backend runs in its own venv, fully isolated from all pentest tools.
WORKDIR /app

COPY requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

ENV PATH="/opt/venv/bin:$PATH"

COPY . .

RUN mkdir -p /wordlists

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
