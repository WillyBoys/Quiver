FROM python:3.12-slim-bookworm

# Install system dependencies and pentest tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core utilities
    curl wget git netcat-openbsd dnsutils whois unzip \
    # Pentest tools available in Debian bookworm
    nmap \
    sqlmap \
    hydra \
    john \
    smbclient \
    samba-common-bin \
    snmp \
    # Ruby (needed for whatweb)
    ruby ruby-dev \
    # Build dependencies + Perl (needed for nikto)
    gcc libffi-dev libssl-dev \
    perl libnet-ssleay-perl libjson-perl libxml-writer-perl \
    && rm -rf /var/lib/apt/lists/*

# nikto (removed from Debian repos — install from GitHub)
RUN git clone --depth=1 https://github.com/sullo/nikto /opt/nikto && \
    ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# gobuster
RUN curl -L https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz \
    | tar xz -C /usr/local/bin gobuster && chmod +x /usr/local/bin/gobuster

# ffuf
RUN curl -L https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz \
    | tar xz -C /usr/local/bin ffuf && chmod +x /usr/local/bin/ffuf

# nuclei
RUN curl -L https://github.com/projectdiscovery/nuclei/releases/download/v3.2.4/nuclei_3.2.4_linux_amd64.zip \
    -o /tmp/nuclei.zip && cd /tmp && unzip nuclei.zip && mv nuclei /usr/local/bin/ && chmod +x /usr/local/bin/nuclei

# whatweb — install runtime gems only, skip bundler (Gemfile pulls heavy dev deps that need make)
RUN gem install webrick addressable && \
    git clone --depth=1 https://github.com/urbanadventurer/WhatWeb /opt/whatweb && \
    ln -sf /opt/whatweb/whatweb /usr/local/bin/whatweb && \
    chmod +x /opt/whatweb/whatweb

# enum4linux-ng (replaces the old enum4linux)
RUN git clone --depth=1 https://github.com/cddmp/enum4linux-ng /opt/enum4linux-ng && \
    pip install -r /opt/enum4linux-ng/requirements.txt --break-system-packages && \
    ln -sf /opt/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux-ng

# User-added packages — edit user-tools.txt and run: docker-compose up --build backend
COPY user-tools.txt /tmp/user-tools.txt
RUN if grep -qvE '^\s*#|^\s*$' /tmp/user-tools.txt; then \
      apt-get update && \
      grep -vE '^\s*#|^\s*$' /tmp/user-tools.txt | sed 's/\s*#.*//' | xargs apt-get install -y --no-install-recommends && \
      rm -rf /var/lib/apt/lists/*; \
    fi

# SpiSuite (requires Go 1.24.5 — apt golang is too old, install from official release)
RUN curl -L https://go.dev/dl/go1.24.5.linux-amd64.tar.gz | tar xz -C /usr/local && \
    git clone --depth=1 https://github.com/waffl3ss/SpiSuite.git /opt/SpiSuite && \
    cd /opt/SpiSuite && \
    CGO_ENABLED=0 /usr/local/go/bin/go build -o /usr/local/bin/spisuite . && \
    rm -rf /usr/local/go

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /wordlists

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
