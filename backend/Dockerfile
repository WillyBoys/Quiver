FROM python:3.13-slim-bookworm

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
    sslscan \
    # Ruby (needed for whatweb, wpscan, cewl)
    ruby ruby-dev \
    # Build dependencies + Perl (needed for nikto, wpscan native gems)
    gcc make libc6-dev libffi-dev libssl-dev \
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

# User-added pip packages — edit user-pip.txt and run: docker-compose up --build backend
COPY user-pip.txt /tmp/user-pip.txt
RUN if grep -qvE '^\s*#|^\s*$' /tmp/user-pip.txt; then \
      grep -vE '^\s*#|^\s*$' /tmp/user-pip.txt | sed 's/\s*#.*//' | \
      xargs pip install --no-cache-dir --break-system-packages; \
    fi

# SpiSuite (requires Go 1.24.5 — apt golang is too old, install from official release)
RUN curl -L https://go.dev/dl/go1.24.5.linux-amd64.tar.gz | tar xz -C /usr/local && \
    git clone --depth=1 https://github.com/waffl3ss/SpiSuite.git /opt/SpiSuite && \
    cd /opt/SpiSuite && \
    CGO_ENABLED=0 /usr/local/go/bin/go build -o /usr/local/bin/spisuite . && \
    rm -rf /usr/local/go

# feroxbuster
RUN curl -L "https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip" \
    -o /tmp/ferox.zip && \
    cd /tmp && unzip ferox.zip feroxbuster && \
    mv /tmp/feroxbuster /usr/local/bin/feroxbuster && \
    chmod +x /usr/local/bin/feroxbuster && \
    rm /tmp/ferox.zip

# kerbrute
RUN curl -L "https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64" \
    -o /usr/local/bin/kerbrute && chmod +x /usr/local/bin/kerbrute

# trufflehog (install script resolves versioned release asset automatically)
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /usr/local/bin

# wpscan — pre-build nokogiri with system libxml2 to skip bundled source compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libxml2-dev libxslt1-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/* \
    && gem install nokogiri -- --use-system-libraries \
    && gem install wpscan

# cewl — not on RubyGems; install via git clone
RUN git clone --depth=1 https://github.com/digininja/CeWL /opt/cewl && \
    cd /opt/cewl && \
    gem install bundler && \
    bundle config build.nokogiri --use-system-libraries && \
    bundle install && \
    ln -sf /opt/cewl/cewl.rb /usr/local/bin/cewl && \
    chmod +x /opt/cewl/cewl.rb

# pip-based tools
RUN pip install --no-cache-dir --break-system-packages \
    wafw00f \
    dnsrecon \
    impacket \
    bbot \
    subdominator


# searchsploit / exploit-db
RUN git clone --depth=1 https://gitlab.com/exploit-database/exploitdb /opt/exploitdb && \
    ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

# cloud_enum
RUN git clone --depth=1 https://github.com/initstring/cloud_enum /opt/cloud_enum && \
    pip install --no-cache-dir --break-system-packages dnspython requests requests-futures && \
    printf '#!/bin/sh\nexec python3 /opt/cloud_enum/cloud_enum.py "$@"\n' \
        > /usr/local/bin/cloud_enum && chmod +x /usr/local/bin/cloud_enum

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /wordlists

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
