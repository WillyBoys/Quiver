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
    snmp \
    # Build dependencies + Perl (needed for nikto)
    gcc libffi-dev libssl-dev \
    perl libnet-ssleay-perl libjson-perl libxml-writer-perl \
    && rm -rf /var/lib/apt/lists/*

# nikto (removed from Debian repos — install from GitHub)
RUN git clone --depth=1 https://github.com/sullo/nikto /opt/nikto && \
    ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl || true

# gobuster
RUN curl -L https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz \
    | tar xz -C /usr/local/bin gobuster && chmod +x /usr/local/bin/gobuster || true

# ffuf
RUN curl -L https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz \
    | tar xz -C /usr/local/bin ffuf && chmod +x /usr/local/bin/ffuf || true

# nuclei
RUN curl -L https://github.com/projectdiscovery/nuclei/releases/download/v3.2.4/nuclei_3.2.4_linux_amd64.zip \
    -o /tmp/nuclei.zip && cd /tmp && unzip nuclei.zip && mv nuclei /usr/local/bin/ && chmod +x /usr/local/bin/nuclei || true

# whatweb
RUN apt-get update && apt-get install -y --no-install-recommends ruby ruby-dev && \
    rm -rf /var/lib/apt/lists/* && \
    gem install whatweb || true

# enum4linux-ng (replaces the old enum4linux)
RUN git clone --depth=1 https://github.com/cddmp/enum4linux-ng /opt/enum4linux-ng && \
    pip install -r /opt/enum4linux-ng/requirements.txt --break-system-packages && \
    ln -sf /opt/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux-ng || true

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /wordlists

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
