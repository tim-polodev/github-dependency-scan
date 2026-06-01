FROM eclipse-temurin:17-jre-focal

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install core utilities: Git, Python3, Pip, Curl, Unzip, Nodejs, Npm
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    python3 \
    python3-pip \
    python3-setuptools \
    curl \
    unzip \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Download and install OWASP Dependency-Check CLI
ENV ODC_VERSION=12.2.2
RUN curl -sSL https://github.com/dependency-check/DependencyCheck/releases/download/v${ODC_VERSION}/dependency-check-${ODC_VERSION}-release.zip -o /tmp/odc.zip \
    && unzip /tmp/odc.zip -d /usr/share \
    && rm /tmp/odc.zip \
    && ln -s /usr/share/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check.sh

# Prepare workspace directory
WORKDIR /app

# Copy and install python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r /app/requirements.txt

# Setup application files
COPY scan.py /app/scan.py
RUN chmod +x /app/scan.py

# Create a non-root system user and prepare writable data directory for vulnerability cache
RUN useradd -u 1000 -m -s /bin/bash scanner \
    && mkdir -p /data \
    && chown -R scanner:scanner /data /app

# Switch to non-root user
USER 1000:1000

# Set database location environment variable default
ENV DATA_DIR=/data

# Start the python scanner orchestrator
ENTRYPOINT ["python3", "scan.py"]
