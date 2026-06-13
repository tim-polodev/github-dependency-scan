FROM eclipse-temurin:17-jre-jammy

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install core utilities and setup deadsnakes PPA for multiple Python versions
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    unzip \
    software-properties-common \
    gnupg2 \
    ca-certificates \
    && add-apt-repository -y ppa:deadsnakes/ppa \
    && apt-get update && apt-get install -y --no-install-recommends \
    python3-pip \
    python3-setuptools \
    python3-venv \
    python3-dev \
    python3.8 python3.8-venv python3.8-dev \
    python3.9 python3.9-venv python3.9-dev \
    python3.11 python3.11-venv python3.11-dev \
    python3.12 python3.12-venv python3.12-dev \
    && rm -rf /var/lib/apt/lists/*

# Download and install OWASP Dependency-Check CLI
ENV ODC_VERSION=12.2.2
RUN curl -sSL https://github.com/dependency-check/DependencyCheck/releases/download/v${ODC_VERSION}/dependency-check-${ODC_VERSION}-release.zip -o /tmp/odc.zip \
    && unzip /tmp/odc.zip -d /usr/share \
    && rm /tmp/odc.zip \
    && ln -s /usr/share/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check.sh

# Prepare workspace directory
WORKDIR /app

# Copy and install python dependencies (for the main orchestrator script)
COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r /app/requirements.txt

# Setup application files
COPY scanner/ /app/scanner/

# Create a non-root system user and prepare writable data directory
RUN useradd -u 1000 -m -s /bin/bash scanner \
    && mkdir -p /data \
    && chown -R scanner:scanner /data /app

# Switch to non-root user
USER 1000:1000

# Install NVM (Node Version Manager) and default Node 20.11.1
ENV NVM_DIR=/home/scanner/.nvm
RUN mkdir -p $NVM_DIR \
    && curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash \
    && . $NVM_DIR/nvm.sh \
    && nvm install 20.11.1 \
    && nvm alias default 20.11.1 \
    && nvm use default

# Add default Node version to PATH so node/npm are available by default
ENV PATH=/home/scanner/.nvm/versions/node/v20.11.1/bin:$PATH
ENV DATA_DIR=/data

# Start the python scanner orchestrator
ENTRYPOINT ["python3", "-m", "scanner"]
