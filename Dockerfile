FROM python:3.10-slim

LABEL maintainer="Nexus Security Scanner"
LABEL description="AI-powered multi-vulnerability scanner"
LABEL version="1.0.0"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep
RUN pip install semgrep --no-cache-dir

WORKDIR /app

# Copy requirements first (Docker layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Create directories
RUN mkdir -p .nexus_cache outputs

# Environment variables
ENV NEXUS_API_KEY=""
ENV NEXUS_BASE_URL=""
ENV NEXUS_MODEL="mimo-v2.5-pro-max"
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import perception.encoder; print('ok')" || exit 1

# Default entrypoint
ENTRYPOINT ["python", "main_p4.py"]
CMD ["--help"]
