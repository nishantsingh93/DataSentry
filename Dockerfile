# Multi-stage build for optimized production image
FROM python:3.11-slim as builder

# Set build arguments
ARG BUILD_DATE
ARG VERSION=0.1.0
ARG REVISION

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libc6-dev \
    libffi-dev \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt

# Download spaCy model
RUN python -m spacy download en_core_web_sm

# Production stage
FROM python:3.11-slim as production

# Set labels
LABEL maintainer="DataSentry Team" \
      version="${VERSION}" \
      description="PII Guardrail Tool for AI Agent Interactions" \
      build-date="${BUILD_DATE}" \
      revision="${REVISION}"

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r datasentry && useradd -r -g datasentry -u 1000 datasentry

# Copy Python packages from builder
COPY --from=builder /root/.local /home/datasentry/.local

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=datasentry:datasentry datasentry/ ./datasentry/
COPY --chown=datasentry:datasentry config/ ./config/
COPY --chown=datasentry:datasentry setup.py .
COPY --chown=datasentry:datasentry pyproject.toml .
COPY --chown=datasentry:datasentry README.md .

# Create necessary directories
RUN mkdir -p /app/logs /app/cache /app/data \
    && chown -R datasentry:datasentry /app

# Switch to non-root user
USER datasentry

# Set Python path
ENV PATH="/home/datasentry/.local/bin:${PATH}"
ENV PYTHONPATH="/app:${PYTHONPATH}"

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV API_HOST=0.0.0.0
ENV API_PORT=8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Expose ports
EXPOSE 8000 8080

# Default command
CMD ["python", "-m", "datasentry.api.app"]