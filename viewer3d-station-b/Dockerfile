# Station B 3D Viewer - Dockerfile
# READ-ONLY telemetry visualization for ICS demo/awareness
# No PLC write capabilities

FROM python:3.11-slim

LABEL maintainer="ICSHUB"
LABEL description="Station B 3D Real-time Viewer (Read-Only)"
LABEL version="1.0.0"

# Security: run as non-root user
RUN useradd -m -s /bin/bash viewer && \
    mkdir -p /app/static && \
    chown -R viewer:viewer /app

WORKDIR /app

# Install dependencies
COPY --chown=viewer:viewer backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code with explicit ownership for non-root runtime
COPY --chown=viewer:viewer backend/*.py /app/
COPY --chown=viewer:viewer frontend/static/ /app/static/
RUN chmod 0644 /app/*.py /app/requirements.txt && \
    find /app/static -type f -exec chmod 0644 {} + && \
    find /app/static -type d -exec chmod 0755 {} +

# Switch to non-root user
USER viewer

# Expose port
EXPOSE 8090

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8090/api/status')" || exit 1

# Run server
CMD ["python", "telemetry_server.py", "--host", "0.0.0.0", "--port", "8090", "--static", "/app/static"]
