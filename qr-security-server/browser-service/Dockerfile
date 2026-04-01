FROM mcr.microsoft.com/playwright/python:v1.52.0-noble

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers (Chromium only)
RUN playwright install chromium

COPY server.py .

# Run as non-root for security
RUN useradd -m -s /bin/bash appuser && \
    chown -R appuser:appuser /app
USER appuser

EXPOSE 3000

ENV PORT=3000
ENV PAGE_TIMEOUT_MS=12000

CMD ["python", "server.py"]
