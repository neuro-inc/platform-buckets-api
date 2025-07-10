FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Python version and dependency files
COPY pyproject.toml .
COPY poetry.lock ./

RUN pip install poetry==2.1.3

# Install Python dependencies
RUN poetry install --only main

# Copy application code
COPY src src

# Create non-root user for security
# RUN useradd --create-home --shell /bin/bash app \
#     && chown -R app:app /app

# USER app

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:80/healthz || exit 1

# Run the application
CMD ["poetry", "run", "uvicorn", "src.main:app", "--host", "0.0.0", "--port", "8000"]
