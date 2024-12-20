FROM python:3.9-slim

WORKDIR /app

# Install system dependencies required for pandas and cryptography (needed by msal)
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install requirements first to cache the layer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create migrations directory and initialize if needed
RUN mkdir -p migrations/versions

# Create a startup script that handles migrations and session directory
RUN echo '#!/bin/bash\n\
mkdir -p flask_session\n\
if [ ! -f migrations/versions/*.py ]; then\n\
    flask db init || true\n\
    flask db migrate -m "Initial migration" || true\n\
fi\n\
flask db upgrade\n\
exec gunicorn --bind 0.0.0.0:8080 --log-level debug --timeout 120 app:app' > /app/start.sh

RUN chmod +x /app/start.sh

EXPOSE 8080

CMD ["/app/start.sh"] 