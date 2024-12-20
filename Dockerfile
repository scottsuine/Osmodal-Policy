FROM python:3.9-slim

WORKDIR /app

# Install system dependencies required for pandas, cryptography, and other packages
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    libffi-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install requirements first to cache the layer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir msal flask-session python-dotenv

# Copy the rest of the application
COPY . .

# Create migrations directory and initialize if needed
RUN mkdir -p migrations/versions \
    && mkdir -p flask_session

# Create a startup script that handles migrations
RUN echo '#!/bin/bash\n\
if [ ! -f migrations/versions/*.py ]; then\n\
    flask db init || true\n\
    flask db migrate -m "Initial migration" || true\n\
fi\n\
flask db upgrade\n\
exec gunicorn --bind 0.0.0.0:8080 --log-level debug --timeout 120 app:app' > /app/start.sh \
    && chmod +x /app/start.sh

EXPOSE 8080

CMD ["/app/start.sh"]