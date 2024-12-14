FROM python:3.9-slim

WORKDIR /app

# Install system dependencies required for pandas
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Create migrations directory and initialize if needed
RUN mkdir -p migrations/versions

# Create a startup script that handles migrations
RUN echo '#!/bin/bash\n\
if [ ! -f migrations/versions/*.py ]; then\n\
    flask db init || true\n\
    flask db migrate -m "Initial migration" || true\n\
fi\n\
flask db upgrade\n\
exec gunicorn --bind 0.0.0.0:8080 --log-level debug --timeout 120 app:app' > /app/start.sh

RUN chmod +x /app/start.sh

EXPOSE 8080

CMD ["/app/start.sh"] 