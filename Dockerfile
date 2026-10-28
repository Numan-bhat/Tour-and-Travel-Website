FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app

# Chromium prints quotations to PDF; DejaVu supplies the rupee sign if web fonts fail to load.
RUN apt-get update \
    && apt-get install -y --no-install-recommends chromium fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./
RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /app/instance /app/static/uploads \
    && chown -R appuser:appuser /app \
    && sed -i 's/\r$//' /app/docker-start.sh

# Starts as root only to take ownership of the mounted upload disk (UPLOAD_DIR), then runs the app as appuser.
EXPOSE 8080

CMD ["sh", "/app/docker-start.sh"]
