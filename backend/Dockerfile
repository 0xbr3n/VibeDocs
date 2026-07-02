FROM python:3.12-slim

# System deps:
#   - libreoffice for docx -> pdf
#   - fonts-liberation for proper font rendering
#   - poppler-utils for pdf operations
#   - build-essential temporarily for any wheel compilation
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        libreoffice-writer \
        libreoffice-core \
        fonts-liberation \
        fonts-dejavu \
        poppler-utils \
        curl \
        ca-certificates \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Build context is the REPO ROOT (set in docker-compose.yml), so COPY
# paths below reference `backend/<x>` for files that live under the
# backend directory and `report-templates` for the sibling folder.
# This lets the image bundle the tracker templates so
# the Risk-Register exporter has them available without depending on
# a bind mount.
COPY backend/requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y build-essential \
    && apt-get autoremove -y

COPY backend/app /app/app
COPY backend/word_templates /app/word_templates

# Bundle the bundled tracker templates so the
# image is self-contained. Without this, the tracker export silently
# falls back to a synthesised flat layout because TRACKER_TEMPLATES_DIR
# resolves to a non-existent path inside the container.
COPY report-templates /app/report-templates

# Make data dirs in case volumes aren't mounted
RUN mkdir -p /data/uploads /data/reports

EXPOSE 8000

# Use uvicorn directly. For higher load swap in gunicorn -k uvicorn.workers.UvicornWorker
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
