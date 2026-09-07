# =============================================================================
# Aegis Threat
# Multi-stage build: compile the frontend, then serve it from the FastAPI app.
# =============================================================================

# ---------------------
# Stage 1: Build Frontend
# ---------------------
FROM node:22-alpine AS frontend-build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY index.html vite.config.js tailwind.config.js postcss.config.js ./
COPY src/ ./src/
COPY public/ ./public/

# Same-origin in production, so the API base stays empty.
ENV VITE_API_URL=""
RUN npm run build

# ---------------------
# Stage 2: Fetch models
# ---------------------
# Downloading is confined to this stage. The runtime image loads models offline,
# so anything not baked in here degrades to a fallback rather than reaching the
# network mid-analysis.
FROM python:3.11-slim AS model-cache

WORKDIR /build
ENV AEGIS_THREAT_MODEL_CACHE=/opt/aegis/models \
    AEGIS_THREAT_ALLOW_MODEL_DOWNLOAD=1

COPY backend/requirements.txt backend/requirements.lock.txt* ./
RUN if [ -f requirements.lock.txt ]; then \
        pip install --no-cache-dir --require-hashes -r requirements.lock.txt; \
    else \
        echo "WARNING: building without a hashed dependency lock" && \
        pip install --no-cache-dir -r requirements.txt; \
    fi

COPY backend/app/ ./app/
COPY backend/tools/ ./tools/
COPY backend/model_locks.json ./model_locks.json
RUN python tools/prefetch_models.py

# ---------------------
# Stage 3: Runtime
# ---------------------
FROM python:3.11-slim AS production

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --create-home --uid 10001 aegis

COPY backend/requirements.txt backend/requirements.lock.txt* ./
RUN if [ -f requirements.lock.txt ]; then \
        pip install --no-cache-dir --require-hashes -r requirements.lock.txt; \
    else \
        echo "WARNING: building without a hashed dependency lock" && \
        pip install --no-cache-dir -r requirements.txt; \
    fi

COPY backend/app/ ./app/
COPY backend/tools/ ./tools/
COPY backend/model_locks.json ./model_locks.json
COPY --from=model-cache /opt/aegis/models /opt/aegis/models
COPY --from=frontend-build /app/dist ./static/

RUN cat > /app/serve.py << 'EOF'
"""Production server: FastAPI backend plus the built frontend."""
from pathlib import Path
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.main import app

static_dir = Path("/app/static")
if static_dir.exists():
    app.mount("/assets", StaticFiles(directory=str(static_dir / "assets")), name="assets")

    @app.get("/{path:path}")
    async def serve_spa(path: str):
        file_path = static_dir / path
        if file_path.exists() and file_path.is_file():
            return FileResponse(str(file_path))
        return FileResponse(str(static_dir / "index.html"))
EOF

RUN chown -R aegis:aegis /app /opt/aegis
USER aegis

# The frontend is served from this origin, so cross-origin access is not needed.
# Override ALLOWED_ORIGINS only if the UI is hosted separately.
ENV ENVIRONMENT=production \
    ALLOWED_ORIGINS=http://localhost:8000 \
    AEGIS_THREAT_MODEL_CACHE=/opt/aegis/models \
    AEGIS_THREAT_ALLOW_MODEL_DOWNLOAD=0

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["python", "-m", "uvicorn", "serve:app", "--host", "0.0.0.0", "--port", "8000"]
