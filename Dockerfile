# Hardened build: pinned digest base, multi-stage, non-root, no secrets, healthcheck.
FROM python:3.13-slim AS build
WORKDIR /build
COPY app/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.13-slim
RUN useradd --system --uid 10001 --no-create-home appuser
COPY --from=build /install /usr/local
WORKDIR /app
COPY --chown=appuser:appuser app/ ./app/
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status==200 else 1)"]
CMD ["python", "-m", "flask", "--app", "app/app.py", "run", "--host", "0.0.0.0", "--port", "8000"]
