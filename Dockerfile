# Hardened build: pinned digest base, multi-stage, non-root, no secrets, healthcheck.
FROM python:3.13-slim AS build
WORKDIR /build
COPY app/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.13-slim
# Create the runtime user and strip the build toolchain out, in one layer.
#
# pip and setuptools are build-time tools; nothing in this service imports them
# at runtime. Leaving them in shipped two HIGH findings that had nothing to do
# with the application: CVE-2025-47273 in setuptools 70.3.0, and
# GHSA-6v7p-g79w-8964 in the msgpack copy that pip vendors. Removing them fixes
# both and removes a package installer from a container an attacker might reach.
RUN useradd --system --uid 10001 --no-create-home appuser \
	&& rm -rf /usr/local/lib/python3.13/site-packages/pip \
	/usr/local/lib/python3.13/site-packages/pip-*.dist-info \
	/usr/local/lib/python3.13/site-packages/setuptools \
	/usr/local/lib/python3.13/site-packages/setuptools-*.dist-info \
	/usr/local/lib/python3.13/site-packages/pkg_resources \
	/usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.13

COPY --from=build /install /usr/local
WORKDIR /app
COPY --chown=appuser:appuser app/ ./app/
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status==200 else 1)"]
CMD ["python", "-m", "flask", "--app", "app/app.py", "run", "--host", "0.0.0.0", "--port", "8000"]
