# Abe HTTP sidecar — any language can POST /v1/check.
#   docker build -t abe .
#   docker run --rm -e ABE_TOKEN=change-me -v "$PWD:/policy:ro" -v abe-records:/data -p 127.0.0.1:8787:8787 abe
# Publish the port on 127.0.0.1 only. The container requires ABE_TOKEN because it must bind 0.0.0.0 internally.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    ABE_POLICY=/policy/abe-policy.yaml ABE_STORE=sqlite:/data/abe-records.db

COPY python /src/python
COPY flow-resolver /src/flow-resolver
RUN pip install --no-cache-dir "/src/python[signing]" /src/flow-resolver && rm -rf /src \
    && useradd --system --uid 10001 abe && mkdir -p /data && chown abe /data

USER abe
WORKDIR /data
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8787/healthz', timeout=2).status == 200 else 1)"

ENTRYPOINT ["sh", "-c", "if [ -z \"$ABE_TOKEN\" ]; then echo 'ABE_TOKEN is required' >&2; exit 2; fi; exec abe serve --host 0.0.0.0 --allow-remote --port 8787 --store \"$ABE_STORE\""]
