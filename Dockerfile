FROM python:3.12-alpine

# v2 has no third-party dependencies and no PHP: the image is just Python.
WORKDIR /app
COPY core/ ./core/
COPY web/ ./web/
COPY scenarios/ ./scenarios/
COPY scripts/ ./scripts/
COPY tests/ ./tests/
COPY seeker.py ./
COPY README.md ./
COPY LICENSE ./
RUN mkdir -p docs && chmod +x seeker.py

ENV SEEKER_HOST=0.0.0.0 \
    SEEKER_PORT=8080 \
    SEEKER_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/console', timeout=3).status==200 else 1)"

ENTRYPOINT ["python3", "/app/seeker.py"]
CMD ["serve"]
