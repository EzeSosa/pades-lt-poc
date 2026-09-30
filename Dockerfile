FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Dependencias primero (capa cacheable), después el código.
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-install-project --no-dev
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev

RUN useradd --system --uid 10001 app && mkdir -p /data && chown app /data
USER app

# La PKI (claves incluidas) vive en el volumen /data para sobrevivir reinicios.
# PUBLIC_BASE_URL queda grabada en los certificados (CDP, AIA, OCSP) la primera
# vez que se genera la PKI: tiene que ser alcanzable desde el contenedor y
# desde quien valide las firmas.
ENV PATH="/app/.venv/bin:$PATH" \
    PKI_DIR=/data/pki \
    PUBLIC_BASE_URL=http://127.0.0.1:8000

VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/pki/root.crt')"

CMD ["uvicorn", "pades_lt_poc.app:app", "--host", "0.0.0.0", "--port", "8000"]
