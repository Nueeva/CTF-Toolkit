FROM python:3.12-slim

LABEL org.opencontainers.image.title="CTF-Toolkit v4.0 Apex"
LABEL org.opencontainers.image.description="Multi-domain CTF Exploitation Workbench, A* Magic Solver & CyberChef Recipe Studio"
LABEL org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    TERM=xterm-256color

WORKDIR /app

COPY requirements.txt pyproject.toml README.md LICENSE main.py ./
COPY ctf_toolkit ./ctf_toolkit

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir --no-deps .

WORKDIR /work

ENTRYPOINT ["ctf-toolkit"]
CMD ["interactive"]
