FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_NO_CACHE=1
WORKDIR /app
RUN pip install --no-cache-dir uv==0.9.7
COPY pyproject.toml uv.lock ./
COPY app ./app
RUN uv sync --frozen --no-dev
COPY migrations ./migrations
COPY alembic.ini ./
COPY config ./config
RUN useradd --uid 10001 --create-home aivi && mkdir -p /app/reports /app/logs && chown -R aivi:aivi /app
USER 10001
ENV PATH="/app/.venv/bin:$PATH"
CMD ["aivi", "scheduler"]
