FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
COPY pyproject.toml .
COPY aegis ./aegis
COPY runbooks ./runbooks
RUN pip install --no-cache-dir .

EXPOSE 8000

