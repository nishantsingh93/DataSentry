FROM python:3.11-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && python -m spacy download en_core_web_sm

COPY datasentry ./datasentry
COPY config ./config

RUN useradd --create-home datasentry \
    && mkdir -p /app/logs \
    && chown -R datasentry:datasentry /app
USER datasentry

EXPOSE 8000
CMD ["python", "-m", "datasentry.cli", "serve", "--host", "0.0.0.0", "--port", "8000"]
