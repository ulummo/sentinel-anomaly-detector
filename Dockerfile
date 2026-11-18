FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --create-home --uid 10001 sentinel && mkdir -p /data && chown -R sentinel:sentinel /app /data
USER sentinel
ENV SENTINEL_DB_PATH=/data/sentinel_events.sqlite3
EXPOSE 8000
CMD ["uvicorn","sentinel.api:app","--host","0.0.0.0","--port","8000"]
