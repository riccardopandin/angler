FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Never run as root. This container parses hostile input for a living.
RUN useradd --create-home --uid 10001 angler
USER angler

EXPOSE 8080
# Render, Fly and most PaaS hand the port in at runtime. Default to 8080 locally.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080}"]
