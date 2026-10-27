FROM python:3.11-slim

# Install system network tools (nmap, dnsutils for dig/nslookup, iputils-ping)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    dnsutils \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=5000
EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "300", "app:app"]
