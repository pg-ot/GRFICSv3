FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping net-tools curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ./
COPY templates ./templates

CMD ["sh", "-c", "ip route replace 192.168.90.0/24 via 192.168.100.200 && ip route replace 192.168.95.0/24 via 192.168.100.200 && python app.py"]
