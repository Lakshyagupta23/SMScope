FROM python:3.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 IPS_DRY_RUN=1 ENABLE_ACTIVE_RESPONSE=0
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --uid 10001 --create-home appuser && mkdir -p /data && chown appuser:appuser /data
USER 10001:10001
EXPOSE 8000
CMD ["python", "main.py"]
