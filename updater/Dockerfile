FROM python:3.12.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data

WORKDIR /updater

COPY requirements.txt ./
RUN pip install --no-cache-dir --requirement requirements.txt
COPY app.py ./

# Root is required to reach /var/run/docker.sock on the host; the compose file adds
# no-new-privileges and the service publishes no ports.
EXPOSE 8070
CMD ["python", "app.py"]
