FROM python:3.12-slim

WORKDIR /app

# openssh-client for talking to the EM through the restricted key,
# openssl for the certs admin page (reading/validating cert files) --
# neither present in the slim base image by default.
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client openssl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py forescout_client.py .
COPY templates/ templates/
COPY static/ static/

# The restricted SSH private key lives here -- mounted as a read-only
# volume by start.sh (or Deploy.sh, for the EM-hosted package), never
# baked into the image.
ENV FORESCOUT_SSH_KEY=/keys/webapp_query_rsa
VOLUME /keys

# Pending scheduled-debug jobs + their fired-outcome log -- bind-mounted
# read-write by start.sh so a future-dated debug start survives this
# container being redeployed before it fires.
VOLUME /data

# HTTPS certs -- only mounted (and FORESCOUT_SSL_CERT/_KEY only set) by
# Deploy.sh for the EM-hosted package (Phase C, 2026-08-26). Unset here
# so the .230 deployment (start.sh, no certs mounted) keeps serving
# plain HTTP exactly as before -- see app.py's __main__ block.
VOLUME /certs

EXPOSE 5000

CMD ["python", "app.py"]
