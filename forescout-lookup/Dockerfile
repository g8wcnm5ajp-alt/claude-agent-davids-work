FROM python:3.12-slim

WORKDIR /app

# openssh-client for talking to the EM through the restricted key --
# not present in the slim base image by default.
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py forescout_client.py .
COPY templates/ templates/
COPY static/ static/

# The restricted SSH private key lives here -- mounted as a read-only
# volume by start.sh, never baked into the image.
ENV FORESCOUT_SSH_KEY=/keys/webapp_query_rsa
VOLUME /keys

# Pending scheduled-debug jobs + their fired-outcome log -- bind-mounted
# read-write by start.sh so a future-dated debug start survives this
# container being redeployed before it fires.
VOLUME /data

EXPOSE 5000

CMD ["python", "app.py"]
