FROM python:3.12-slim

WORKDIR /app

# openssl for entrypoint.sh's self-signed cert generation -- not
# guaranteed present in the slim base image.
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py entrypoint.sh .
RUN chmod +x entrypoint.sh
COPY templates/ templates/
COPY static/ static/

# Token/leaderboard data, the session secret key, and the TLS cert/key
# all live here -- mounted as a volume by start.sh so they survive
# container recreation, not baked into the image.
ENV FRUIT_MACHINE_DB=/data/fruit_machine.db
VOLUME /data

EXPOSE 5000 5001

CMD ["./entrypoint.sh"]
