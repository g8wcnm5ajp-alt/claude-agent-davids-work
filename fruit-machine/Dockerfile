FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/
COPY static/ static/

# Token/leaderboard data lives here -- mounted as a volume by start.sh so
# it survives container recreation, not baked into the image.
ENV FRUIT_MACHINE_DB=/data/fruit_machine.db
VOLUME /data

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]
