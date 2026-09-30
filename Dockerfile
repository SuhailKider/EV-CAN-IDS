FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY can_ids ./can_ids
# Train on simulated traffic at build time so the container starts instantly.
RUN python -m can_ids train

EXPOSE 8050
CMD ["python", "-m", "can_ids", "dashboard", "--host", "0.0.0.0", "--port", "8050"]
