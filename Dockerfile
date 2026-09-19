FROM python:3.11-slim

WORKDIR /app

# Install Python dependencies
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source
COPY backend/ ./backend/

# Copy static frontends
COPY dashboard/ ./dashboard/
COPY test-harness/ ./test-harness/

# Create model artifact directory
RUN mkdir -p backend/model_artifacts

# Pre-train and serialize ML model at build time
RUN python backend/train_eval.py

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
