FROM python:3.9-slim

WORKDIR /app

# Install system dependencies (needed for scapy and ML libs)
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Ensure data directory exists
RUN mkdir -p data

# Pre-train the ML model during build
RUN python ml/train_model.py

CMD ["python", "run.py", "all"]
