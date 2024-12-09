# Base Python image
FROM python:3.9-slim

# Update system packages and install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
  && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    pyyaml \
    requests \
    paho-mqtt

# Set working directory
WORKDIR /scanner

# By default, run the scanner script
CMD [ "python", "-u", "scanner.py" ]
