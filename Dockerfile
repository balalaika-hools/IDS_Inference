FROM python:3.9-slim

# Install required system packages
RUN apt-get update && apt-get install -y \
    tcpdump \
    libpcap-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*


# Set working directory
WORKDIR /app

# Copy requirements.txt f
COPY requirements.txt /app/

# Install Python dependencies except torch
RUN pip install --no-cache-dir -r requirements.txt

#Install cpu only Pytorch
RUN pip install torch --index-url https://download.pytorch.org/whl/cpu


# Copy your application code
COPY . /app/


# Expose the API port
EXPOSE 8000

# Run as root to simplify permissions (limited capabilities)
USER root

# Command to run the API
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]





