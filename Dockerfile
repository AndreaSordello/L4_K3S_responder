FROM python:3.10-slim

# Install gcc and iptables dev dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    iptables \
    libnfnetlink-dev \
    libnetfilter-conntrack-dev \
    && apt-get clean

# Set work directory
WORKDIR /app

# Copy files
COPY requirements.txt .
COPY toolbox.py .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Entry point
CMD ["python", "toolbox.py"]
