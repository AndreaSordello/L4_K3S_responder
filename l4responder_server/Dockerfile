FROM python:3.13-slim

# Create non-root user
RUN useradd -r -s /bin/false responder

# Set work directory
WORKDIR /app

# Copy files
COPY responder.py .

# Run as non-root
USER responder

# Entry point
CMD ["python", "responder.py"]
