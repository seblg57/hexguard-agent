FROM python:3.9-slim

# Set the working directory
WORKDIR /opt/hexguard-agent/hexguard

# Install sqlite3
RUN apt-get update && apt-get install -y sqlite3 && rm -rf /var/lib/apt/lists/*

# Copy requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application files
COPY app/hexguard /opt/hexguard-agent/hexguard

# Expose the application's port
EXPOSE 5000

# Define the command to run the application with gunicorn
CMD ["gunicorn", "--certfile=/etc/ssl/certs/fullchain.pem", "--keyfile=/etc/ssl/private/privkey.pem", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]

