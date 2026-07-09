# 1. Use an official, lightweight Python runtime as a parent image
FROM python:3.11-slim

# 2. Set metadata for the image
LABEL maintainer="Your Name <your.email@example.com>"
LABEL description="BITSOLERA Custom Reconnaissance Tool"

# 3. Set the working directory inside the container
WORKDIR /app

# 4. Copy only the requirements file first (leverages Docker cache for faster rebuilds)
COPY requirements.txt .

# 5. Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# 6. Copy the rest of the application code into the container
COPY . .

# 7. Create the reports directory so the tool doesn't crash when saving
RUN mkdir -p /app/reports

# 8. Define the default executable when the container starts
# This allows users to pass arguments directly to the container like a native CLI
ENTRYPOINT ["python", "main.py"]
