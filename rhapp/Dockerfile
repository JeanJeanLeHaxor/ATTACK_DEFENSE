# Use official Python base image
FROM python:3.10-slim

# Install dependencies for Playwright browsers
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    gnupg \
    libnss3 \
    libatk-bridge2.0-0 \
    libgtk-3-0 \
    libx11-xcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpangocairo-1.0-0 \
    libatspi2.0-0 \
    libdrm2 \
    libxss1 \
    libxcursor1 \
    libxfixes3 \
    libxi6 \
    libxtst6 \
    libcups2 \
    libdbus-1-3 \
    libexpat1 \
    libxinerama1 \
    libegl1 \
    libgl1 \
    libglx-mesa0 \
    libgles2 \
    libwayland-client0 \
    libwayland-cursor0 \
    libwayland-egl1 \
    libfontconfig1 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libxrender1 \
    --no-install-recommends && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy your app code
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers
RUN python3 -m playwright install --with-deps

# Expose port
EXPOSE 5000

# Run the app
CMD ["python3", "main.py"]
