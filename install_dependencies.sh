#!/bin/bash

# Install Dependencies Script for Network Traffic Analysis Tool

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

echo "Starting the installation of dependencies..."

# Update package lists
echo "Updating package lists..."
sudo apt-get update

# Install Python3 if not already installed
if command_exists python3; then
    echo "Python3 is already installed."
else
    echo "Installing Python3..."
    sudo apt-get install -y python3
fi

# Install pip3 if not already installed
if command_exists pip3; then
    echo "pip3 is already installed."
else
    echo "Installing pip3..."
    sudo apt-get install -y python3-pip
fi

# Install Scapy
echo "Installing Scapy..."
pip3 install scapy

# Install GeoIP library (optional, for GeoIP features)
echo "Installing GeoIP library..."
pip3 install geoip2

# Install other required Python libraries (if any)
echo "Installing other required Python libraries..."
pip3 install -r requirements.txt

# Download the GeoLite2-City database if needed
if [ ! -f "GeoLite2-City.mmdb" ]; then
    echo "Downloading GeoLite2-City.mmdb..."
    wget -O GeoLite2-City.mmdb "https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz"
    tar -xzf GeoLite2-City.mmdb.tar.gz
    rm GeoLite2-City.mmdb.tar.gz
fi

echo "All dependencies have been installed successfully."

# Optionally, run the main script to start the tool
echo "Do you want to run the main script now? (y/n)"
read -r run_script

if [ "$run_script" = "y" ]; then
    python3 main.py
fi

echo "Installation and setup complete."
