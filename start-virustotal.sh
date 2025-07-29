#!/bin/bash

# Start VirusTotal MCP Server with SSE transport

echo "Starting VirusTotal MCP Server with SSE transport..."

# Check if .env file exists
if [ ! -f .env ]; then
    echo "Error: .env file not found. Please create a .env file with your VIRUSTOTAL_API_KEY."
    exit 1
fi

# Check if VIRUSTOTAL_API_KEY is set
if ! grep -q "VIRUSTOTAL_API_KEY" .env; then
    echo "Error: VIRUSTOTAL_API_KEY not found in .env file."
    exit 1
fi

# Set default port if not specified
export PORT=${PORT:-3000}
export HOST=${HOST:-localhost}

echo "Server will start on http://$HOST:$PORT/sse"
echo "Health check: http://$HOST:$PORT/health"
echo "Debug sessions: http://$HOST:$PORT/debug/sessions"
echo ""

# Start the server
npm run dev 