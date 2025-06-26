#!/bin/bash
echo "Stopping HexGuard environment..."

cd /opt/hexguard/docker
docker-compose down

echo "HexGuard environment stopped successfully."
