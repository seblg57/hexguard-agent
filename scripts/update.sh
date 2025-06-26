#!/bin/bash
echo "Updating HexGuard environment..."

cd /opt/hexguard/docker
docker-compose pull
docker-compose up -d

echo "HexGuard environment updated and restarted successfully."
