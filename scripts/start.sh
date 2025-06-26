#!/bin/bash
echo "Starting HexGuard environment..."

cd /opt/hexguard/docker
docker-compose up -d

echo "HexGuard environment started successfully."