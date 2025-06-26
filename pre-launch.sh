#!/bin/bash
echo "🧹 Préparation du terrain pour HexGuard TARantula..."

mkdir -p /var/log/nginx
touch /var/log/secure
touch /var/log/audit/audit.log
touch /var/log/messages
mkdir -p /opt/hexguard-agent/hexguard

echo "✅ Préparation terminée. Tu peux lancer docker-compose."

