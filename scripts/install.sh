#!/bin/bash
sudo mkdir -p /opt/hexguard

PYTHON_VERSION="3.11"
DOCKER_COMPOSE_VERSION="1.29.2"  # Specify the Docker Compose version you need

install_python() {
    if command -v python3 &>/dev/null && python3 --version | grep -q "$PYTHON_VERSION"; then
        echo "Python $PYTHON_VERSION is already installed."
    else
        echo "Python $PYTHON_VERSION not found. Installing now."
        sudo dnf install -y dnf-plugins-core
        sudo dnf config-manager --set-enabled appstream
        sudo dnf install -y python$PYTHON_VERSION
        if python3 --version | grep -q "$PYTHON_VERSION"; then
            echo "Python $PYTHON_VERSION has been successfully installed."
        else
            echo "Failed to install Python $PYTHON_VERSION. Please check for issues."
            exit 1
        fi
    fi
}

install_firewalld() {
    if command -v firewalld &>/dev/null && docker-compose --version | grep -q "$DOCKER_COMPOSE_VERSION"; then
        echo "Docker Compose $DOCKER_COMPOSE_VERSION is already installed."
    else
        echo "Docker Compose $DOCKER_COMPOSE_VERSION not found. Installing now."
        sudo curl -L "https://github.com/docker/compose/releases/download/$DOCKER_COMPOSE_VERSION/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        sudo chmod +x /usr/local/bin/docker-compose
        if docker-compose --version | grep -q "$DOCKER_COMPOSE_VERSION"; then
            echo "Docker Compose $DOCKER_COMPOSE_VERSION has been successfully installed."
        else
            echo "Failed to install Docker Compose $DOCKER_COMPOSE_VERSION. Please check for issues."
            exit 1
        fi
    fi
}

install_docker_compose() {
    if command -v docker-compose &>/dev/null && docker-compose --version | grep -q "$DOCKER_COMPOSE_VERSION"; then
        echo "Docker Compose $DOCKER_COMPOSE_VERSION is already installed."
    else
        echo "Docker Compose $DOCKER_COMPOSE_VERSION not found. Installing now."
        sudo curl -L "https://github.com/docker/compose/releases/download/$DOCKER_COMPOSE_VERSION/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        sudo chmod +x /usr/local/bin/docker-compose
        if docker-compose --version | grep -q "$DOCKER_COMPOSE_VERSION"; then
            echo "Docker Compose $DOCKER_COMPOSE_VERSION has been successfully installed."
        else
            echo "Failed to install Docker Compose $DOCKER_COMPOSE_VERSION. Please check for issues."
            exit 1
        fi
    fi
}

install_python
install_docker_compose

echo "Python and Docker Compose installation completed successfully."






sudo firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="0.0.0.0/0" log prefix="firewalld-drop: " level="info" limit value="1/m" drop'
firewall-cmd --reload

