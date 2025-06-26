

hexguard.zip


TAR_VERSION="tar --version | awk {'print $4'} | head -n 1"

if command -v tar &>/dev/null ; then
        echo "Tar  is already installed."
    else
        echo "Tar not found. Installing now."
        sudo dnf install -y tar

        if python3 --version | grep -q "$PYTHON_VERSION"; then
            echo "Python $PYTHON_VERSION has been successfully installed."
        else
            echo "Failed to install Python $PYTHON_VERSION. Please check for issues."
            exit 1
        fi
  fi