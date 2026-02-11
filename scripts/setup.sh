#!/usr/bin/env bash
set -euo pipefail

echo "=== safe-agent-sandbox setup ==="
echo ""

OS="$(uname -s)"
ARCH="$(uname -m)"
echo "Platform: ${OS} ${ARCH}"
echo ""

# ---------------------------------------------------------------------------
# macOS setup (Docker Desktop)
# ---------------------------------------------------------------------------
setup_macos() {
    echo "--- macOS setup ---"

    if command -v docker &>/dev/null; then
        echo "Docker found: $(docker --version)"
    else
        echo "Docker not found."
        echo "Install Docker Desktop from https://www.docker.com/products/docker-desktop/"
        echo "After installing, make sure Docker Desktop is running."
        exit 1
    fi

    if docker info &>/dev/null; then
        echo "Docker daemon is running."
    else
        echo "Docker daemon is not reachable."
        echo "Open Docker Desktop and wait for it to finish starting."
        exit 1
    fi

    pull_images_docker
    setup_go
}

# ---------------------------------------------------------------------------
# Linux setup (containerd + runc + CNI, or Docker)
# ---------------------------------------------------------------------------
setup_linux() {
    echo "--- Linux setup ---"

    if command -v containerd &>/dev/null; then
        echo "containerd found: $(containerd --version)"
        install_runc
        install_cni
        pull_images_containerd
        setup_namespace
    elif command -v docker &>/dev/null; then
        echo "containerd not found, using Docker instead."
        echo "Docker found: $(docker --version)"
        pull_images_docker
    else
        echo "Neither containerd nor Docker found."
        echo ""
        echo "Option 1: Install containerd (recommended for production)"
        echo "  See install_containerd() in this script or visit:"
        echo "  https://github.com/containerd/containerd/blob/main/docs/getting-started.md"
        echo ""
        echo "Option 2: Install Docker Engine"
        echo "  https://docs.docker.com/engine/install/"
        exit 1
    fi

    setup_go
}

# ---------------------------------------------------------------------------
# Install containerd (Linux only)
# ---------------------------------------------------------------------------
install_containerd() {
    if command -v containerd &>/dev/null; then
        echo "containerd already installed: $(containerd --version)"
        return
    fi

    echo "Installing containerd..."
    CONTAINERD_VERSION="1.7.27"
    wget -q "https://github.com/containerd/containerd/releases/download/v${CONTAINERD_VERSION}/containerd-${CONTAINERD_VERSION}-linux-amd64.tar.gz"
    sudo tar Cxzvf /usr/local "containerd-${CONTAINERD_VERSION}-linux-amd64.tar.gz"
    rm "containerd-${CONTAINERD_VERSION}-linux-amd64.tar.gz"

    sudo mkdir -p /usr/local/lib/systemd/system
    sudo wget -qO /usr/local/lib/systemd/system/containerd.service \
        "https://raw.githubusercontent.com/containerd/containerd/main/containerd.service"
    sudo systemctl daemon-reload
    sudo systemctl enable --now containerd
}

# ---------------------------------------------------------------------------
# Install runc (Linux only)
# ---------------------------------------------------------------------------
install_runc() {
    if command -v runc &>/dev/null; then
        echo "runc already installed: $(runc --version | head -1)"
        return
    fi

    echo "Installing runc..."
    RUNC_VERSION="1.1.12"
    wget -q "https://github.com/opencontainers/runc/releases/download/v${RUNC_VERSION}/runc.amd64"
    sudo install -m 755 runc.amd64 /usr/local/sbin/runc
    rm runc.amd64
}

# ---------------------------------------------------------------------------
# Install CNI plugins (Linux only)
# ---------------------------------------------------------------------------
install_cni() {
    if [[ -d /opt/cni/bin ]]; then
        echo "CNI plugins already installed."
        return
    fi

    echo "Installing CNI plugins..."
    CNI_VERSION="1.4.0"
    sudo mkdir -p /opt/cni/bin
    wget -q "https://github.com/containernetworking/plugins/releases/download/v${CNI_VERSION}/cni-plugins-linux-amd64-v${CNI_VERSION}.tgz"
    sudo tar Cxzvf /opt/cni/bin "cni-plugins-linux-amd64-v${CNI_VERSION}.tgz"
    rm "cni-plugins-linux-amd64-v${CNI_VERSION}.tgz"
}

# ---------------------------------------------------------------------------
# Pull sandbox runtime images
# ---------------------------------------------------------------------------
pull_images_containerd() {
    echo "Pulling sandbox runtime images (containerd)..."
    sudo ctr images pull docker.io/library/python:3.12-slim
    sudo ctr images pull docker.io/library/node:20-slim
    sudo ctr images pull docker.io/library/alpine:3.19
}

pull_images_docker() {
    echo "Pulling sandbox runtime images (Docker)..."
    docker pull python:3.12-slim
    docker pull node:20-slim
    docker pull alpine:3.19
}

# ---------------------------------------------------------------------------
# Create containerd namespace
# ---------------------------------------------------------------------------
setup_namespace() {
    echo "Creating sandbox namespace..."
    sudo ctr namespaces create sandbox 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Go dependencies
# ---------------------------------------------------------------------------
setup_go() {
    echo ""
    echo "Installing Go dependencies..."
    go mod download
    go mod tidy
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
case "$OS" in
    Darwin)
        setup_macos
        ;;
    Linux)
        setup_linux
        ;;
    *)
        echo "Unsupported platform: ${OS}"
        echo "This project supports macOS (via Docker Desktop) and Linux (via containerd or Docker)."
        exit 1
        ;;
esac

echo ""
echo "=== Setup complete ==="
echo "Run 'make build' to build the project."
echo "Run 'make run' to start the server."
