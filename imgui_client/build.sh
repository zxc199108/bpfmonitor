#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

echo "=== bpfscript ImGui Monitor - Build ==="
echo ""

# Check and install system dependencies
echo "[1/3] Checking system dependencies..."
MISSING=""
for pkg in libsdl2-dev libcurl4-openssl-dev nlohmann-json3-dev; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        MISSING="$MISSING $pkg"
    fi
done
for cmd in cmake g++ pkg-config; do
    if ! command -v "$cmd" &>/dev/null; then
        MISSING="$MISSING $cmd"
    fi
done

if [ -n "$MISSING" ]; then
    echo "  Missing:$MISSING"
    echo "  Installing (requires sudo)..."
    sudo apt-get install -y $MISSING
else
    echo "  All dependencies found."
fi

# Configure
echo "[2/3] Configuring with CMake..."
cmake -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release "$SCRIPT_DIR"

# Build
echo "[3/3] Building..."
cmake --build "$BUILD_DIR" -j$(nproc)

echo ""
echo "Build complete: $BUILD_DIR/imgui_monitor"
echo ""
echo "Usage:"
echo "  $BUILD_DIR/imgui_monitor [server_url]"
echo "  $BUILD_DIR/imgui_monitor http://localhost:8080"
