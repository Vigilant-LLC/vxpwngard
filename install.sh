#!/usr/bin/env bash
set -euo pipefail

REPO="Vigilant-LLC/runner-guard"
BINARY_NAME="runner-guard"
INSTALL_DIR="/usr/local/bin"

# Detect OS
detect_os() {
    local os
    os="$(uname -s)"
    case "${os}" in
        Linux*)     echo "linux" ;;
        Darwin*)    echo "darwin" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *)
            echo "Error: Unsupported operating system: ${os}" >&2
            exit 1
            ;;
    esac
}

# Detect architecture
detect_arch() {
    local arch
    arch="$(uname -m)"
    case "${arch}" in
        x86_64|amd64)   echo "amd64" ;;
        aarch64|arm64)   echo "arm64" ;;
        *)
            echo "Error: Unsupported architecture: ${arch}" >&2
            exit 1
            ;;
    esac
}

# Get latest release tag from GitHub API
get_latest_version() {
    local latest
    latest="$(curl -sSfL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name":' \
        | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"

    if [ -z "${latest}" ]; then
        echo "Error: Could not determine latest release version." >&2
        echo "Check your internet connection or visit https://github.com/${REPO}/releases" >&2
        exit 1
    fi

    echo "${latest}"
}

main() {
    echo "Installing ${BINARY_NAME}..."
    echo ""

    local os arch version download_url tmp_dir archive_name

    os="$(detect_os)"
    arch="$(detect_arch)"
    version="$(get_latest_version)"

    echo "  OS:       ${os}"
    echo "  Arch:     ${arch}"
    echo "  Version:  ${version}"
    echo ""

    if [ "${os}" = "windows" ]; then
        archive_name="${BINARY_NAME}_${version#v}_${os}_${arch}.zip"
    else
        archive_name="${BINARY_NAME}_${version#v}_${os}_${arch}.tar.gz"
    fi

    download_url="https://github.com/${REPO}/releases/download/${version}/${archive_name}"

    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "${tmp_dir}"' EXIT

    echo "Downloading ${download_url}..."
    if ! curl -sSfL -o "${tmp_dir}/${archive_name}" "${download_url}"; then
        echo "Error: Failed to download ${download_url}" >&2
        echo "Please check that the release exists at https://github.com/${REPO}/releases" >&2
        exit 1
    fi

    echo "Extracting..."
    if [ "${os}" = "windows" ]; then
        unzip -q "${tmp_dir}/${archive_name}" -d "${tmp_dir}"
    else
        tar -xzf "${tmp_dir}/${archive_name}" -C "${tmp_dir}"
    fi

    echo "Installing to ${INSTALL_DIR}/${BINARY_NAME}..."
    if [ -w "${INSTALL_DIR}" ]; then
        cp "${tmp_dir}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
        chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    else
        echo "  (requires sudo)"
        sudo cp "${tmp_dir}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
        sudo chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    fi

    echo ""
    echo "runner-guard ${version} installed successfully."
    echo ""
    echo "Run: runner-guard demo"
}

main
