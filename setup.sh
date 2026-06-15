#!/usr/bin/env bash
# setup.sh — Tracery development environment bootstrap
# Supports Ubuntu 22.04, Ubuntu 24.04, and Debian 12
# Detects architecture (x86_64 and aarch64/ARM64 both supported)
# Run as root or with sudo privileges.
#
# Usage (three equivalent forms):
#   curl -fsSL https://raw.githubusercontent.com/riyacore404/tracery/main/setup.sh | sudo bash
#   sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/riyacore404/tracery/main/setup.sh)"
#   OR locally: sudo bash setup.sh

set -euo pipefail

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

log()     { echo -e "${CYAN}[tracery]${RESET} $*"; }
ok()      { echo -e "${GREEN}[  OK  ]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[ WARN ]${RESET} $*"; }
die()     { echo -e "${RED}[ FAIL ]${RESET} $*" >&2; exit 1; }
section() { echo -e "\n${BOLD}━━━ $* ━━━${RESET}"; }

# ─── Root check ──────────────────────────────────────────────────────────────
if [[ "$EUID" -ne 0 ]]; then
  die "Please run as root: sudo bash setup.sh"
fi

# ─── OS check ────────────────────────────────────────────────────────────────
section "Checking OS"
if [[ ! -f /etc/os-release ]]; then
  die "Cannot detect OS — /etc/os-release missing."
fi
source /etc/os-release
if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
  warn "Detected OS: $ID $VERSION_ID — only Ubuntu/Debian are officially supported."
fi
ok "OS: $PRETTY_NAME"

# ─── Architecture detection ──────────────────────────────────────────────────
section "Checking Architecture"
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)
    GO_ARCH="amd64"
    GORELEASER_ARCH="x86_64"
    BPF_TARGET="x86"
    ok "Architecture: x86_64 (amd64)"
    ;;
  aarch64|arm64)
    GO_ARCH="arm64"
    GORELEASER_ARCH="arm64"
    BPF_TARGET="arm64"
    ok "Architecture: ARM64 (aarch64)"
    ;;
  *)
    warn "Unknown architecture: $ARCH — proceeding but things may not work"
    GO_ARCH="amd64"
    GORELEASER_ARCH="x86_64"
    BPF_TARGET="x86"
    ;;
esac

# ─── Kernel version check ────────────────────────────────────────────────────
section "Checking Kernel"
KERNEL=$(uname -r)
KERNEL_MAJOR=$(echo "$KERNEL" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL" | cut -d. -f2)

if [[ "$KERNEL_MAJOR" -lt 5 ]] || { [[ "$KERNEL_MAJOR" -eq 5 ]] && [[ "$KERNEL_MINOR" -lt 8 ]]; }; then
  die "Kernel $KERNEL is too old. Tracery requires Linux 5.8+ (ring buffer support). Upgrade your kernel."
fi
ok "Kernel $KERNEL — meets minimum requirement (5.8+)"

# ─── BTF check ───────────────────────────────────────────────────────────────
if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
  warn "/sys/kernel/btf/vmlinux not found — CO-RE portability may be limited."
  warn "Ensure your kernel was compiled with CONFIG_DEBUG_INFO_BTF=y."
else
  ok "BTF available at /sys/kernel/btf/vmlinux"
fi

# ─── System dependencies ─────────────────────────────────────────────────────
section "Installing system dependencies"
apt-get update -qq

# Try clang-16 first, fall back to clang-14, then clang
CLANG_PKG=""
for ver in 16 14 ""; do
  pkg="clang${ver:+-$ver}"
  if apt-cache show "$pkg" &>/dev/null 2>&1; then
    CLANG_PKG="$pkg"
    break
  fi
done
LLVM_PKG="${CLANG_PKG/clang/llvm}"

PKGS=(
  "${CLANG_PKG:-clang}"
  "${LLVM_PKG:-llvm}"
  libelf-dev
  libbpf-dev
  bpftool
  linux-headers-"$(uname -r)"
  build-essential
  pkg-config
  git
  curl
  wget
  make
  jq
)

for pkg in "${PKGS[@]}"; do
  if dpkg -s "$pkg" &>/dev/null 2>&1; then
    ok "$pkg already installed"
  else
    log "Installing $pkg..."
    if apt-get install -y -qq "$pkg" 2>/dev/null; then
      ok "$pkg installed"
    else
      BASE_PKG=$(echo "$pkg" | sed "s/-$(uname -r)//")
      if [[ "$pkg" != "$BASE_PKG" ]]; then
        log "Retrying with base package $BASE_PKG..."
        apt-get install -y -qq "$BASE_PKG" 2>/dev/null && ok "$BASE_PKG installed" \
          || warn "Could not install $pkg or $BASE_PKG — continuing"
      else
        warn "Could not install $pkg — continuing"
      fi
    fi
  fi
done

# ─── Clang symlink ───────────────────────────────────────────────────────────
section "Setting up clang symlinks"
if ! command -v clang &>/dev/null; then
  if command -v clang-16 &>/dev/null; then
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-16 100
    update-alternatives --install /usr/bin/llc   llc   /usr/bin/llc-16   100
    ok "clang -> clang-16 symlink created"
  elif command -v clang-14 &>/dev/null; then
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-14 100
    update-alternatives --install /usr/bin/llc   llc   /usr/bin/llc-14   100
    ok "clang -> clang-14 symlink created"
  else
    warn "No versioned clang found — install manually if BPF compilation fails"
  fi
else
  ok "clang already on PATH: $(clang --version | head -1)"
fi

# ─── Go ──────────────────────────────────────────────────────────────────────
section "Installing Go"
GO_VERSION="1.22.4"
GO_TARBALL="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
GO_URL="https://go.dev/dl/${GO_TARBALL}"
GO_INSTALL_DIR="/usr/local"

if command -v go &>/dev/null; then
  INSTALLED_GO=$(go version | awk '{print $3}' | sed 's/go//')
  ok "Go $INSTALLED_GO already installed"
else
  log "Downloading Go $GO_VERSION for $GO_ARCH..."
  wget -q "$GO_URL" -O "/tmp/$GO_TARBALL"
  tar -C "$GO_INSTALL_DIR" -xzf "/tmp/$GO_TARBALL"
  rm "/tmp/$GO_TARBALL"

  cat > /etc/profile.d/go.sh <<'EOF'
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
EOF
  source /etc/profile.d/go.sh
  ok "Go $GO_VERSION installed at /usr/local/go"
fi

export PATH=$PATH:/usr/local/go/bin

# ─── goreleaser ──────────────────────────────────────────────────────────────
section "Installing goreleaser"
if command -v goreleaser &>/dev/null; then
  ok "goreleaser already installed"
else
  log "Installing goreleaser for $GORELEASER_ARCH..."
  GORELEASER_URL="https://github.com/goreleaser/goreleaser/releases/latest/download/goreleaser_Linux_${GORELEASER_ARCH}.tar.gz"
  wget -q "$GORELEASER_URL" -O /tmp/goreleaser.tar.gz
  tar -C /usr/local/bin -xzf /tmp/goreleaser.tar.gz goreleaser
  rm /tmp/goreleaser.tar.gz
  ok "goreleaser installed"
fi

# ─── bpftool check ───────────────────────────────────────────────────────────
section "Verifying bpftool"
if command -v bpftool &>/dev/null; then
  ok "bpftool: $(bpftool version 2>&1 | head -1)"
else
  warn "bpftool not found — skeleton generation will not work."
  warn "Try: apt-get install linux-tools-$(uname -r)"
fi

# ─── Generate vmlinux.h ──────────────────────────────────────────────────────
section "Generating vmlinux.h"
VMLINUX_DEST="$HOME/tracery/bpf/vmlinux.h"
mkdir -p "$(dirname "$VMLINUX_DEST")"

if [[ -f "$VMLINUX_DEST" ]]; then
  ok "vmlinux.h already exists"
elif [[ -f /sys/kernel/btf/vmlinux ]]; then
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$VMLINUX_DEST"
  ok "Generated vmlinux.h at $VMLINUX_DEST"
else
  warn "Cannot generate vmlinux.h — /sys/kernel/btf/vmlinux not found"
fi

# ─── CAP_BPF hint ────────────────────────────────────────────────────────────
section "Capability notes"
warn "Tracery must run as root OR with CAP_BPF + CAP_PERFMON capabilities."
warn "After building, grant capabilities with:"
warn "  sudo setcap cap_bpf,cap_perfmon+ep ./tracery"

# ─── Summary ─────────────────────────────────────────────────────────────────
section "Environment Summary"
echo ""
printf "  %-20s %s\n" "OS:"         "$PRETTY_NAME"
printf "  %-20s %s\n" "Kernel:"     "$(uname -r)"
printf "  %-20s %s\n" "Arch:"       "$ARCH (BPF target: $BPF_TARGET)"
printf "  %-20s %s\n" "clang:"      "$(clang --version 2>/dev/null | head -1 || echo 'not found')"
printf "  %-20s %s\n" "Go:"         "$(go version 2>/dev/null | awk '{print $3}' || echo 'not found')"
printf "  %-20s %s\n" "bpftool:"    "$(bpftool version 2>/dev/null | head -1 || echo 'not found')"
printf "  %-20s %s\n" "libbpf-dev:" "$(dpkg -s libbpf-dev 2>/dev/null | grep Version | awk '{print $2}' || echo 'not found')"
printf "  %-20s %s\n" "BTF:"        "$(test -f /sys/kernel/btf/vmlinux && echo 'available' || echo 'MISSING')"
echo ""
ok "Setup complete. Build environment is ready."
echo ""
echo -e "  ${BOLD}Next steps:${RESET}"
echo "  1. cd ~/tracery"
echo "  2. make build"
echo "  3. sudo ./tracery count --pid \$(pgrep bash)"
echo ""