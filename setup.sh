#!/usr/bin/env bash
# setup.sh — Tracery development environment bootstrap
# Supports Ubuntu 22.04, Ubuntu 24.04, and Debian 12
# Run as root or with sudo privileges.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/riyacore404/tracery/main/setup.sh | bash
#   OR: bash setup.sh

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

PKGS=(
  clang-16
  llvm-16
  libelf-dev
  libbpf-dev
  bpftool
  linux-headers-"$(uname -r)"
  linux-tools-"$(uname -r)"
  build-essential
  pkg-config
  git
  curl
  wget
  make
  jq
  asciinema   # for recording terminal demos
)

# linux-tools may not exist for custom kernels — make it optional
OPTIONAL_PKGS=(linux-tools-"$(uname -r)")

for pkg in "${PKGS[@]}"; do
  if dpkg -s "$pkg" &>/dev/null; then
    ok "$pkg already installed"
  else
    log "Installing $pkg..."
    if apt-get install -y -qq "$pkg" 2>/dev/null; then
      ok "$pkg installed"
    else
      # Try without kernel-specific version for tools
      BASE_PKG=$(echo "$pkg" | sed "s/-$(uname -r)//")
      if [[ "$pkg" != "$BASE_PKG" ]]; then
        log "Retrying with base package $BASE_PKG..."
        apt-get install -y -qq "$BASE_PKG" 2>/dev/null && ok "$BASE_PKG installed" || warn "Could not install $pkg or $BASE_PKG — continuing"
      else
        warn "Could not install $pkg — continuing"
      fi
    fi
  fi
done

# ─── Clang symlink ───────────────────────────────────────────────────────────
section "Setting up clang symlinks"
if ! command -v clang &>/dev/null; then
  update-alternatives --install /usr/bin/clang clang /usr/bin/clang-16 100
  update-alternatives --install /usr/bin/llc   llc   /usr/bin/llc-16   100
  ok "clang -> clang-16 symlink created"
else
  ok "clang already on PATH: $(clang --version | head -1)"
fi

# ─── Go ──────────────────────────────────────────────────────────────────────
section "Installing Go"
GO_VERSION="1.22.4"
GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TARBALL}"
GO_INSTALL_DIR="/usr/local"

if command -v go &>/dev/null; then
  INSTALLED_GO=$(go version | awk '{print $3}' | sed 's/go//')
  ok "Go $INSTALLED_GO already installed"
else
  log "Downloading Go $GO_VERSION..."
  wget -q "$GO_URL" -O "/tmp/$GO_TARBALL"
  tar -C "$GO_INSTALL_DIR" -xzf "/tmp/$GO_TARBALL"
  rm "/tmp/$GO_TARBALL"

  # Add to /etc/profile.d for all future shells
  cat > /etc/profile.d/go.sh <<'EOF'
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
EOF
  source /etc/profile.d/go.sh
  ok "Go $GO_VERSION installed at /usr/local/go"
fi

# Ensure go is in PATH for this script
export PATH=$PATH:/usr/local/go/bin

# ─── goreleaser ──────────────────────────────────────────────────────────────
section "Installing goreleaser"
if command -v goreleaser &>/dev/null; then
  ok "goreleaser already installed"
else
  log "Installing goreleaser..."
  GORELEASER_URL="https://github.com/goreleaser/goreleaser/releases/latest/download/goreleaser_Linux_x86_64.tar.gz"
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

# ─── Clone libbpf-bootstrap (reference) ─────────────────────────────────────
section "Fetching libbpf-bootstrap"
BOOTSTRAP_DIR="$HOME/libbpf-bootstrap"
if [[ -d "$BOOTSTRAP_DIR" ]]; then
  ok "libbpf-bootstrap already cloned at $BOOTSTRAP_DIR"
else
  log "Cloning libbpf-bootstrap..."
  git clone --depth=1 --recurse-submodules \
    https://github.com/libbpf/libbpf-bootstrap.git "$BOOTSTRAP_DIR"
  ok "Cloned to $BOOTSTRAP_DIR"
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
printf "  %-20s %s\n" "OS:"        "$PRETTY_NAME"
printf "  %-20s %s\n" "Kernel:"    "$(uname -r)"
printf "  %-20s %s\n" "clang:"     "$(clang --version 2>/dev/null | head -1 || echo 'not found')"
printf "  %-20s %s\n" "Go:"        "$(go version 2>/dev/null | awk '{print $3}' || echo 'not found')"
printf "  %-20s %s\n" "bpftool:"   "$(bpftool version 2>/dev/null | head -1 || echo 'not found')"
printf "  %-20s %s\n" "libbpf-dev:" "$(dpkg -s libbpf-dev 2>/dev/null | grep Version | awk '{print $2}' || echo 'not found')"
printf "  %-20s %s\n" "BTF:"       "$(test -f /sys/kernel/btf/vmlinux && echo 'available' || echo 'MISSING')"
echo ""
ok "Setup complete. You're ready to build Tracery."
echo ""
echo -e "  ${BOLD}Next steps:${RESET}"
echo "  1. cd ~/tracery"
echo "  2. make build"
echo "  3. sudo ./tracery count --pid \$(pgrep firefox)"
echo ""s