#!/usr/bin/env bash
# ============================================================
# VulnMind AI - Kali Linux Installer
# Run as: bash install.sh
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
cat << 'EOF'

 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███╗   ███╗██╗███╗   ██╗██████╗
 ██║   ██║██║   ██║██║     ████╗  ██║████╗ ████║██║████╗  ██║██╔══██╗
 ██║   ██║██║   ██║██║     ██╔██╗ ██║██╔████╔██║██║██╔██╗ ██║██║  ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██║╚██╔╝██║██║██║╚██╗██║██║  ██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║ ╚═╝ ██║██║██║ ╚████║██████╔╝
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝
          AI-Powered Vulnerability Assessment Platform for Kali Linux

EOF
}

info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; }
step()    { echo -e "\n${BOLD}${CYAN}══ $1 ══${NC}"; }

banner

echo -e "${CYAN}Installing VulnMind AI on Kali Linux...${NC}\n"

# ─── Check root / sudo ───────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    warn "Not running as root. Some tool installs may require sudo."
    SUDO="sudo"
else
    SUDO=""
fi

# ─── Python Check ────────────────────────────────────────────────────────────
step "Checking Python"
if ! command -v python3 &>/dev/null; then
    error "Python 3 not found. Install it first: apt install python3"
    exit 1
fi
PY_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
success "Python $PY_VERSION found"

# ─── Python Dependencies ─────────────────────────────────────────────────────
step "Installing Python Dependencies"
info "Installing required packages..."

PACKAGES=(
    "rich"
    "typer"
    "sqlalchemy"
    "requests"
    "python-dotenv"
    "reportlab"
    "fpdf2"
    "python-docx"
    "jinja2"
    "urllib3"
)

for pkg in "${PACKAGES[@]}"; do
    python3 -m pip install "$pkg" --break-system-packages -q 2>/dev/null && \
        success "Installed: $pkg" || warn "Failed to install: $pkg"
done

# ─── System Security Tools ───────────────────────────────────────────────────
step "Installing System Security Tools (apt)"
info "Updating package list..."
$SUDO apt-get update -qq 2>/dev/null || warn "apt update failed (continuing...)"

APT_TOOLS=(
    "nmap"
    "nikto"
    "sqlmap"
    "whois"
    "openssl"
    "masscan"
    "amass"
    "curl"
    "wget"
    "git"
)

for tool in "${APT_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        success "Already installed: $tool"
    else
        info "Installing $tool..."
        $SUDO apt-get install -y "$tool" -qq 2>/dev/null && \
            success "Installed: $tool" || warn "Could not install $tool (skipping)"
    fi
done

# ─── Go Tools ────────────────────────────────────────────────────────────────
step "Installing Go-based Tools"

if ! command -v go &>/dev/null; then
    warn "Go not found. Skipping Go-based tools."
    warn "Install Go: apt install golang  OR  https://go.dev/dl/"
    warn "Then manually install: subfinder, nuclei, naabu, katana, dalfox"
else
    GO_VERSION=$(go version 2>&1 | awk '{print $3}')
    success "Go $GO_VERSION found"

    GO_TOOLS=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/tomnomnom/assetfinder@latest"
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/hahwul/dalfox/v2@latest"
    )

    for tool_path in "${GO_TOOLS[@]}"; do
        tool_name=$(basename "${tool_path%%@*}")
        if command -v "$tool_name" &>/dev/null; then
            success "Already installed: $tool_name"
        else
            info "Installing $tool_name..."
            go install -v "$tool_path" 2>/dev/null && \
                success "Installed: $tool_name" || warn "Failed to install: $tool_name"
        fi
    done

    # Add GOPATH to PATH if not already there
    GOPATH_BIN=$(go env GOPATH)/bin
    if [[ ":$PATH:" != *":$GOPATH_BIN:"* ]]; then
        warn "Add Go binaries to PATH: export PATH=\$PATH:$GOPATH_BIN"
        echo "export PATH=\$PATH:$GOPATH_BIN" >> ~/.bashrc
        echo "export PATH=\$PATH:$GOPATH_BIN" >> ~/.zshrc 2>/dev/null || true
        success "Added $GOPATH_BIN to ~/.bashrc and ~/.zshrc"
    fi
fi

# ─── Initialize VulnMind ─────────────────────────────────────────────────────
step "Initializing VulnMind AI"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Create dirs
mkdir -p ~/.vulnmind/reports
success "Created ~/.vulnmind directory"

# Initialize database
cd "$SCRIPT_DIR"
python3 -c "from database.models import init_db; init_db(); print('Database initialized')" && \
    success "Database initialized at ~/.vulnmind/vulnmind.db" || \
    error "Database init failed"

# Create launcher script
cat > /usr/local/bin/vulnmind << LAUNCHER
#!/usr/bin/env bash
cd "$SCRIPT_DIR"
python3 vulnmind.py "\$@"
LAUNCHER

$SUDO chmod +x /usr/local/bin/vulnmind 2>/dev/null || chmod +x /usr/local/bin/vulnmind
success "Created launcher: /usr/local/bin/vulnmind"

# ─── Update nuclei templates ─────────────────────────────────────────────────
if command -v nuclei &>/dev/null; then
    step "Updating Nuclei Templates"
    info "Downloading latest nuclei templates..."
    nuclei -update-templates 2>/dev/null && success "Nuclei templates updated" || warn "Could not update nuclei templates"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  VulnMind AI Installation Complete!${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Start VulnMind AI:${NC}"
echo -e "  ${CYAN}  vulnmind${NC}                    → Interactive mode"
echo -e "  ${CYAN}  vulnmind -t example.com${NC}     → Quick scan"
echo -e "  ${CYAN}  vulnmind --config${NC}           → Configuration wizard"
echo ""
echo -e "  ${BOLD}Default Login:${NC} admin / admin"
echo -e "  ${YELLOW}  Change password after first login!${NC}"
echo ""
echo -e "  ${BOLD}Reports saved to:${NC} ~/.vulnmind/reports/"
echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo ""
