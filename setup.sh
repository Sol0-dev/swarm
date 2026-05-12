#!/bin/bash
# SwarmBounty - Kali Linux Setup Script
# Installs Python deps + optionally installs common bug bounty tools

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "  ███████╗██╗    ██╗ █████╗ ██████╗ ███╗   ███╗"
echo "  ██╔════╝██║    ██║██╔══██╗██╔══██╗████╗ ████║"
echo "  ███████╗██║ █╗ ██║███████║██████╔╝██╔████╔██║"
echo "  ╚════██║██║███╗██║██╔══██║██╔══██╗██║╚██╔╝██║"
echo "  ███████║╚███╔███╔╝██║  ██║██║  ██║██║ ╚═╝ ██║"
echo "  ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝"
echo -e "${NC}"
echo -e "${YELLOW}SwarmBounty Setup for Kali Linux${NC}"
echo ""

# Python deps
echo -e "${GREEN}[1/4] Installing Python dependencies...${NC}"
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || \
    pip3 install -r requirements.txt

# Make executable
chmod +x swarmbounty.py

# Create symlink
echo -e "${GREEN}[2/4] Creating swarmbounty command...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -w /usr/local/bin ]; then
    ln -sf "$SCRIPT_DIR/swarmbounty.py" /usr/local/bin/swarmbounty
    echo -e "  ${GREEN}✓ Created /usr/local/bin/swarmbounty${NC}"
else
    echo -e "  ${YELLOW}⚠ Can't write to /usr/local/bin. Run with sudo, or add to PATH:${NC}"
    echo "    export PATH=\"\$PATH:$SCRIPT_DIR\""
fi

# Optional: install bug bounty tools
echo ""
echo -e "${GREEN}[3/4] Bug bounty tools check...${NC}"

check_tool() {
    if command -v $1 &> /dev/null; then
        echo -e "  ${GREEN}✓ $1${NC}"
        return 0
    else
        echo -e "  ${YELLOW}✗ $1 (not installed)${NC}"
        return 1
    fi
}

echo "  Checking tools:"
check_tool subfinder
check_tool httpx
check_tool nuclei
check_tool gau
check_tool waybackurls
check_tool sqlmap
check_tool nmap
check_tool whatweb
check_tool dalfox

echo ""
echo -e "${YELLOW}[Optional] Install missing Go tools? (requires Go 1.20+)${NC}"
read -p "Install subfinder, httpx, nuclei, gau? [y/N] " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if command -v go &> /dev/null; then
        echo -e "${CYAN}Installing Go tools...${NC}"
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null && \
            echo -e "  ${GREEN}✓ subfinder${NC}" || echo -e "  ${RED}✗ subfinder failed${NC}"
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null && \
            echo -e "  ${GREEN}✓ httpx${NC}" || echo -e "  ${RED}✗ httpx failed${NC}"
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null && \
            echo -e "  ${GREEN}✓ nuclei${NC}" || echo -e "  ${RED}✗ nuclei failed${NC}"
        go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null && \
            echo -e "  ${GREEN}✓ gau${NC}" || echo -e "  ${RED}✗ gau failed${NC}"
        # Update PATH reminder
        echo -e "${YELLOW}  Make sure ~/go/bin is in your PATH:${NC}"
        echo "    echo 'export PATH=\$PATH:~/go/bin' >> ~/.bashrc && source ~/.bashrc"
    else
        echo -e "${RED}  Go not found. Install Go first: https://go.dev/dl/${NC}"
    fi
fi

# Config setup prompt
echo ""
echo -e "${GREEN}[4/4] Configuration${NC}"
echo -e "  Config will be stored at: ${CYAN}~/.swarmbounty/config.json${NC}"
echo ""
read -p "Configure API keys now? [Y/n] " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    python3 swarmbounty.py --config
fi

echo ""
echo -e "${GREEN}✓ SwarmBounty is ready!${NC}"
echo ""
echo -e "${CYAN}Quick start:${NC}"
echo "  python3 swarmbounty.py --chat                    # Start live chat"
echo "  python3 swarmbounty.py --target example.com --ask  # Interactive hunt"
echo "  python3 swarmbounty.py --target example.com --yolo # Autonomous hunt"
echo "  python3 swarmbounty.py --config                  # Add/change API keys"
echo ""
echo -e "${YELLOW}⚠ Only test systems you have explicit written permission to test.${NC}"
